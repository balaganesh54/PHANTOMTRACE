import os, json, datetime as dt
from fastapi import APIRouter,Depends,UploadFile,File,HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from ..core.db import get_db
from ..models import *
from ..schemas.api import LoginIn,InvestigationIn
from ..services.analysis import run_analysis
r=APIRouter(prefix='/api')
@r.get('/health')
def health(): return {'status':'ok','demo_mode':True}
@r.post('/auth/login')
def login(x:LoginIn):
    if x.email=='demo@example.com' and x.password=='password': return {'token':'demo-token','user':{'email':x.email,'name':'Security Analyst'}}
    raise HTTPException(401,'Demo authentication only: use demo@example.com / password')
@r.post('/investigations')
def create(x:InvestigationIn,db:Session=Depends(get_db)):
    inv=Investigation(case_name=x.case_name,description=x.description); db.add(inv); db.commit(); return {'id':inv.id}
@r.get('/investigations')
def list_inv(db:Session=Depends(get_db)):
    return [{'id':i.id,'case_name':i.case_name,'status':i.status,'demo':i.demo,'created_at':i.created_at.isoformat(),'score':i.risk.score if i.risk else None,'level':i.risk.level if i.risk else None,'subject':i.email.subject if i.email else None} for i in db.query(Investigation).order_by(Investigation.created_at.desc()).all()]
@r.post('/investigations/{id}/analyze')
async def analyze(id:str,file:UploadFile=File(...),db:Session=Depends(get_db)):
    inv=db.get(Investigation,id)
    if not inv: raise HTTPException(404,'Investigation not found')
    if not file.filename.lower().endswith('.eml'): raise HTTPException(400,'Only .eml files are accepted')
    raw=await file.read()
    if len(raw)>5*1024*1024: raise HTTPException(413,'File too large')
    run_analysis(db,inv,raw); return {'id':id,'score':inv.risk.score,'level':inv.risk.level}
@r.post('/investigations/{id}/analyze-demo')
def analyze_demo(id:str,db:Session=Depends(get_db)):
    inv=db.get(Investigation,id)
    if not inv: raise HTTPException(404,'Not found')
    raw=b'From: Microsoft Security <alerts@micros0ft-secure.com>\nTo: analyst@example.com\nReply-To: verify@secure-login.example\nSubject: Urgent account verification\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\n\nVerify immediately: http://secure-login.example/verify'
    run_analysis(db,inv,raw); inv.demo=True; db.commit(); return {'id':id,'score':inv.risk.score,'level':inv.risk.level}
@r.get('/investigations/{id}')
def get(id:str,db:Session=Depends(get_db)):
    i=db.get(Investigation,id)
    if not i: raise HTTPException(404,'Not found')
    return {'id':i.id,'case_name':i.case_name,'description':i.description,'status':i.status,'demo':i.demo,'created_at':i.created_at.isoformat(),'analyzed_at':i.analyzed_at.isoformat() if i.analyzed_at else None,'email':{'sender':i.email.sender,'recipient':i.email.recipient,'subject':i.email.subject} if i.email else None,'risk':{'score':i.risk.score,'level':i.risk.level,'factors':json.loads(i.risk.factors)} if i.risk else None,'auth':{'spf':next((h.value.split('spf=')[1].split()[0].upper() for h in i.headers if h.key.lower()=='authentication-results' and 'spf=' in h.value.lower()),'UNKNOWN'),'dkim':next((h.value.split('dkim=')[1].split()[0].upper() for h in i.headers if h.key.lower()=='authentication-results' and 'dkim=' in h.value.lower()),'UNKNOWN'),'dmarc':next((h.value.split('dmarc=')[1].split()[0].upper() for h in i.headers if h.key.lower()=='authentication-results' and 'dmarc=' in h.value.lower()),'UNKNOWN')},'counts':{'iocs':len(i.iocs),'urls':len(i.urls),'domains':len(i.domains)}}
@r.get('/investigations/{id}/headers')
def headers(id:str,db:Session=Depends(get_db)): return [{'key':h.key,'value':h.value} for h in db.get(Investigation,id).headers]
@r.get('/investigations/{id}/iocs')
def iocs(id:str,db:Session=Depends(get_db)): return [vars_clean(x,['value','type','source','risk','confidence','status']) for x in db.get(Investigation,id).iocs]
@r.get('/investigations/{id}/urls')
def urls(id:str,db:Session=Depends(get_db)): return [vars_clean(x,['value','domain','protocol','risk','redirects','reputation','reasons']) for x in db.get(Investigation,id).urls]
@r.get('/investigations/{id}/domains')
def domains(id:str,db:Session=Depends(get_db)): return [vars_clean(x,['name','age','registrar','nameservers','mx','a_records','asn','hosting','reputation']) for x in db.get(Investigation,id).domains]
@r.get('/investigations/{id}/graph')
def graph(id:str,db:Session=Depends(get_db)):
    i=db.get(Investigation,id); nodes=[{'id':'email','type':'email','label':i.email.subject if i.email else 'Email'}]; edges=[]
    for n,u in enumerate(i.urls): uid=f'url{n}'; nodes.append({'id':uid,'type':'url','label':u.domain}); edges.append({'source':'email','target':uid})
    for n,d in enumerate(i.domains):
        did=f'domain{n}'
        nodes.append({'id':did,'type':'domain','label':d.name})
        for uidx,u in enumerate(i.urls):
            if u.domain == d.name:
                edges.append({'source':f'url{uidx}','target':did})
    return {'nodes':nodes,'edges':edges}
@r.get('/investigations/{id}/mitre')
def mitre(id:str,db:Session=Depends(get_db)): return [vars_clean(x,['technique_id','technique','confidence','evidence','classification']) for x in db.get(Investigation,id).mitre]
@r.get('/investigations/{id}/timeline')
def timeline(id:str,db:Session=Depends(get_db)): return [vars_clean(x,['timestamp','event','detail','severity']) for x in db.get(Investigation,id).timeline]
@r.get('/investigations/{id}/risk')
def risk(id:str,db:Session=Depends(get_db)): i=db.get(Investigation,id); return {'score':i.risk.score,'level':i.risk.level,'factors':json.loads(i.risk.factors)}
def vars_clean(o,fields): return {f:getattr(o,f) for f in fields}
def _build_report_pdf(i, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='PTTitle', parent=styles['Title'], fontName='Helvetica-Bold', fontSize=22, leading=26, alignment=TA_CENTER, spaceAfter=10))
    styles.add(ParagraphStyle(name='PTH1', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=15, leading=18, spaceBefore=12, spaceAfter=7, textColor=colors.HexColor('#0B5C75')))
    styles.add(ParagraphStyle(name='PTBody', parent=styles['BodyText'], fontName='Helvetica', fontSize=9.5, leading=14, spaceAfter=5))
    styles.add(ParagraphStyle(name='PTSmall', parent=styles['BodyText'], fontName='Helvetica', fontSize=8, leading=11, textColor=colors.HexColor('#475569')))
    styles.add(ParagraphStyle(name='PTMono', parent=styles['BodyText'], fontName='Courier', fontSize=7.5, leading=10))

    def esc(v):
        return str(v if v not in (None, '') else 'UNKNOWN').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    def p(v, style='PTBody'): return Paragraph(esc(v), styles[style])
    def section(title, story):
        story.append(Paragraph(title, styles['PTH1']))
    def table(data, widths=None):
        t=Table(data, colWidths=widths, repeatRows=1, hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#E2E8F0')),('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#0F172A')),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTNAME',(0,1),(-1,-1),'Helvetica'),('FONTSIZE',(0,0),(-1,-1),8),
            ('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#CBD5E1')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),5),('RIGHTPADDING',(0,0),(-1,-1),5),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)
        ])); return t

    story=[Paragraph('PHANTOMTRACE', styles['PTTitle']), Paragraph('Forensic Investigation Report', styles['Heading2']), Spacer(1,8)]
    meta=[['Case ID',i.id],['Case Name',i.case_name],['Status',i.status],['Created',i.created_at.isoformat() if i.created_at else 'UNKNOWN'],['Analyzed',i.analyzed_at.isoformat() if i.analyzed_at else 'UNKNOWN'],['Demo Data','YES — synthetic demonstration evidence' if i.demo else 'NO']]
    story.append(table([[p('Field','PTSmall'),p('Value','PTSmall')]]+[[p(a,'PTSmall'),p(b,'PTSmall')] for a,b in meta],[42*mm,125*mm])); story.append(Spacer(1,10))

    risk=i.risk; email=i.email
    section('Executive Summary', story)
    story.append(p('This report summarizes the PHANTOMTRACE local analysis of the submitted email. Findings are based on parsed evidence and configured demo-mode rules. External reputation, WHOIS, ASN and geolocation claims are not made when those providers are unavailable.'))
    if risk:
        story.append(p(f'Overall risk: {risk.score}/100 — {risk.level}.'))
        factors=json.loads(risk.factors) if risk.factors else []
        if factors:
            story.append(table([[p('Points','PTSmall'),p('Risk factor','PTSmall')]]+[[p(f'+{x.get("points",0)}','PTSmall'),p(x.get('reason','UNKNOWN'),'PTSmall')] for x in factors],[25*mm,142*mm]))

    section('Email Details', story)
    story.append(table([[p('Field','PTSmall'),p('Value','PTSmall')]]+[[p(a,'PTSmall'),p(b,'PTSmall')] for a,b in [('Subject',email.subject if email else 'UNKNOWN'),('Sender',email.sender if email else 'UNKNOWN'),('Recipient',email.recipient if email else 'UNKNOWN')]],[42*mm,125*mm]))

    authvals={}
    for h in i.headers:
        if h.key.lower()=='authentication-results':
            import re
            for k in ('spf','dkim','dmarc'):
                m=re.search(rf'{k}=([A-Za-z]+)',h.value,re.I); authvals[k]=m.group(1).upper() if m else 'UNKNOWN'
    section('Authentication Analysis', story)
    story.append(table([[p('SPF','PTSmall'),p('DKIM','PTSmall'),p('DMARC','PTSmall')],[p(authvals.get('spf','UNKNOWN'),'PTSmall'),p(authvals.get('dkim','UNKNOWN'),'PTSmall'),p(authvals.get('dmarc','UNKNOWN'),'PTSmall')]], [55*mm,55*mm,55*mm]))

    section(f'Header Analysis ({len(i.headers)} parsed headers)', story)
    story.append(table([[p('Header','PTSmall'),p('Value','PTSmall')]]+[[p(h.key,'PTSmall'),p(h.value,'PTSmall')] for h in i.headers],[50*mm,117*mm]))

    section(f'IOC Findings ({len(i.iocs)})', story)
    if i.iocs:
        story.append(table([[p(x,'PTSmall') for x in ['IOC','Type','Risk','Confidence','Status']]]+[[p(x.value,'PTSmall'),p(x.type,'PTSmall'),p(x.risk,'PTSmall'),p(f'{x.confidence}%' if x.confidence is not None else 'UNKNOWN','PTSmall'),p(x.status,'PTSmall')] for x in i.iocs],[60*mm,22*mm,22*mm,28*mm,35*mm]))
    else: story.append(p('No IOCs were extracted.'))

    section(f'URL Findings ({len(i.urls)})', story)
    if i.urls:
        story.append(table([[p(x,'PTSmall') for x in ['URL','Domain','Protocol','Risk','Reputation']]]+[[p(x.value,'PTMono'),p(x.domain,'PTSmall'),p(x.protocol,'PTSmall'),p(x.risk,'PTSmall'),p(x.reputation,'PTSmall')] for x in i.urls],[65*mm,30*mm,20*mm,20*mm,32*mm]))
    else: story.append(p('No URLs were extracted.'))

    section(f'Domain Findings ({len(i.domains)})', story)
    if i.domains:
        story.append(table([[p(x,'PTSmall') for x in ['Domain','Age','Registrar','ASN','Reputation']]]+[[p(x.name,'PTMono'),p(x.age,'PTSmall'),p(x.registrar,'PTSmall'),p(x.asn,'PTSmall'),p(x.reputation,'PTSmall')] for x in i.domains],[45*mm,25*mm,38*mm,25*mm,34*mm]))
    else: story.append(p('No domains were extracted.'))

    section(f'MITRE ATT&CK Mapping ({len(i.mitre)})', story)
    if i.mitre:
        story.append(table([[p(x,'PTSmall') for x in ['ID','Technique','Confidence','Classification','Evidence']]]+[[p(x.technique_id,'PTSmall'),p(x.technique,'PTSmall'),p(f'{x.confidence}%' if x.confidence is not None else 'UNKNOWN','PTSmall'),p(x.classification,'PTSmall'),p(x.evidence,'PTSmall')] for x in i.mitre],[25*mm,40*mm,25*mm,30*mm,47*mm]))
    else: story.append(p('No MITRE techniques were mapped.'))

    section(f'Investigation Timeline ({len(i.timeline)} events)', story)
    if i.timeline:
        story.append(table([[p(x,'PTSmall') for x in ['Time','Event','Detail','Severity']]]+[[p(x.timestamp,'PTSmall'),p(x.event,'PTSmall'),p(x.detail,'PTSmall'),p(x.severity,'PTSmall')] for x in i.timeline],[28*mm,38*mm,75*mm,26*mm]))
    else: story.append(p('No timeline events were recorded.'))

    section('Recommendations & Limitations', story)
    for item in ['Demo mode uses local parsing and deterministic heuristic scoring.','Unknown intelligence fields are intentionally not invented.','Suspicious URLs are displayed for analysis and are not automatically opened.','Synthetic demo evidence must not be treated as real-world threat intelligence.']:
        story.append(Paragraph('• '+esc(item), styles['PTBody']))
    story.append(Spacer(1,12)); story.append(Paragraph('Generated by PHANTOMTRACE — AI-Assisted Email Threat Detection & Cyber Forensics Web Platform', styles['PTSmall']))
    SimpleDocTemplate(path,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=16*mm,bottomMargin=16*mm,title='PHANTOMTRACE Forensic Investigation Report').build(story)

@r.post('/investigations/{id}/report')
def report(id:str,db:Session=Depends(get_db)):
    i=db.get(Investigation,id)
    if not i or not i.risk: raise HTTPException(400,'Analyze investigation first')
    os.makedirs('reports',exist_ok=True); path=f'reports/{id}.pdf'; _build_report_pdf(i,path)
    db.add(Report(investigation_id=id,format='pdf',path=path)); db.commit()
    return {'format':'pdf','path':path,'download_url':f'/api/investigations/{id}/report/pdf'}

@r.get('/investigations/{id}/report/pdf')
def download_report(id:str,db:Session=Depends(get_db)):
    i=db.get(Investigation,id)
    if not i or not i.risk: raise HTTPException(400,'Analyze investigation first')
    os.makedirs('reports',exist_ok=True); path=f'reports/{id}.pdf'; _build_report_pdf(i,path)
    db.add(Report(investigation_id=id,format='pdf',path=path)); db.commit()
    return FileResponse(path, media_type='application/pdf', filename=f'PHANTOMTRACE_{id}_forensic_report.pdf', headers={'Content-Disposition':f'attachment; filename="PHANTOMTRACE_{id}_forensic_report.pdf"'})
