import json, datetime as dt
from sqlalchemy.orm import Session
from ..models import *
from ..analyzers.email_analyzer import parse_eml

def run_analysis(db:Session, inv:Investigation, raw:bytes):
    a=parse_eml(raw); inv.status='analyzed'; inv.analyzed_at=dt.datetime.utcnow()
    inv.email=Email(sender=a['sender'],recipient=a['recipient'],subject=a['subject'],body=a['body'],raw=raw.decode('utf-8','replace'))
    for k,v in a['headers'].items(): inv.headers.append(EmailHeader(key=k,value=v))
    for i,u in enumerate(a['urls']):
        from urllib.parse import urlparse
        p=urlparse(u); d=p.hostname or ''; suspicious=any(x in d for x in ['paypa1','micros0ft','secure','login','verify']) or p.scheme!='https'
        inv.urls.append(URL(value=u,domain=d,protocol=p.scheme,risk='HIGH' if suspicious else 'MEDIUM',reputation='DEMO: suspicious pattern' if suspicious else 'UNKNOWN',reasons=json.dumps(['look-alike/suspicious hostname' if suspicious else 'URL extracted; external reputation not configured'])) )
    for d in a['domains']: inv.domains.append(Domain(name=d,age='UNKNOWN',registrar='UNKNOWN',nameservers='UNKNOWN',mx='UNKNOWN',a_records='UNKNOWN',asn='UNKNOWN',hosting='UNKNOWN',reputation='UNKNOWN'))
    for ip in a['ips']: inv.iocs.append(IOC(value=ip,type='IP',source='Email content/header',risk='MEDIUM',confidence=70,status='Review'))
    for d in a['domains']: inv.iocs.append(IOC(value=d,type='DOMAIN',source='Email URL',risk='HIGH' if 'secure' in d or 'login' in d else 'MEDIUM',confidence=82,status='Suspicious'))
    for u in a['urls']: inv.iocs.append(IOC(value=u,type='URL',source='Email body',risk='HIGH',confidence=80,status='Suspicious'))
    for h in a['hashes']: inv.iocs.append(IOC(value=h,type='HASH',source='Email content',risk='UNKNOWN',confidence=50,status='Unverified'))
    factors=a['factors']; inv.risk=RiskAssessment(score=a['score'],level=a['level'],factors=json.dumps(factors))
    now=dt.datetime.now().strftime('%H:%M')
    events=[('Email received','Raw message parsed','info'),('Header analysis','Message headers extracted','info'),('Authentication','SPF/DKIM/DMARC evaluated','warning' if 'FAIL' in [a['spf'],a['dkim'],a['dmarc']] else 'success'),('IOC extraction',f"{len(inv.iocs)} indicators extracted",'warning' if inv.iocs else 'success'),('Risk scoring',f"Score {a['score']}/100 — {a['level']}",'critical' if a['score']>=80 else 'warning' if a['score']>=60 else 'info')]
    for j,(e,d,s) in enumerate(events): inv.timeline.append(TimelineEvent(timestamp=f'{now} + {j}m',event=e,detail=d,severity=s))
    if a['urls']: inv.mitre.append(MitreTechnique(technique_id='T1566.002',technique='Phishing: Spearphishing Link',confidence=88,evidence='A URL was extracted from the email body and requires review.',classification='OBSERVED'))
    if re_bec(a): inv.mitre.append(MitreTechnique(technique_id='T1534',technique='Internal Spearphishing',confidence=55,evidence='Urgency/financial language detected; this is contextual only.',classification='POTENTIAL'))
    inv.hops.append(SMTPHop(hostname='Unknown',ip=a['ips'][0] if a['ips'] else 'UNKNOWN',timestamp=a['headers'].get('Date','UNKNOWN'),location='UNKNOWN',asn='UNKNOWN'))
    db.add(AuditLog(action='email_analyzed',investigation_id=inv.id)); db.commit(); return a

def re_bec(a): return any(x in a['body'].lower() for x in ['wire transfer','invoice','payment','gift card'])

def seed_demo(db):
    if db.query(Investigation).count(): return
    samples=[('Benign Email','Friendly internal note','From: alice@example.com\nTo: analyst@example.com\nSubject: Team lunch\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nHi team, lunch at noon?'),('Phishing Email','Credential lure','From: Microsoft Security <alerts@micros0ft-secure.com>\nTo: analyst@example.com\nReply-To: verify@secure-login.example\nSubject: Urgent account verification\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\n\nVerify immediately: http://secure-login.example/verify'),('BEC Email','Payment request','From: executive@example.com\nTo: finance@example.com\nSubject: Urgent invoice payment\nAuthentication-Results: spf=fail dkim=pass dmarc=fail\n\nPlease process the invoice and wire transfer immediately.')]
    for name,desc,raw in samples:
        inv=Investigation(case_name=name,description=desc,demo=True); db.add(inv); db.flush(); run_analysis(db,inv,raw.encode())
