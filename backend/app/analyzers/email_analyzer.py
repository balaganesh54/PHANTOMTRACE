import re, ipaddress
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from datetime import datetime

URL_RE=re.compile(r'https?://[^\s<>\"\']+')
IP_RE=re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
HASH_RE=re.compile(r'\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}|[a-fA-F0-9]{24})?\b')

def parse_eml(raw:bytes):
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    headers={k:str(v) for k,v in msg.items()}
    body=msg.get_body(preferencelist=('plain','html'))
    text=body.get_content() if body else ''
    urls=list(dict.fromkeys(URL_RE.findall(text+'\n'+str(msg))))
    ips=[]
    for x in IP_RE.findall(raw.decode('utf-8','ignore')):
        try: ipaddress.ip_address(x); ips.append(x)
        except: pass
    hashes=list(dict.fromkeys(HASH_RE.findall(raw.decode('utf-8','ignore'))))
    domains=[]
    for u in urls:
        d=urlparse(u.rstrip('.,;')).hostname
        if d: domains.append(d.lower())
    domains=list(dict.fromkeys(domains))
    from email.utils import parseaddr
    sender_domain=parseaddr(headers.get('From',''))[1].split('@')[-1].lower() if '@' in parseaddr(headers.get('From',''))[1] else ''
    if sender_domain: domains.append(sender_domain)
    domains=list(dict.fromkeys(domains))
    auth=headers.get('Authentication-Results','').lower()
    spf='PASS' if 'spf=pass' in auth else 'FAIL' if 'spf=fail' in auth else 'UNKNOWN'
    dkim='PASS' if 'dkim=pass' in auth else 'FAIL' if 'dkim=fail' in auth else 'UNKNOWN'
    dmarc='PASS' if 'dmarc=pass' in auth else 'FAIL' if 'dmarc=fail' in auth else 'UNKNOWN'
    reply=headers.get('Reply-To',''); sender=headers.get('From','')
    factors=[]; score=0
    checks=[(spf=='FAIL',10,'SPF failed'),(dkim=='FAIL',10,'DKIM failed'),(dmarc=='FAIL',10,'DMARC failed'),(bool(reply and sender and reply.lower()!=sender.lower()),15,'Reply-To differs from sender'),(any(k in d for d in domains for k in ['paypa1','micros0ft','microsoft-secure','office365-login','secure-microsoft']),15,'Look-alike domain detected'),(bool(urls),15,'Suspicious URL signal: URL requires review'),(bool(ips),10,'IP address present in message'),(bool(re.search(r'urgent|immediate(?:ly)?|payment|invoice|wire transfer|gift card',text,re.I)),5,'Urgency/financial language'),(bool(re.search(r'microsoft|google|paypal|security',text+' '+sender,re.I)),7,'Brand/security impersonation language')]
    for ok,pts,label in checks:
        if ok: score+=pts; factors.append({'points':pts,'reason':label})
    score=min(score,100)
    level='CRITICAL' if score>=80 else 'HIGH' if score>=60 else 'MEDIUM' if score>=30 else 'LOW'
    return {'headers':headers,'sender':headers.get('From',''),'recipient':headers.get('To',''),'subject':headers.get('Subject','(no subject)'),'body':text,'urls':urls,'domains':domains,'ips':list(dict.fromkeys(ips)),'hashes':hashes,'spf':spf,'dkim':dkim,'dmarc':dmarc,'reply_to':reply,'score':score,'level':level,'factors':factors}
