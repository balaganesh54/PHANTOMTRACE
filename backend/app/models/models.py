import uuid, datetime as dt
from sqlalchemy import Column,String,DateTime,Integer,Text,ForeignKey,Boolean
from sqlalchemy.orm import relationship

def uid(): return str(uuid.uuid4())
from ..core.db import Base
class User(Base):
    __tablename__='users'; id=Column(String,primary_key=True,default=uid); email=Column(String,unique=True); name=Column(String); password_hash=Column(String); created_at=Column(DateTime,default=dt.datetime.utcnow)
class Investigation(Base):
    __tablename__='investigations'; id=Column(String,primary_key=True,default=uid); case_name=Column(String); description=Column(Text); status=Column(String,default='created'); demo=Column(Boolean,default=False); created_at=Column(DateTime,default=dt.datetime.utcnow); analyzed_at=Column(DateTime)
    email=relationship('Email',uselist=False,cascade='all, delete-orphan'); risk=relationship('RiskAssessment',uselist=False,cascade='all, delete-orphan'); iocs=relationship('IOC',cascade='all, delete-orphan'); urls=relationship('URL',cascade='all, delete-orphan'); domains=relationship('Domain',cascade='all, delete-orphan'); hops=relationship('SMTPHop',cascade='all, delete-orphan'); timeline=relationship('TimelineEvent',cascade='all, delete-orphan'); mitre=relationship('MitreTechnique',cascade='all, delete-orphan'); headers=relationship('EmailHeader',cascade='all, delete-orphan')
class Email(Base):
    __tablename__='emails'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); sender=Column(String); recipient=Column(String); subject=Column(String); body=Column(Text); raw=Column(Text)
class EmailHeader(Base):
    __tablename__='email_headers'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); key=Column(String); value=Column(Text)
class SMTPHop(Base):
    __tablename__='smtp_hops'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); hostname=Column(String); ip=Column(String); timestamp=Column(String); location=Column(String); asn=Column(String)
class IOC(Base):
    __tablename__='iocs'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); value=Column(String); type=Column(String); source=Column(String); risk=Column(String); confidence=Column(Integer); status=Column(String)
class URL(Base):
    __tablename__='urls'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); value=Column(Text); domain=Column(String); protocol=Column(String); risk=Column(String); redirects=Column(Integer,default=0); reputation=Column(String); reasons=Column(Text)
class Domain(Base):
    __tablename__='domains'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); name=Column(String); age=Column(String); registrar=Column(String); nameservers=Column(Text); mx=Column(Text); a_records=Column(Text); asn=Column(String); hosting=Column(String); reputation=Column(String)
class RiskAssessment(Base):
    __tablename__='risk_assessments'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); score=Column(Integer); level=Column(String); factors=Column(Text)
class MitreTechnique(Base):
    __tablename__='mitre_techniques'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); technique_id=Column(String); technique=Column(String); confidence=Column(Integer); evidence=Column(Text); classification=Column(String)
class TimelineEvent(Base):
    __tablename__='timeline_events'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); timestamp=Column(String); event=Column(String); detail=Column(Text); severity=Column(String)
class ThreatIntelligence(Base):
    __tablename__='threat_intelligence'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); indicator=Column(String); source=Column(String); verdict=Column(String); confidence=Column(Integer)
class Report(Base):
    __tablename__='reports'; id=Column(String,primary_key=True,default=uid); investigation_id=Column(String,ForeignKey('investigations.id')); format=Column(String); path=Column(String); created_at=Column(DateTime,default=dt.datetime.utcnow)
class AuditLog(Base):
    __tablename__='audit_logs'; id=Column(String,primary_key=True,default=uid); action=Column(String); investigation_id=Column(String); timestamp=Column(DateTime,default=dt.datetime.utcnow)
