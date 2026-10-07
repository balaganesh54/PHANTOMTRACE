from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .core.db import Base,engine,SessionLocal
from .models import *
from .api.routes import r
from .services.analysis import seed_demo
Base.metadata.create_all(bind=engine)
app=FastAPI(title='PHANTOMTRACE API',version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(',')],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
@app.middleware('http')
async def security_headers(request,call_next):
    response=await call_next(request); response.headers['X-Content-Type-Options']='nosniff'; response.headers['X-Frame-Options']='DENY'; response.headers['Referrer-Policy']='no-referrer'; response.headers['Content-Security-Policy']="default-src 'self'; frame-ancestors 'none'"; return response
app.include_router(r)
@app.on_event('startup')
def startup():
    db=SessionLocal(); seed_demo(db); db.close()
