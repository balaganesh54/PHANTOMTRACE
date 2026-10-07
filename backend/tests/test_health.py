from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def test_health(): assert client.get('/api/health').status_code==200
def test_login(): assert client.post('/api/auth/login',json={'email':'demo@example.com','password':'password'}).status_code==200
