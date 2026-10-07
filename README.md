# PHANTOMTRACE
AI-Assisted Email Threat Detection & Cyber Forensics — browser-based SIH 2026 prototype.

## Working features
- Demo login (`demo@example.com` / `password`)
- PostgreSQL through Docker; SQLite fallback for local backend
- Safe `.eml` upload with 5 MB limit
- RFC email/header parsing, URL/domain/IP/hash IOC extraction
- SPF/DKIM/DMARC parsing from Authentication-Results
- Deterministic, explainable 0–100 risk score
- Synthetic demo investigations seeded on startup and marked DEMO DATA
- Investigation overview, headers, IOCs, URLs, domains, graph, MITRE, timeline and report routes
- React Flow threat graph and Recharts dashboard
- PDF forensic report
- Security headers, CORS restriction, audit logging
- No attachment execution and no automatic browsing of suspicious URLs

## Docker
```bash
docker compose up --build
```
Open `http://localhost:3000`.

## Local development
### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Default is SQLite. For PostgreSQL, install `psycopg[binary]` and set `DATABASE_URL`.

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Set `NEXT_PUBLIC_API_URL=http://localhost:8000/api` if required.

## API documentation
FastAPI Swagger: `http://localhost:8000/docs`
Health: `GET /api/health`

## Demo
Login → Dashboard → New Investigation → choose no file for a synthetic demo, or upload `samples/phishing.eml` → inspect evidence tabs → Generate Report.

## Security and limitations
The analyzer treats uploaded email as data. It does not execute attachments and never automatically opens URLs. External reputation/WHOIS/DNS enrichment is optional; unavailable data is `UNKNOWN` and demo intelligence is labeled `DEMO`. Location is not used to infer maliciousness. The included authentication is deliberately demo-only and should be replaced with real identity/authentication before production.


## Forensic Report

Open an analyzed investigation and select **Report**. The Report page now renders the complete forensic report directly in the browser, including the case summary, risk factors, authentication results, headers, IOCs, URLs, domains, MITRE ATT&CK mappings, timeline, and limitations.

Use **Download PDF** to generate and download the complete PDF report. In Docker Compose, generated PDFs are also persisted to the host `reports/` directory.

If you updated an existing checkout, rebuild the containers:

```powershell
docker compose down
docker compose up --build
```
