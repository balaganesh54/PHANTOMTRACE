# PHANTOMTRACE Architecture
Browser (Next.js/React/TypeScript) → FastAPI REST API → deterministic analysis services → SQLAlchemy ORM → PostgreSQL/SQLite.

The upload flow parses an `.eml`, stores normalized evidence, extracts IOCs, evaluates Authentication-Results, computes an explainable risk score, maps supported evidence to MITRE ATT&CK, creates timeline events, and generates a report from persisted evidence.

Security boundary: the email is never executed. Suspicious URLs are not fetched by the prototype. CORS is restricted, security headers are added, upload size is limited, and audit records are written for analysis. External enrichment can be isolated behind the intelligence service in a production deployment.
