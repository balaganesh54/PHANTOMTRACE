FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir psycopg[binary]==3.2.9
COPY app ./app
COPY tests ./tests
RUN mkdir -p reports
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
