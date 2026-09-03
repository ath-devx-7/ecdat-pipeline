# Weak-crypto Python service — ECDAT demo target C (SPEC.md §14).
FROM python:3.11-slim

WORKDIR /opt/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE 8081
CMD ["python", "app.py"]
