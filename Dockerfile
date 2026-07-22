FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hardlink_audit ./hardlink_audit

EXPOSE 8990
CMD ["uvicorn", "hardlink_audit.webapp:app", "--host", "0.0.0.0", "--port", "8990"]
