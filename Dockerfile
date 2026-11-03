FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APIHUB_ENV=production \
    APIHUB_HOST=0.0.0.0 \
    APIHUB_PORT=8000

WORKDIR /app

RUN groupadd -r apihub && useradd -r -g apihub apihub

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R apihub:apihub /app

USER apihub

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["python3", "main.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
