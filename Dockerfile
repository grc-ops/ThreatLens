FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    STATE_DIR=/data PORT=8000

RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown app:app /data
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# Windows checkouts can turn line endings into CRLF, which breaks shell scripts
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'),timeout=4)"

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
