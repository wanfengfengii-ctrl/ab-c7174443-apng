FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY verify.py ./verify.py

# The service and the verifier use only the Python standard library, so no
# third-party packages are installed. This also serves as the build step
# exercised by the one-shot verify service.
RUN python -m compileall -q app verify.py

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
    CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8080'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "app.server"]
