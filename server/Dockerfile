FROM python:3.12-slim

WORKDIR /app
COPY mtrelay.py .

# stdlib only — no pip dependencies
ENTRYPOINT ["python3", "mtrelay.py"]
