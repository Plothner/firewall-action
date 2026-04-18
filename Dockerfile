FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir semgrep httpx
COPY entrypoint.py /entrypoint.py
COPY rules/ /rules/
ENTRYPOINT ["python", "/entrypoint.py"]
