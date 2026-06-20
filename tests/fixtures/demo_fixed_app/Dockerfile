FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 5000
COPY . /app
WORKDIR /app
RUN pip3 install --no-cache-dir -r requirements.txt
RUN adduser --disabled-password appuser
USER appuser
HEALTHCHECK --interval=30s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python3", "app.py"]
