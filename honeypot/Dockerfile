FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY listener.py .

# Runs as non-root. Binding to the unprivileged HONEYPOT_PORT (default 2222)
# means we don't need root/CAP_NET_BIND_SERVICE inside the container -- the
# host maps the real port 22 -> this container's 2222 (see docker-compose.yml).
RUN useradd -m honeypot
USER honeypot

CMD ["python", "listener.py"]
