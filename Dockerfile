FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data/keys /app/data/db

ENV PORT=8080

EXPOSE 8001 8002 8003 9000 8080

ENTRYPOINT ["python", "main.py"]

# The image defaults to the single-port interactive demo; docker-compose and
# the CLI examples override this command for the individual services.
CMD ["web", "--host", "0.0.0.0"]
