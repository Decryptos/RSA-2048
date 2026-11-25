FROM python:3.12-slim

WORKDIR /app
COPY Main ./Main
USER 65534:65534

CMD ["python", "-u", "Main", "3233", "--seconds", "5"]
