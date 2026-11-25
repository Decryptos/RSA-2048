FROM python:3.12-slim

WORKDIR /app
RUN python -m pip install --no-cache-dir cryptography
COPY rsa_public_key_menu.py ./rsa_public_key_menu.py
USER 65534:65534

CMD ["sleep", "infinity"]
