FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Pin dependencies to an auditable set for this private laboratory build.
COPY requirements-cloud.txt /app/requirements-cloud.txt
RUN python -m pip install --no-cache-dir -r /app/requirements-cloud.txt

# Package the real existing factorisation engine and offline workbench.
COPY Main /app/Main
COPY *.py /app/

# Build fails if a critical import or known RSA functional control fails.
RUN python -B -c "import railway_health; railway_health.run_checks()"

USER 65534:65534

EXPOSE 8080
CMD ["python", "-B", "/app/railway_health.py"]
