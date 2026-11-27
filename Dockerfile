# One image for both the pipeline (Prefect-scheduled) and the dashboard: same code, same
# pinned dependencies, two different commands in docker-compose.yml.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first: this layer is cached as long as requirements.txt does not change.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY cybersentinel ./cybersentinel
RUN pip install --no-deps .

COPY orchestration ./orchestration
COPY dashboard ./dashboard
COPY warehouse ./warehouse
COPY contracts ./contracts
COPY config ./config
COPY .streamlit ./.streamlit

# Run as an unprivileged user; /app/data is the mount point of the shared volume.
RUN useradd --create-home --uid 1000 cybersentinel \
    && mkdir -p /app/data /app/warehouse/target /app/warehouse/logs \
    && chown -R cybersentinel /app/data /app/warehouse
USER cybersentinel

CMD ["python", "-m", "cybersentinel", "status"]
