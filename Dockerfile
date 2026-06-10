FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home appuser

COPY --chown=appuser:appuser . .

# No build-time database bake: the API lifespan startup and run.py commands
# call init_db()/migrate_schema() at runtime, so the schema is created on boot.

# Enforce API key authentication by default in container deployments.
# Override PI_API_KEY at runtime via docker-compose or -e flag.
ENV PI_REQUIRE_API_KEY=1
ENV PI_API_HOST=0.0.0.0

USER appuser

EXPOSE 8000 8501

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port 8000 & streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0"]
