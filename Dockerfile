FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python database/init_db.py

# Enforce API key authentication by default in container deployments.
# Override PI_API_KEY at runtime via docker-compose or -e flag.
ENV PI_REQUIRE_API_KEY=1
ENV PI_API_HOST=0.0.0.0

EXPOSE 8000 8501

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port 8000 & streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0"]
