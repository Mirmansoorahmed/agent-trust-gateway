FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY gateway gateway
COPY servers servers
COPY agents agents
COPY eval eval
COPY config config
COPY policies policies
COPY scripts scripts
RUN pip install --no-cache-dir .

COPY scripts/wait-for-key.sh /wait-for-key.sh
RUN chmod +x /wait-for-key.sh

ENV PYTHONPATH=/app
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8080"]
