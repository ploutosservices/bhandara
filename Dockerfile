FROM python:3.12-slim AS base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

# The tests and the demo's certificate maker: docker compose builds this with `target: test`.
FROM base AS test
COPY requirements-test.txt .
RUN pip install --no-cache-dir -r requirements-test.txt
COPY tests/ tests/
COPY demo/ demo/
USER nobody

# The service — the default target, so `docker build .` builds it.
FROM base AS app
USER nobody
EXPOSE 8100
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
