FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy app
COPY vulnscout/ vulnscout/

# Expose API
EXPOSE 8000

CMD ["uvicorn", "vulnscout.main:app", "--host", "0.0.0.0", "--port", "8000"]
