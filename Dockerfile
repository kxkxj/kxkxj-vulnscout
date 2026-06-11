FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project source
COPY pyproject.toml README.md ./
COPY vulnscout/ vulnscout/

# Install Python package
RUN pip install --no-cache-dir .

# Expose API
EXPOSE 8000

CMD ["uvicorn", "vulnscout.main:app", "--host", "0.0.0.0", "--port", "8000"]
