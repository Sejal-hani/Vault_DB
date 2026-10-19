FROM python:3.11-slim

WORKDIR /app

# Install system utilities for health monitoring
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY . .

EXPOSE 8000

CMD ["python", "server.py"]
