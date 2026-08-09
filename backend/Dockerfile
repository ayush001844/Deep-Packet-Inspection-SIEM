FROM python:3.10-slim

WORKDIR /app

# Install system dependencies required for packet sniffing and building C extensions
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
# We copy the contents of the backend folder into /app/backend to maintain module paths
# But wait, main.py is run as `uvicorn backend.main:app`. This means `/app` must contain `backend` directory.
# Let's set the workdir to /app, and copy the whole backend directory into /app/backend
WORKDIR /app
COPY . /app/backend

# The command to run the application
# We need to run it from /app so python can find the `backend` module
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
