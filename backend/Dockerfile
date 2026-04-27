# backend/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Copy the pyproject.toml from the root directory
COPY pyproject.toml .

# Force pip to install CPU-only version of pytorch
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu

# Install the dependencies
RUN pip install --no-cache-dir .

# Copy the backend code
COPY backend/app ./app

# Expose the FastAPI port
EXPOSE 8000

# Command to run the API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]