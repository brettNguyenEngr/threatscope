# frontend/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Copy the pyproject.toml from the root directory
COPY pyproject.toml .

# Install the dependencies
RUN pip install --no-cache-dir .

# Copy the frontend code
COPY frontend/app.py .

# Expose the Streamlit port
EXPOSE 8501

# Command to run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]