FROM python:3.9-alpine

WORKDIR /app

# Install aiohttp
RUN pip install aiohttp

# Copy the tarpit script
COPY app.py .

# Run the tarpit
CMD ["python", "app.py"]
