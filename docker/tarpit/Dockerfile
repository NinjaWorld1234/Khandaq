FROM python:3.9-alpine

WORKDIR /app

# Install dependencies
RUN pip install aiohttp redis

# Copy the tarpit script
COPY app.py .

# Run the tarpit
CMD ["python", "app.py"]
