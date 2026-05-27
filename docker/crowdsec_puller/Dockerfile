# Ephemeral CrowdSec Intel Puller (The Suicide Container)
# --------------------------------------------------------
# This container is designed to wake up, fetch threat intel from the internet,
# push it to the internal network, and immediately die.

FROM python:3.11-alpine

# Set non-root user for security
RUN adduser -D -g '' puller
USER puller

WORKDIR /app

# Install minimal requirements
COPY --chown=puller:puller requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the intel puller script
COPY --chown=puller:puller puller.py .

# Run the script when container starts
CMD ["python", "puller.py"]
