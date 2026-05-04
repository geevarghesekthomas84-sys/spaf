# ─────────────────────────────────────────────────────────────────────────────
# SPAF — Smart Pentesting Automation Framework
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# System dependencies: nmap required, curl/wget/git useful for plugins
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        wget \
        git \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Optional: RustScan (uncomment for high-speed scanning inside the container)
# RUN curl -LO https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb \
#     && dpkg -i rustscan_2.3.0_amd64.deb && rm rustscan_2.3.0_amd64.deb

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy source and install CLI entry point
COPY . .
RUN pip install --no-cache-dir -e .

# Runtime environment
ENV PYTHONUNBUFFERED=1
ENV SPAF_MONGO_URI=mongodb://mongo:27017

ENTRYPOINT ["spaf"]
CMD ["--help"]
