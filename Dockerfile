# ─────────────────────────────────────────────────────────────────────────────
# SPAF — Smart Pentesting Automation Framework
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# System dependencies: nmap required, curl/wget/git useful for plugins,
# golang required to build the external recon toolkit binaries.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        wget \
        git \
        dnsutils \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

# ── External recon toolkit ───────────────────────────────────────────────────
# Installs the Go-based recon suite used by `spaf toolkit` / `spaf tools`:
#   subfinder, httpx, nuclei, katana, dnsx  (ProjectDiscovery)
#   assetfinder, waybackurls, hakrawler     (tomnomnom / hakluke)
#   gau (lc), ffuf                          (fuzzing)
ENV GOBIN=/usr/local/bin
ENV GOPATH=/root/go
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/hakluke/hakrawler@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && rm -rf /root/go/pkg /root/.cache/go-build

# Pre-download nuclei templates so first scan is fast (best-effort).
RUN nuclei -update-templates || true

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
