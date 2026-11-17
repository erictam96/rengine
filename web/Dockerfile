# Base image
FROM ubuntu:24.04

ARG GECKOVERSION=0.37.1
# Current ProjectDiscovery releases require Go >= 1.26 (tlsx needs 1.27)
ARG GOVERSION=1.27.4
ARG TARGETARCH

# Labels and Credits
LABEL \
    name="reNgine" \
    author="Yogesh Ojha <yogesh.ojha11@gmail.com>" \
    description="reNgine is a automated pipeline of recon process, useful for information gathering during web application penetration testing."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Ubuntu 24.04's system Python is externally managed (PEP 668), so
    # reNgine gets its own virtualenv, first on PATH (python3 / pip3).
    VIRTUAL_ENV=/opt/venv \
    GOROOT="/usr/local/go" \
    GOPATH="/go" \
    GO111MODULE=on
ENV PATH="/opt/venv/bin:${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Fail early on unsupported architectures
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" != "arm64" ] && [ "${ARCH}" != "amd64" ]; then \
      echo "reNgine not supported, encountered unknown architecture: ${ARCH}" \
      && exit 1; \
    fi

# Python + essential packages
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    gcc \
    geoip-bin \
    geoip-database \
    git \
    libharfbuzz-subset0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpcap-dev \
    libpq-dev \
    netcat-openbsd \
    nmap \
    software-properties-common \
    wget \
    x11-utils \
    xvfb \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv

# Firefox (non-snap) for EyeWitness screenshots
RUN add-apt-repository -y ppa:mozillateam/ppa \
    && printf 'Package: *\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001\n' > /etc/apt/preferences.d/mozilla-firefox \
    && apt-get update -y \
    && apt-get install -y --no-install-recommends firefox \
    && rm -rf /var/lib/apt/lists/*

# Go toolchain
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local

# geckodriver
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then \
      GECKOPATH="geckodriver-v${GECKOVERSION}-linux-aarch64.tar.gz"; \
    else \
      GECKOPATH="geckodriver-v${GECKOVERSION}-linux64.tar.gz"; \
    fi \
    && wget -q https://github.com/mozilla/geckodriver/releases/download/v${GECKOVERSION}/${GECKOPATH} \
    && tar -xzf ${GECKOPATH} \
    && rm ${GECKOPATH} \
    && mv geckodriver /usr/bin

# Make directory for app
WORKDIR /usr/src/app

# Recon tooling, pinned for reproducible builds.
# Bump versions here deliberately rather than tracking @latest.
# Notes:
#  - amass stays on v3: v4/v5 changed the CLI output format reNgine parses.
#  - s3scanner v3 tags don't use a /v3 module path, so @latest is required.
#  - gf, waybackurls and hakrawler publish no semver tags.
RUN printf "\
    github.com/jaeles-project/gospider@v1.1.6\n\
    github.com/tomnomnom/gf@latest\n\
    github.com/tomnomnom/unfurl@v0.4.3\n\
    github.com/tomnomnom/waybackurls@latest\n\
    github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0\n\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0\n\
    github.com/projectdiscovery/chaos-client/cmd/chaos@v0.5.2\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.7.0\n\
    github.com/hakluke/hakrawler@latest\n\
    github.com/lc/gau/v2/cmd/gau@v2.2.4\n\
    github.com/owasp-amass/amass/v3/...@v3.23.3\n\
    github.com/ffuf/ffuf/v2@v2.3.0\n\
    github.com/projectdiscovery/tlsx/cmd/tlsx@v1.4.6\n\
    github.com/hahwul/dalfox/v2@v2.13.0\n\
    github.com/projectdiscovery/katana/cmd/katana@v1.8.0\n\
    github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@v1.4.1\n\
    github.com/sa7mon/s3scanner@latest\n" | \
    xargs -L1 go install -ldflags="-s -w" && \
    rm -rf /go/pkg/* /root/.cache/go-build

# Update Nuclei templates and chaos
RUN nuclei -update-templates && chaos -update || true

# Python requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade pip "setuptools<81" wheel \
    && pip3 install -r /tmp/requirements.txt

# EyeWitness dependencies
RUN pip3 install \
    fuzzywuzzy \
    "selenium>=4.20,<5" \
    python-Levenshtein \
    pyvirtualdisplay \
    netaddr

# Copy source code
COPY . /usr/src/app/
