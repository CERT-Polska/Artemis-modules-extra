# Dockerfile for karton_puredns module
FROM certpl/artemis:latest

# Set environment variables
ENV GOLANG_VERSION=1.19.5 \
    GO_PACKAGE=go${GOLANG_VERSION}.linux-amd64.tar.gz \
    GOPATH=/root/go \
    PATH=$PATH:/usr/local/go/bin:/root/go/bin \
    PUREDNS_PATH=/usr/local/bin/puredns \
    RESOLVERS_FILE=/opt/resolvers.txt \
    DEFAULT_WORDLIST=/opt/wordlists/default.txt

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    curl \
    git \
    make \
    gcc \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://golang.org/dl/${GO_PACKAGE} && \
    tar -C /usr/local -xzf ${GO_PACKAGE} && \
    rm ${GO_PACKAGE}

# Install massdns (dependency for puredns)
RUN git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && \
    make && \
    cp /tmp/massdns/bin/massdns /usr/local/bin/ && \
    rm -rf /tmp/massdns

# Install puredns
RUN go install github.com/d3mondev/puredns/v2@latest && \
    cp $GOPATH/bin/puredns /usr/local/bin/

# Create directories
RUN mkdir -p /opt/wordlists

# Download default wordlist for subdomain bruteforce
RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O ${DEFAULT_WORDLIST}

# Copy resolvers file and module
COPY resolvers.txt ${RESOLVERS_FILE}
COPY karton_puredns.py /opt/artemis/modules/

# Set working directory
WORKDIR /opt/

# Set entrypoint
CMD ["/opt/artemis/karton_ctl.py", "spawn", "artemis.modules.karton_puredns"]
