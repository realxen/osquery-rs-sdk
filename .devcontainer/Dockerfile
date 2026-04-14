FROM mcr.microsoft.com/devcontainers/rust:1-bookworm AS development

ARG TARGETARCH
ARG OSQUERY_VERSION=5.22.1
ARG CURL_OPTS="--retry 3 --retry-delay 5 --retry-connrefused"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/osquery/bin:${PATH}"
ENV OSQUERY_EXTENSION_SOCKET="/var/osquery/osquery.em"
ENV OSQUERY_DB_DIR="/var/osquery/osquery.db"
ENV OSQUERY_LOG_DIR="/var/log/osquery"

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        lsof \
        procps \
        thrift-compiler; \
    rustup component add rustfmt clippy; \
    case "${TARGETARCH}" in \
        amd64) osquery_arch="amd64" ;; \
        arm64) osquery_arch="arm64" ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl ${CURL_OPTS} -fL -o /tmp/osquery.deb \
      "https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery_${OSQUERY_VERSION}-1.linux_${osquery_arch}.deb"; \
    apt-get install -y --no-install-recommends /tmp/osquery.deb; \
    rm -f /tmp/osquery.deb; \
    mkdir -p /var/osquery /var/log/osquery; \
    chown -R vscode:vscode /var/osquery /var/log/osquery; \
    rm -rf /var/lib/apt/lists/*
