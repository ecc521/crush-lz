FROM ubuntu:24.04
ARG CBMC_VERSION=6.11.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gcc libc6-dev make time \
    && ARCH=$(uname -m) \
    && if [ "$ARCH" = "aarch64" ]; then \
         DEB_ARCH="arm64-"; \
       else \
         DEB_ARCH=""; \
       fi \
    && curl -fsSL -o /tmp/cbmc.deb \
      "https://github.com/diffblue/cbmc/releases/download/cbmc-${CBMC_VERSION}/ubuntu-24.04-${DEB_ARCH}cbmc-${CBMC_VERSION}-Linux.deb" \
    && apt-get install -y /tmp/cbmc.deb \
    && rm -rf /tmp/cbmc.deb /var/lib/apt/lists/*
WORKDIR /work
ENV PROOF_JOBS=16
CMD ["make", "-C", "harness", "proofs"]
