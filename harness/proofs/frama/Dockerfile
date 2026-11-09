FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    frama-c-base why3 z3 cvc4 gcc python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN why3 config detect
WORKDIR /work
ENTRYPOINT ["python3", "harness/proofs/frama/period_metadata.py"]
