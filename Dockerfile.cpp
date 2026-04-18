# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY cpp/ .

RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DWITH_PCAP=ON && \
    cmake --build . -j$(nproc)

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/netsentry /usr/local/bin/netsentry
ENTRYPOINT ["/usr/local/bin/netsentry"]
CMD ["--sim"]
