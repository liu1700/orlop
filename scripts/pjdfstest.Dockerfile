# Runner image for scripts/pjdfstest-rig.sh: Rust + Go toolchains, FUSE,
# and a prebuilt pjdfstest under /opt/pjdfstest. Built/run by
# scripts/pjdfstest-docker.sh; the repo is bind-mounted at /src.
FROM rust:1-bookworm

ARG GO_VERSION=1.25.7

RUN apt-get update && apt-get install -y --no-install-recommends \
      fuse3 libfuse3-dev pkg-config util-linux openssl sqlite3 git perl python3 bc \
      autoconf automake libtool build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
      | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH

RUN git clone --depth 50 https://github.com/pjd/pjdfstest /opt/pjdfstest \
    && cd /opt/pjdfstest \
    && autoreconf -ifs \
    && ./configure \
    && make pjdfstest

WORKDIR /src
