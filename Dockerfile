# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ARG JAZZER_VERSION=0.30.0
ARG ATHERIS_VERSION=3.1.0
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:/opt/jazzer:$PATH \
    JAZZER_JAR=/opt/jazzer/jazzer_standalone.jar

# Toolchains: Python + Atheris, clang/libFuzzer + sanitizers, JDK + Maven + Jazzer,
# and the usual build systems for compiling C/C++ components from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev \
        clang llvm lld libclang-rt-18-dev \
        build-essential cmake ninja-build meson autoconf automake libtool pkg-config \
        openjdk-21-jdk-headless maven \
        git curl ca-certificates unzip xz-utils file \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH:-amd64}" in \
        amd64) arch=x86-64 ;; \
        arm64) arch=arm64 ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && mkdir -p /opt/jazzer \
    && curl -fsSL "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v${JAZZER_VERSION}/jazzer-linux-${arch}.tar.gz" \
        | tar -xz -C /opt/jazzer \
    && test -x /opt/jazzer/jazzer && test -f "$JAZZER_JAR"

RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir "atheris==${ATHERIS_VERSION}"

# Untrusted code (package installs, builds, harnesses) runs as this user.
RUN useradd --create-home --uid 10001 fuzzer

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sbomfuzz ./sbomfuzz
RUN pip install --no-cache-dir .

WORKDIR /data
ENTRYPOINT ["sbomfuzz"]
CMD ["--help"]
