FROM mcr.microsoft.com/devcontainers/base:dev-ubuntu-24.04
USER root
RUN apt-get update -y && \
    apt-get install -y python3-full python3-pip && \
    pip3 install --no-cache-dir requests colorama && \
    rm -rf /var/lib/apt/lists/*
