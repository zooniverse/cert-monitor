FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LO https://dl.k8s.io/release/v1.33.3/bin/linux/amd64/kubectl
RUN install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && rm -f ./kubectl

ADD ./ /app
