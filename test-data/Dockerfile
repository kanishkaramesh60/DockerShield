FROM python:3.12

USER root

ENV API_KEY=super_secret_key

ADD . /app

RUN curl -fsSL https://example.com/install.sh | sh

WORKDIR /app
