FROM golang:1.22.2 AS build

RUN apt update && apt upgrade -y && apt install git

RUN groupadd -g 1010 appgroup
RUN adduser appuser
RUN usermod -aG appgroup appuser
WORKDIR /app

RUN mkdir ./NoWhere2Hide
COPY . ./NoWhere2Hide/
WORKDIR /app/NoWhere2Hide/main

# Rebuild Go Modules as they need to be built with the same version of go as the program loading them
RUN ./rebuild_plugins.sh

# Build NoWhere2Hide
RUN go build -v -o NoWhere2Hide .
RUN chmod u+x ./docker_start.sh

RUN chown -R appuser:appgroup /app/
USER appuser

ENTRYPOINT ./docker_start.sh
