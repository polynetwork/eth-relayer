FROM golang:1.15 AS build
WORKDIR /app
RUN git clone https://github.com/polynetwork/eth-relayer.git  && \
    cd eth-relayer && \
    go build -o run_eth_relayer main.go

FROM ubuntu:18.04
WORKDIR /app
COPY ./config.json config.json
COPY --from=build /app/eth-relayer/run_eth_relayer run_eth_relayer
CMD ["/bin/bash"]