FROM ubuntu:xenial

RUN \
  apt-get update && apt-get upgrade -q -y && \
  apt-get install -y --no-install-recommends golang git make gcc libc-dev ca-certificates && \
  git clone --depth 1 --branch release/1.7 https://github.com/MeshBoxTech/mesh-chain && \
  (cd mesh-chain && make geth) && \
  cp mesh-chain/build/bin/geth /geth && \
  apt-get remove -y golang git make gcc libc-dev && apt autoremove -y && apt-get clean && \
  rm -rf /mesh-chain

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/geth"]
