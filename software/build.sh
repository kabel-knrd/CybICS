#!/bin/bash

set -e
cd "$(dirname "$0")"

# TODO: don't change hosts docker socket permissions
# currently docker group inside the devconteiner is another one than the hosts group
# this should be fixed...
sudo chown devuser /var/run/docker.sock

name=cybicsbuilder
docker buildx ls | grep -q $name || docker buildx create --driver-opt network=host --use --config config.toml --name $name
docker buildx inspect --bootstrap

docker buildx build --platform linux/arm64 -t localhost:5000/cybics-readi2c:latest --push ./scripts
docker buildx build --platform linux/arm64 -t localhost:5000/cybics-openplc:latest --push ./OpenPLC
docker buildx build --platform linux/arm64 -t localhost:5000/cybics-fuxa:latest --push ./FUXA
docker buildx build --platform linux/arm64 -t localhost:5000/cybics-stm32:latest --push ./stm32
