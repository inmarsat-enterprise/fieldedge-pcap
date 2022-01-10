#!/bin/bash
#
# Builds the fieldedge-pyshark images
#
echo "You must login to Docker hub via command line with an authorized user on the inmarsat organization."
set -euo pipefail
# Pull latest image to populate build cache
docker pull inmarsat/fieldedge-pyshark:compile-stage || true
docker pull inmarsat/fieldedge-pyshark:latest || true

docker buildx build --platform linux/arm/v7 \
    --target compile-image \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --cache-from inmarsat/fieldedge-pyshark:compile-stage \
    --tag inmarsat/fieldedge-pyshark:compile-stage \
    -f pyshark.Dockerfile .

docker buildx build --platform linux/arm/v7 \
    --target build-image \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --cache-from inmarsat/fieldedge-pyshark:compile-stage \
    --cache-from inmarsat/fieldedge-pyshark:latest \
    --tag inmarsat/fieldedge-pyshark:latest \
    -f pyshark.Dockerfile .

docker push inmarsat/fieldedge-pyshark:compile-stage
docker push inmarsat/fieldedge-pyshark:latest
