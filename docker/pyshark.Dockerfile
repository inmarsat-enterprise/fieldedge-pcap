# Debian doesn't support arm32v6 so use arm32v5 for Pi Zero compatibility
#   arm32v7 could be used for Pi 3B/4/Zero 2
# Alpine we avoid for now to simplify; can optimize later
FROM arm32v5/python:3.9-slim-buster AS compile-image
LABEL maintainer="geoff.bruce-payne@inmarsat.com"
# Compile dependencies for lxml as a dependency of pyshark - build wheel
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxslt-dev \
    libz-dev
RUN pip install --user pyshark

FROM arm32v5/python:3.9-slim-buster AS build-image
RUN DEBIAN_FRONTEND=noninteractive \
    echo wireshark-common wireshark-common/install-setuid boolean true \
    | debconf-set-selections \
    && apt-get update && apt-get install -y \
    --no-install-recommends \
    libxslt-dev \
    tshark
RUN chmod +x /usr/bin/dumpcap
# Copy compiled python packages in consolidated directory
COPY --from=compile-image /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
