FROM alpine:3.19.1

# Expose Ports of RouterOS
EXPOSE 2000-2256

# Change work dir (it will also create this folder if is not exist)
WORKDIR /routeros

# Install dependencies
RUN set -xe \
    && apk add --no-cache --update \
    netcat-openbsd qemu-x86_64 qemu-system-x86_64 \
    busybox-extras iproute2 iputils \
    bridge-utils iptables jq bash python3

# Environments which may be change
ENV ROUTEROS_VERSION="7.13.4"
ENV ROUTEROS_IMAGE="chr-${ROUTEROS_VERSION}.vdi"
ENV ROUTEROS_PATH="https://download.mikrotik.com/routeros/${ROUTEROS_VERSION}/${ROUTEROS_IMAGE}.zip"

# Download VDI image from remote site
RUN wget "$ROUTEROS_PATH" -O "/routeros/${ROUTEROS_IMAGE}.zip" && \
    unzip "/routeros/${ROUTEROS_IMAGE}.zip" -d "/routeros" && \
    rm -f "/routeros/${ROUTEROS_IMAGE}.zip"

# Copy script to routeros folder
ADD ["./scripts", "/routeros"]

ENTRYPOINT ["/routeros/entrypoint.sh"]