# Real-iptables guard lifecycle tests.
#
#   docker build -f test/integration/guard/Dockerfile -t bypath-guard-test .
#   docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW bypath-guard-test
#
# The container is the isolated lab: the tests create, crash and remove
# BYPATH_PROXY_IN only inside this network namespace and a private
# /var/lib/bypath-guard-test-* directory. Nothing contacts a provider, a tunnel
# or the host's firewall.
FROM golang:1.26 AS test

RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV BYPATH_GUARD_IPTABLES=1
ENTRYPOINT ["go", "test", "-count=1", "-v", "./internal/proxyguard"]
