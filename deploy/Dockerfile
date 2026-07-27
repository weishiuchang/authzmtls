# docker build -f deploy/Dockerfile --target debug -t authzmtls:debug .
# docker build -f deploy/Dockerfile --target release -t authzmtls:latest .

ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

# VERSION stamps cmd/authzmtls/main.go's `version` var, surfaced by --version
# and the STARTING log line. CI passes the short git SHA on every push, or
# the git tag verbatim when building a tagged release (see
# .github/workflows/docker-publish.yaml); a plain `docker build` with no
# --build-arg falls back to "dev", same as running `go build` directly.
ARG VERSION=dev

# Static build
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/authzmtls ./cmd/authzmtls && \
    chmod 0555 /out/authzmtls

# release image
FROM scratch AS release

# `scratch` has no /etc/passwd, so `USER` needs a numeric UID/GID. 65532 is
# the common "nonroot" convention; any unused UID works equally well.
COPY --from=builder --chown=65532:65532 /out/authzmtls /authzmtls
COPY docs/config.yaml /etc/authzmtls/config.yaml

USER 65532:65532

ENTRYPOINT ["/authzmtls"]
CMD ["/etc/authzmtls/config.yaml"]

# debug image with busybox
FROM busybox:stable AS debug

COPY --from=builder --chown=nobody:nobody /out/authzmtls /authzmtls
COPY docs/config.yaml /etc/authzmtls/config.yaml

USER 65532:65532

ENTRYPOINT ["/authzmtls"]
CMD ["/etc/authzmtls/config.yaml"]
