# Ordeal — adversarial test harness for Sigma detection rules.
#
# Two stages. The builder produces a static binary; the final image is
# distroless with no shell, no package manager, and a non-root user. Mount your
# rules read-only and pass arguments straight to the entrypoint:
#
#   docker build -t ordeal .
#   docker run --rm -v "$PWD/rules:/rules:ro" ordeal run /rules

FROM golang:1.26 AS builder

ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /src

# Dependencies first, so a source-only change reuses the module layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build \
      -trimpath \
      -ldflags "-s -w -X github.com/principlebreach/ordeal/internal/cli.version=${VERSION}" \
      -o /ordeal \
      ./cmd/ordeal

# ---------------------------------------------------------------------------

FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.title="Ordeal" \
      org.opencontainers.image.description="Adversarial test harness for Sigma detection rules." \
      org.opencontainers.image.source="https://github.com/principlebreach/ordeal" \
      org.opencontainers.image.url="https://principlebreach.com" \
      org.opencontainers.image.vendor="Principle Breach" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /ordeal /ordeal

USER nonroot:nonroot
WORKDIR /rules

ENTRYPOINT ["/ordeal"]
CMD ["--help"]
