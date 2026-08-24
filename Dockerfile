FROM golang:1.27.0-alpine3.24 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-w -s -X github.com/oszuidwest/zwfm-babbel/pkg/version.Version=${VERSION} -X github.com/oszuidwest/zwfm-babbel/pkg/version.Commit=${COMMIT} -X github.com/oszuidwest/zwfm-babbel/pkg/version.BuildTime=${BUILD_TIME}" \
    -o babbel cmd/babbel/main.go

# Minimal runtime stage
FROM alpine:3.24

LABEL org.opencontainers.image.source="https://github.com/oszuidwest/zwfm-babbel"
LABEL org.opencontainers.image.description="Headless REST API for generating audio news bulletins for radio stations"
LABEL org.opencontainers.image.licenses="MIT"

# CACHEBUST makes CI refresh security patches even when the base digest is unchanged.
ARG CACHEBUST=static
RUN echo "cachebust: ${CACHEBUST}" >/dev/null && apk update && apk upgrade --no-cache && apk add --no-cache ffmpeg tzdata && rm -rf /var/cache/apk/*

# Run with an unprivileged account.
RUN addgroup -g 1001 -S app \
    && adduser -u 1001 -S app -G app

WORKDIR /app

COPY --from=builder /app/babbel .

COPY migrations/ ./migrations/

# Create required directories
RUN mkdir -p uploads audio/processed audio/output audio/temp \
    && chown -R app:app /app

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD ["wget", "--spider", "-q", "http://localhost:8080/health"]

# Environment variables (including CORS) are configured via docker-compose
# See docker-compose.yml and .env.example for configuration options
CMD ["./babbel"]
