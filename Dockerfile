FROM golang:1.26-alpine3.23 AS builder

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X github.com/oszuidwest/zwfm-babbel/pkg/version.Version=${VERSION} -X github.com/oszuidwest/zwfm-babbel/pkg/version.Commit=${COMMIT} -X github.com/oszuidwest/zwfm-babbel/pkg/version.BuildTime=${BUILD_TIME}" \
    -o babbel ./cmd/babbel

# Final stage
FROM debian:13-slim

LABEL org.opencontainers.image.source="https://github.com/oszuidwest/zwfm-babbel"
LABEL org.opencontainers.image.description="Headless REST API for generating audio news bulletins for radio stations"
LABEL org.opencontainers.image.licenses="MIT"

ARG DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies.
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    ca-certificates \
    ffmpeg \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

# Create app user.
RUN groupadd --gid 1001 app && \
    useradd --uid 1001 --gid app --home-dir /app --shell /usr/sbin/nologin --no-create-home app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/babbel .

# Copy migrations
COPY migrations/ ./migrations/

# Create required directories
RUN mkdir -p uploads audio/processed audio/output audio/temp \
    && chown -R app:app /app

USER app

EXPOSE 8080

ENV BABBEL_FFMPEG_PATH=/usr/bin/ffmpeg
ENV BABBEL_FFPROBE_PATH=/usr/bin/ffprobe

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/babbel", "-healthcheck", "http://127.0.0.1:8080/health"]

# Environment variables (including CORS) are configured via docker-compose
# See docker-compose.yml and .env.example for configuration options
CMD ["/app/babbel"]
