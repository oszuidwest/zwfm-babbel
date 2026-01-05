FROM golang:1.25-alpine3.23 AS builder

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Install FFmpeg
RUN apk add --no-cache ffmpeg

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X github.com/oszuidwest/zwfm-babbel/pkg/version.Version=${VERSION} -X github.com/oszuidwest/zwfm-babbel/pkg/version.Commit=${COMMIT} -X github.com/oszuidwest/zwfm-babbel/pkg/version.BuildTime=${BUILD_TIME}" \
    -o babbel cmd/babbel/main.go

# Final stage
FROM alpine:3.23

# Install FFmpeg and timezone data, upgrade to get security patches
RUN apk upgrade --no-cache && apk add --no-cache ffmpeg tzdata

# Create app user
RUN addgroup -g 1001 -S app \
    && adduser -u 1001 -S app -G app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/babbel .

# Copy migrations
COPY migrations/ ./migrations/

# Create required directories
RUN mkdir -p uploads audio/{processed,output,temp} \
    && chown -R app:app /app

USER app

EXPOSE 8080

# Environment variables (including CORS) are configured via docker-compose
# See docker-compose.yml and .env.example for configuration options
CMD ["./babbel"]
