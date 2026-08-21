# Build stage
FROM golang:1.26.6-alpine3.23 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

RUN apk add --no-cache ffmpeg

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
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

RUN mkdir -p uploads audio/{processed,output,temp} \
    && chown -R app:app /app

USER app

EXPOSE 8080

# Runtime configuration is documented in .env.example.
CMD ["./babbel"]
