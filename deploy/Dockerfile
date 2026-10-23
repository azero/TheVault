# syntax=docker/dockerfile:1
# Stage 1: package the Chrome extension so the server can offer it for download (Settings > Browser extension).
FROM node:22-alpine AS ext
RUN apk add --no-cache zip
WORKDIR /src
COPY package.json ./
COPY scripts ./scripts
COPY extension ./extension
COPY server/internal/web/static ./server/internal/web/static
RUN node scripts/build-extension.mjs --embed

# Stage 2: the server, one static binary.
FROM golang:1.26-alpine AS build
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
COPY --from=ext /src/server/internal/web/static/downloads/ ./internal/web/static/downloads/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/thevault ./cmd/thevault

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10002 thevault && adduser -S -u 10002 -G thevault thevault \
 && mkdir /data && chown thevault:thevault /data
COPY --from=build /out/thevault /usr/local/bin/thevault
USER thevault
ENV VAULT_DATA_DIR=/data
VOLUME /data
EXPOSE 8444
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/thevault", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/thevault"]
CMD ["serve"]
