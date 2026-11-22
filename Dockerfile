# The admin web first, then the binary that embeds it.
FROM node:26-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
ARG VITE_PRIMEUI_LICENSE=""
ENV VITE_PRIMEUI_LICENSE=$VITE_PRIMEUI_LICENSE
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./frontend/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/insight .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 insight && mkdir /data && chown insight /data
COPY --from=build /out/insight /usr/local/bin/insight
USER insight
ENV NX_DATA_DIR=/data
# With HTTPS on, Insight's port serves it; acme-http answers the CA on
# :8080, which compose publishes from port 80.
ENV NX_HTTP_LISTEN=:8080
VOLUME /data
EXPOSE 8099 8080
LABEL org.opencontainers.image.source="https://github.com/nx-panel/insight" \
      org.opencontainers.image.title="NX Insight" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/usr/local/bin/insight"]
