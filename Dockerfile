# syntax=docker/dockerfile:1.7
# 单镜像交付：前端静态资源 + Go 控制面（含 PDF 中文字体、采集器与 Agent 子命令）

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS server
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
COPY server/vendor ./vendor
COPY server/*.go ./
COPY server/internal ./internal
COPY server/assets ./assets
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/vulnagent .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app/server
COPY --from=server /out/vulnagent /app/server/vulnagent
COPY --from=web /src/web/dist /app/web/dist
ENV VA_ADDR=:8787 \
    VA_DATA_DIR=/app/data \
    TZ=Asia/Shanghai
VOLUME ["/app/data"]
EXPOSE 8787
ENTRYPOINT ["/app/server/vulnagent"]
CMD ["server"]
