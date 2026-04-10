FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/agentwall ./cmd/agentwall

FROM alpine:3.20
COPY --from=build /out/agentwall /usr/local/bin/agentwall
ENTRYPOINT ["agentwall"]
