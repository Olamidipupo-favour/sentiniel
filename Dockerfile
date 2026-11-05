FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentiniel ./cmd/sentiniel

FROM alpine:3.20
RUN addgroup -S sentiniel && adduser -S -G sentiniel sentiniel
COPY --from=build /out/sentiniel /usr/local/bin/sentiniel
COPY fixtures/infected /fixtures/infected
USER sentiniel
ENTRYPOINT ["sentiniel"]
