FROM golang:1.26.8-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fly-mcp ./cmd/fly-mcp

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build --chown=65532:65532 /out/fly-mcp /fly-mcp

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/fly-mcp"]
