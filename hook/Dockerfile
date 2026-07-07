FROM cgr.dev/chainguard/go:latest AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /test-hook-service .

FROM cgr.dev/chainguard/static:latest
COPY --from=builder /test-hook-service /test-hook-service
ENTRYPOINT ["/test-hook-service"]
