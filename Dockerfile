FROM golang:1.20 AS builder

COPY . /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /app .

FROM scratch

COPY --from=builder /app /app

ENTRYPOINT ["/app"]
