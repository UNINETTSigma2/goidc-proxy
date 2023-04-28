FROM golang:1.18 as builder

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY . . 
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o goidc-proxy

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/goidc-proxy .
USER 65532:65532

ENTRYPOINT ["/goidc-proxy"]

