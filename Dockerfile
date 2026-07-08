FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /fit-issuer ./cmd/fit-issuer

FROM gcr.io/distroless/static
COPY --from=builder /fit-issuer /fit-issuer
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/fit-issuer"]
