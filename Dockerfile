FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/chauth ./cmd/chauth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/chauth /usr/local/bin/chauth
USER nonroot:nonroot
EXPOSE 9440 8443 8080
ENTRYPOINT ["chauth"]
