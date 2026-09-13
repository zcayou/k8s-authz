# syntax=docker/dockerfile:1

ARG BUILDER_IMAGE=golang
ARG BUILDER_VERSION=1.26
ARG RUNTIME_IMAGE=gcr.io/distroless/static
ARG RUNTIME_VERSION=nonroot

FROM --platform=$BUILDPLATFORM $BUILDER_IMAGE:$BUILDER_VERSION AS source

WORKDIR /build

COPY go.mod go.sum ./

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY . .

FROM source AS manager-builder

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/manager \
    ./cmd

FROM source AS cli-builder

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/k8s-authz \
    ./cmd/k8s-authz

FROM $RUNTIME_IMAGE:$RUNTIME_VERSION AS runtime

USER 65532:65532
WORKDIR /
COPY LICENSE /licenses/

FROM runtime AS cli

COPY --from=cli-builder /out/k8s-authz /k8s-authz

ENTRYPOINT ["/k8s-authz"]

FROM runtime AS manager

COPY --from=manager-builder /out/manager /manager

ENTRYPOINT ["/manager"]
