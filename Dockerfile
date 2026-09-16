ARG GOLANG_VERSION=1.25

ARG BUILDPLATFORM

################################################################################
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/toolbox:9.6 AS manifests
ARG ODH_PLATFORM_TYPE=OpenDataHub
USER root
WORKDIR /
COPY opt/manifests /opt/manifests-source
RUN case "${ODH_PLATFORM_TYPE}" in \
      OpenDataHub|opendatahub|odh) platform=odh ;; \
      *) platform=rhoai ;; \
    esac && \
    test -d "/opt/manifests-source/${platform}/kuberay" && \
    mkdir -p /opt/manifests && \
    cp -a "/opt/manifests-source/${platform}/kuberay" /opt/manifests/kuberay

################################################################################
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:$GOLANG_VERSION AS builder
ARG CGO_ENABLED=1
ARG GOEXPERIMENT=strictfipsruntime
ARG TARGETOS
ARG TARGETARCH
USER root
WORKDIR /workspace
COPY go.mod go.sum ./

RUN go mod download

COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

RUN CGO_ENABLED=${CGO_ENABLED} GOEXPERIMENT=${GOEXPERIMENT} GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -trimpath -ldflags="-s -w" -o manager cmd/main.go

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --chown=1001:0 --from=manifests /opt/manifests /opt/manifests
USER 1001

ENTRYPOINT ["/manager"]
