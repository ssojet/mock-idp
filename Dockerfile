# Cross-compile on the build machine for each target, instead of emulating it.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /mock-idp . && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mock-idp /mock-idp
# distroless runs as nonroot (65532); the state directory must be theirs
COPY --from=build --chown=65532:65532 /data /data
ENV MOCKIDP_DATA=/data/state.json
VOLUME /data
EXPOSE 7070
ENTRYPOINT ["/mock-idp"]
