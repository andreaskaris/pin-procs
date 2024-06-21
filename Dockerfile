# Build.
FROM golang:1.21 AS build-stage
WORKDIR /app
COPY . .
RUN make build

# Deploy into image.
FROM alpine:latest AS release
WORKDIR /
COPY --from=build-stage /app/_output/pin-procs /pin-procs
