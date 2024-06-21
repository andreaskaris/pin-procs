IMAGE ?= quay.io/akaris/pin-procs

build:
	CGO_ENABLED=0 GOOS=linux go build -o _output/pin-procs .

container-build:
	podman build -t $(IMAGE)  .

container-push:
	podman push $(IMAGE)

clean:
	rm -f _output/*
