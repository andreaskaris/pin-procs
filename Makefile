IMAGE ?= quay.io/akaris/pin-procs

build:
	CGO_ENABLED=0 GOOS=linux go build -o _output/pin-procs .

clean:
	rm -f _output/*

container-build:
	podman build -t $(IMAGE)  .

container-push:
	podman push $(IMAGE)

deploy:
	kubectl apply -f daemonset.yaml
