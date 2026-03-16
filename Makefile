BINARY  := clusterrun
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: all build clean

all: build

build:
	go build $(LDFLAGS) -o $(BINARY) ./clusterrun.go

clean:
	rm -f $(BINARY)
