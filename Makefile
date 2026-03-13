BINARY := clusterrun

.PHONY: all build clean

all: build

build:
	go build -o $(BINARY) ./clusterrun.go

clean:
	rm -f $(BINARY)
