BINARY := ssh_parallel

.PHONY: all build clean

all: build

build:
	go build -o $(BINARY) ./ssh_parallel.go

clean:
	rm -f $(BINARY)
