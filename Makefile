CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

# Go dependencies
GO_MOD := go.mod

all: generate build

generate:
	go generate ./...

build: generate
	cd cmd/agent && go build -o ../../phantom-grid .
	cd cmd/spa-client && go build -o ../../spa-client .

run: build
	sudo ./phantom-grid

# Run with specific interface
# Usage: make run-interface INTERFACE=ens33
run-interface: build
	sudo ./phantom-grid -interface $(INTERFACE)

clean:
	rm -f phantom-grid spa-client
	rm -f cmd/agent/phantom_bpf*
	rm -f cmd/agent/egress_bpf*

deps:
	go mod tidy


