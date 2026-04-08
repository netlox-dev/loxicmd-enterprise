.DEFAULT_GOAL := build
bin=loxicmd
dock?=loxilb
SHELL := /bin/bash

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
  GOARCH := arm64
else ifeq ($(ARCH),armv7l)
  GOARCH := arm
  GOARM  := 7
else ifeq ($(ARCH),armv6l)
  GOARCH := arm
  GOARM  := 6
else
  GOARCH := amd64
endif

loxilbid=$(shell docker ps -f name=$(dock) | grep -w $(dock) | cut  -d " "  -f 1 | grep -iv  "CONTAINER")

build:
	@GOARCH=$(GOARCH) GOARM=$(GOARM) go build -o ${bin} -ldflags="-X 'loxicmd/cmd.BuildInfo=${shell date '+%Y_%m_%d'}-${shell git branch --show-current}-$(shell git show --pretty=format:%h --no-patch)'"

build-amd64:
	@GOARCH=amd64 go build -o ${bin}-amd64 -ldflags="-X 'loxicmd/cmd.BuildInfo=${shell date '+%Y_%m_%d'}-${shell git branch --show-current}-$(shell git show --pretty=format:%h --no-patch)'"

build-arm64:
	@GOARCH=arm64 go build -o ${bin}-arm64 -ldflags="-X 'loxicmd/cmd.BuildInfo=${shell date '+%Y_%m_%d'}-${shell git branch --show-current}-$(shell git show --pretty=format:%h --no-patch)'"

build-arm:
	@GOARCH=arm GOARM=7 go build -o ${bin}-arm -ldflags="-X 'loxicmd/cmd.BuildInfo=${shell date '+%Y_%m_%d'}-${shell git branch --show-current}-$(shell git show --pretty=format:%h --no-patch)'"

test: 
	go test

check:
	go test

run:
	./$(bin)

install:
	cp loxicmd /usr/local/sbin/
	/usr/local/sbin/loxicmd completion bash > /etc/bash_completion.d/loxi_completion 
	source /etc/bash_completion.d/loxi_completion

docker-cp: build
	docker cp loxicmd $(loxilbid):/usr/local/sbin/loxicmd