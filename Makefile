APP_NAME ?= exposure

.PHONY : install sudoinstall

SOURCES = $(wildcard *.go)

export STARTD := $(shell pwd)
export THIS := $(abspath $(lastword $(MAKEFILE_LIST)))
export THISD := $(dir $(THIS))

export COMMIT_ID := $(shell git describe --tags --always --dirty 2>/dev/null)
export COMMIT_TIME := $(shell git show -s --format=%ct 2>/dev/null)

export LDFLAGS := -X 'main.VERSION=$(COMMIT_ID).$(COMMIT_TIME)'

build: $(APP_NAME)

install: $(GOBIN)/$(APP_NAME)

$(APP_NAME) $(GOBIN)/$(APP_NAME): $(SOURCES)
	go build -ldflags="$(LDFLAGS)" -o $@

test: $(APP_NAME)
	echo hello | tee /dev/stderr | ./exposure conceal alias/secret | tee /dev/stderr | ./exposure reveal
	date | tee /dev/stderr | ./exposure conceal alias/secret | tee /dev/stderr | ./exposure reveal
