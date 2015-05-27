FROM golang:1.4.2-cross
MAINTAINER peter.edge@gmail.com

RUN \
	go get -v golang.org/x/tools/cmd/vet && \
	go get -v github.com/kisielk/errcheck && \
	go get -v github.com/golang/lint/golint

RUN mkdir -p /go/src/github.com/peter-edge/go-encrypt
ADD . /go/src/github.com/peter-edge/go-encrypt/
WORKDIR /go/src/github.com/peter-edge/go-encrypt
