#!/bin/bash


set -ex

GIT_SHA=`git rev-parse --short HEAD|cut -c 1-7 || echo "HEAD"`
version="v1.23.6"

make all WHAT=cmd/kubelet GOFLAGS=-v KUBE_GIT_VERSION=$version-$GIT_SHA
ls _output/bin/kubelet
