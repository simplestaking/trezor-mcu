#!/bin/bash
set -e

IMAGE=trezor-mcu-build-emulator64
TAG=${1:-master}
ELFFILE=build/trezor-emulator64-$TAG

docker build -f Dockerfile.emulator -t $IMAGE .
docker run -t -v $(pwd)/build:/build:z $IMAGE /bin/sh -c "\
    export LC_ALL=C.UTF-8 && \
    export LANG=C.UTF-8 && \
	cd trezor-mcu && \
	make -C vendor/nanopb/generator/proto && \
	make -C firmware/protob && \
	EMULATOR=1 make && \
	EMULATOR=1 make -C emulator && \
	EMULATOR=1 make -C firmware && \
	cp firmware/trezor.elf /$ELFFILE"
