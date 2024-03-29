#!/bin/bash

FRAME=$1 # "y" or "n"
OPTIM=$2 # "O0" or "O2"

usage()
{
	echo "Usage:"
	echo "  $0 FRAME OPTIM"
	echo "Arguments:"
	echo "  FRAME    -fno-omit-frame-pointer enabled? 'y' or 'n'"
	echo "  OPTIM    'O0' or 'O2'"
}

if [ "${FRAME}" == "y" ] ; then
	FRAME_TAG="with-frame"
elif [ "${FRAME}" == "n" ] ; then
	FRAME_TAG="no-frame"
else
	usage
	exit 1
fi
if [[ "${OPTIM}" == "O0" || "${OPTIM}" == "O2" ]] ; then
	OPTIM_TAG="${OPTIM}"
else
	usage
	exit 1
fi

MACHINE="$(uname -m)"
if [ "${MACHINE}" == "x86_64" ] ; then
	MACHINE="amd64"
elif [ "${MACHINE}" == "aarch64" ] ; then
	MACHINE="arm64"
fi

set -e

##
# Package version needs to be decimal
##
GITREV="$(git rev-parse --short=10 HEAD)"
GITTAG="$(git describe --tags | grep -o -E "frr-[^-]+(-[A-Za-z]+)?")"
PKGVER="$(printf '%u\n' 0x$GITREV)"

if [ "${MACHINE}" == "x86_64" ] ; then
	MACHINE="amd64"
elif [ "${MACHINE}" == "aarch64" ] ; then
	MACHINE="arm64"
else
	MACHINE="${MACHINE}"
fi

docker build \
	--platform=linux/${MACHINE} \
	--file=docker/centos-7/${FRAME_TAG}/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--build-arg="OPTIM_TAG=$OPTIM_TAG" \
	--tag="ponedo/frr-centos7:${MACHINE}-${GITTAG}-${FRAME_TAG}-${OPTIM_TAG}" \
	.
