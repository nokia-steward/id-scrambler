#!/bin/sh
# Populate ./wheelhouse with every wheel the Docker build installs, so that
# `docker build` needs no network access of its own.
#
# The wheels are resolved for the *container* interpreter, not the host one, so
# these tags have to track the base image in the Dockerfile: musl (Alpine, via
# python:3.14-alpine) and CPython 3.14. Each architecture gets its own
# subdirectory, named after Docker's TARGETARCH values so the Dockerfile can
# select one directly; keeping them apart stops a cross-architecture wheel from
# ending up in an image layer.
set -eu

ARCHS="${ARCHS:-amd64 arm64}"
PYTHON_VERSION="${PYTHON_VERSION:-3.14}"
ABI="${ABI:-cp314}"
PYTHON="${PYTHON:-python3}"

# Must match `[build-system] requires` in pyproject.toml. Nothing checks that
# here, but the container build does: it resolves the PEP 517 backend out of
# this wheelhouse under --no-index, so a mismatch fails the build rather than
# silently producing an image built with an unpinned setuptools.
BUILD_REQUIRES="${BUILD_REQUIRES:-setuptools==84.0.0}"

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
wheelhouse="$repo_root/wheelhouse"

# Start clean so that wheels left over from an earlier interpreter or platform
# cannot satisfy the install and mask a missing download.
rm -rf "$wheelhouse"

for arch in $ARCHS; do
    case "$arch" in
        amd64) machine=x86_64 ;;
        arm64) machine=aarch64 ;;
        *)
            echo "$0: unsupported architecture '$arch'" >&2
            exit 1
            ;;
    esac

    mkdir -p "$wheelhouse/$arch"

    # musllinux_1_2 is what the Alpine 3.24 base can load (musl 1.2); the older
    # musllinux_1_1 tag is accepted too, for dependencies that publish nothing
    # newer. --only-binary keeps the download honest: a source distribution
    # would have to be compiled inside the container, which is what the
    # wheelhouse exists to avoid.
    # shellcheck disable=SC2086 # BUILD_REQUIRES may name several requirements
    "$PYTHON" -m pip download \
        --only-binary=:all: \
        --platform "musllinux_1_2_$machine" \
        --platform "musllinux_1_1_$machine" \
        --implementation cp \
        --python-version "$PYTHON_VERSION" \
        --abi "$ABI" \
        --dest "$wheelhouse/$arch" \
        --requirement "$repo_root/requirements.txt" \
        $BUILD_REQUIRES
done
