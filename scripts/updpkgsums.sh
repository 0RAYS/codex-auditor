#!/bin/bash

# repo root
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
chksum=$(git archive --format=tar HEAD xref | zstd -q -c | sha256sum | awk '{print $1}')
sed -i "s/^sha256sums=.*/sha256sums=('$chksum')/" scripts/PKGBUILD
