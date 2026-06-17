#!/bin/bash

# repo root
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
chksum=$(git ls-files xref/ | bsdtar --zstd -cf - -T - | sha256sum | awk '{print $1}')
sed -i "s/^sha256sums=.*/sha256sums=('$chksum')/" scripts/PKGBUILD
