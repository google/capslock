#!/bin/sh

# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# This is a convenience script to convert our vector logo images to bitmaps
# in the sizes that we are about.

if ! type rsvg-convert >/dev/null 2>&1 ; then
	echo "Missing rsvg-convert" 1>&2
	test -x /usr/bin/apt && echo "Try: sudo apt install librsvg2-bin" 1>&2
	exit 1
fi

set -e

# Banner image
rsvg-convert --format=png --width=1024 \
  -o capslock-banner.png capslock-banner.svg
echo "Rendered capslock-banner.png"

# Logo to icons; add sizes as required.
for w in 256 64 ; do
    rsvg-convert --format=png --width=$w \
      -o capslock-logo${w}.png capslock-logo.svg
    echo "Rendered capslock-logo${w}.png"
done
