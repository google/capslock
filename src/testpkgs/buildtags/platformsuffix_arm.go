// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build !foo

// Package buildtags is used for testing.
package buildtags

import (
	"net"
)

func Foo() {
	ips, err := net.LookupIP("localhost")
	if err != nil {
		println(err)
	}
	println(len(ips))
}
