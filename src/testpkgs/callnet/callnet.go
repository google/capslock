// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package callnet is used for testing.
package callnet

import (
	"net"
)

// Foo is a test function.
func Foo() int {
	ips, err := net.LookupIP("localhost")
	if err != nil {
		println(err)
	}
	return len(ips)
}
