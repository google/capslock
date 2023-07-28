// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package initfn is used for testing.
package initfn

import (
	"net"
	"os"
	"reflect"
	"runtime/debug"
	"unsafe"
)

// init function
func init() {
	ips, err := net.LookupIP("localhost")
	if err != nil {
		println(err)
	}
	println(len(ips))
}

// another init function
func init() {
	debug.SetMaxThreads(123)
}

// X is initialized by a function call.
var X int = os.Getpid()

// UP is initialized with an unsafe.Pointer conversion.
var UP *uint = (*uint)(unsafe.Pointer(&X))

// The initialization of these variables copies a reflect.Value.
var rv1 reflect.Value
var rv2 = rv1
