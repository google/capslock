// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package proto

// This go generate directive produces the .pb.go file in this package using
// the .proto file as the source.  After any edits to the .proto file, run
// "go generate" to regenerate the .pb.go file.

//go:generate protoc --go_out=. --go_opt=module=github.com/google/capslock/proto capability.proto
