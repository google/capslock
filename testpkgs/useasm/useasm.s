// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "textflag.h"

TEXT ·bar(SB),NOSPLIT,$0-16
	MOVQ x+0(FP), AX
	SHLQ $1, AX
	MOVQ AX, ret+8(FP)
	RET
