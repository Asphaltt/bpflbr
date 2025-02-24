// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package strx

func IsChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
