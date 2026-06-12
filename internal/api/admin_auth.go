// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func (h *APIHandlers) hashToken(input string) string {
	mac := hmac.New(sha256.New, []byte(h.hmacKey))
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}
