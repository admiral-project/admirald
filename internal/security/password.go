// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minInitialAdminPasswordLen = 12
	passwordSaltSize           = 16
	passwordArgon2Time         = 1
	passwordArgon2MemoryKB     = 64 * 1024
	passwordArgon2Threads      = 4
	passwordArgon2KeyLen       = 32
)

var commonPasswords = map[string]bool{
	"password":    true,
	"12345678":    true,
	"123456789":   true,
	"1234567890":  true,
	"qwerty123":   true,
	"letmein":     true,
	"welcome":     true,
	"monkey":      true,
	"dragon":      true,
	"master":      true,
	"football":    true,
	"baseball":    true,
	"sunshine":    true,
	"trustno1":    true,
	"iloveyou":    true,
	"princess":    true,
	"passw0rd":    true,
	"abc123":      true,
	"secret":      true,
	"admin":       true,
	"password123": true,
	"12345678910": true,
	"qwertyuiop":  true,
	"ashley":      true,
	"bailey":      true,
	"shadow":      true,
	"12345":       true,
	"passwd":      true,
	"admiral":     true,
	"changeme":    true,
	"default":     true,
}

func ValidateInitialAdminPassword(username, password string) error {
	trimmed := strings.TrimSpace(password)
	if trimmed != password {
		return fmt.Errorf("admin password must not have leading or trailing spaces")
	}
	if trimmed == "" {
		return fmt.Errorf("admin password is required")
	}
	if len(trimmed) < minInitialAdminPasswordLen {
		return fmt.Errorf("admin password must be at least %d characters long", minInitialAdminPasswordLen)
	}
	if commonPasswords[strings.ToLower(trimmed)] {
		return fmt.Errorf("admin password is too weak (matches a common password)")
	}
	if strings.TrimSpace(username) == trimmed {
		return fmt.Errorf("admin password must not match the username")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, passwordArgon2Time, passwordArgon2MemoryKB, passwordArgon2Threads, passwordArgon2KeyLen)
	return fmt.Sprintf(
		"argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		passwordArgon2MemoryKB,
		passwordArgon2Time,
		passwordArgon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 5 {
		return false, fmt.Errorf("invalid argon2 hash format")
	}
	if parts[0] != "argon2id" || parts[1] != "v=19" {
		return false, fmt.Errorf("unsupported argon2 hash format")
	}

	params := strings.Split(parts[2], ",")
	if len(params) != 3 {
		return false, fmt.Errorf("invalid argon2 parameters")
	}

	memKB, err := parseArgon2Param(params[0], "m")
	if err != nil {
		return false, err
	}
	timeCost, err := parseArgon2Param(params[1], "t")
	if err != nil {
		return false, err
	}
	threads, err := parseArgon2Param(params[2], "p")
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("decode argon2 salt: %w", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode argon2 hash: %w", err)
	}

	computed := argon2.IDKey([]byte(password), salt, uint32(timeCost), uint32(memKB), uint8(threads), uint32(len(expectedHash))) //nolint:gosec // validated by parseArgon2Param (ParseUint bitSize=32)
	if subtle.ConstantTimeCompare(computed, expectedHash) != 1 {
		return false, nil
	}
	return true, nil
}

func parseArgon2Param(value, prefix string) (int, error) {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || parts[0] != prefix {
		return 0, fmt.Errorf("invalid argon2 parameter %q", value)
	}
	n, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse argon2 parameter %q: %w", value, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("argon2 parameter %q must be greater than zero", value)
	}
	return int(n), nil
}
