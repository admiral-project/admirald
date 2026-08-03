// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

import "strings"

// CanonicalImageReference normalizes the short Docker image forms that Podman
// expands when it resolves an image. Digest-pinned references are preserved.
func CanonicalImageReference(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "@sha256:") {
		return value
	}
	first := value
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		first = value[:slash]
	}
	if !strings.Contains(first, ".") && !strings.Contains(first, ":") && first != "localhost" {
		if strings.Contains(value, "/") {
			return "docker.io/" + value
		}
		return "docker.io/library/" + value
	}
	return value
}

func ImageReferencesEqual(actual, expected string) bool {
	actual = CanonicalImageReference(actual)
	expected = CanonicalImageReference(expected)
	return actual != "" && actual == expected
}
