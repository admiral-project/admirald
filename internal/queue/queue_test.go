package queue

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestNameUUIDIsDeterministicAndWellFormed(t *testing.T) {
	a := nameUUID("seed-value")
	b := nameUUID("seed-value")
	c := nameUUID("other-seed")

	if a != b {
		t.Fatalf("expected deterministic UUID, got %q and %q", a, b)
	}
	if a == c {
		t.Fatalf("expected different UUIDs for different seeds, got %q", a)
	}
	if len(a) != 36 || a[8] != '-' || a[13] != '-' || a[18] != '-' || a[23] != '-' {
		t.Fatalf("unexpected UUID format %q", a)
	}
}

func TestRandomHexLength(t *testing.T) {
	got, err := randomHex(16)
	if err != nil {
		t.Fatalf("randomHex failed: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%q)", len(got), got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("expected valid hex string, got %q: %v", got, err)
	}
}

func TestRandomHexPropagatesReaderError(t *testing.T) {
	original := randomReader
	randomReader = failingReader{}
	t.Cleanup(func() { randomReader = original })

	_, err := randomHex(16)
	if !errors.Is(err, errRandomReader) {
		t.Fatalf("expected random reader error, got %v", err)
	}
}

var errRandomReader = errors.New("random reader failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRandomReader }

func TestSignPayloadProducesVerifiableSignature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	p := NewPublisher(nil, nil, seed, nil)

	payload := []byte(`{"task":"demo"}`)
	signedAt := int64(1710000000)
	sigHex := p.signPayload(payload, signedAt)

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	msg := append(payload, []byte(fmt.Sprintf("%d", signedAt))...)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("expected signature to verify")
	}
}

func TestSealPayloadPassthroughWithoutEncryptionKey(t *testing.T) {
	p := NewPublisher(nil, nil, make([]byte, ed25519.SeedSize), nil)
	plaintext := []byte(`{"task":"plain"}`)

	got, err := p.sealPayload(plaintext)
	if err != nil {
		t.Fatalf("seal payload: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("expected plaintext passthrough, got %q", got)
	}
}

func TestSealPayloadEncryptsWithWrapper(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	key := []byte("0123456789abcdef0123456789abcdef")
	p := NewPublisher(nil, nil, seed, key)
	plaintext := []byte(`{"task":"secret"}`)

	got, err := p.sealPayload(plaintext)
	if err != nil {
		t.Fatalf("seal payload: %v", err)
	}
	if string(got) == string(plaintext) {
		t.Fatal("expected encrypted wrapper, got plaintext")
	}

	var wrapper map[string]string
	if err := json.Unmarshal(got, &wrapper); err != nil {
		t.Fatalf("unmarshal wrapper: %v", err)
	}
	ct := wrapper["ct"]
	if ct == "" {
		t.Fatalf("expected ciphertext wrapper, got %v", wrapper)
	}
	if _, err := base64.StdEncoding.DecodeString(ct); err != nil {
		t.Fatalf("expected base64 ciphertext, got %q: %v", ct, err)
	}
}
