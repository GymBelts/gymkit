package secret

import "testing"

func TestEncryptionRoundTrip(t *testing.T) {
	secret := "test-secret"
	enc, err := Encrypt("hello", secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(enc, secret)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "hello" {
		t.Fatalf("got %q", plain)
	}
	if _, err := Decrypt(enc, "other"); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "(not set)"},
		{"short", "••••••••"},
		{"1234567", "••••••••"},
		{"sk-or-v1-abcdefghijklmnop", "sk-o••••mnop"},
		{"abcdefgh", "abcd••••efgh"},
	}
	for _, tt := range tests {
		if got := MaskSecret(tt.in); got != tt.want {
			t.Errorf("MaskSecret(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEncryptionKey(t *testing.T) {
	if got := EncryptionKey("session", ""); got != "session" {
		t.Fatalf("fallback: %q", got)
	}
	if got := EncryptionKey("session", "settings"); got != "settings" {
		t.Fatalf("override: %q", got)
	}
}
