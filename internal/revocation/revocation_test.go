package revocation_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/3soos3/fit-issuer/internal/revocation"
)

func TestNew(t *testing.T) {
	dir := t.TempDir()
	s, err := revocation.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ok, err := s.IsRevoked("nonexistent", "A")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if ok {
		t.Error("expected not revoked on empty store")
	}
}

func TestRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := revocation.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	e := revocation.Entry{
		JTI:              "770a0600-e29b-41d4-a716-446655440002",
		ISS:              "https://fit.example.org",
		RevokedAt:        time.Now().UTC().Format(time.RFC3339),
		RevocationReason: "test",
		RevokedBy:        "tester",
	}
	if err := s.Revoke(e); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	ok, err := s.IsRevoked(e.JTI, "A")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !ok {
		t.Error("expected jti to be revoked")
	}

	// Verify all 5 FSS-0006 §6.4 fields are persisted
	data, err := os.ReadFile(filepath.Join(dir, "revoked_jtis.json"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var entries []revocation.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got.JTI == ""              { t.Error("jti empty") }
	if got.ISS == ""              { t.Error("iss empty") }
	if got.RevokedAt == ""        { t.Error("revoked_at empty") }
	if got.RevocationReason == "" { t.Error("revocation_reason empty") }
	if got.RevokedBy == ""        { t.Error("revoked_by empty") }
}

func TestNotRevoked(t *testing.T) {
	dir := t.TempDir()
	s, _ := revocation.New(dir)
	ok, _ := s.IsRevoked("some-other-jti", "A")
	if ok {
		t.Error("absent jti should not be revoked")
	}
}

func TestProfileTTL(t *testing.T) {
	dir := t.TempDir()
	s, err := revocation.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, profile := range []string{"A", "B", "C", ""} {
		if _, err := s.IsRevoked("x", profile); err != nil {
			t.Errorf("IsRevoked with profile %q: %v", profile, err)
		}
	}
}

func TestCacheInvalidation(t *testing.T) {
	dir := t.TempDir()
	s, err := revocation.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const jti = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

	ok, _ := s.IsRevoked(jti, "A")
	if ok {
		t.Fatal("should not be revoked before Revoke")
	}

	e := revocation.Entry{
		JTI: jti, ISS: "x", RevokedAt: "now",
		RevocationReason: "r", RevokedBy: "b",
	}
	if err := s.Revoke(e); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Revoke invalidates the cache; next call must reload and find the entry
	ok, err = s.IsRevoked(jti, "A")
	if err != nil {
		t.Fatalf("IsRevoked after revoke: %v", err)
	}
	if !ok {
		t.Error("expected jti revoked after Revoke")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	s, err := revocation.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := revocation.Entry{
		JTI: "bbb", ISS: "x", RevokedAt: "now",
		RevocationReason: "r", RevokedBy: "b",
	}
	if err := s.Revoke(e); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Tmp file should not exist after successful write
	if _, err := os.Stat(filepath.Join(dir, "revoked_jtis.json.tmp")); !os.IsNotExist(err) {
		t.Error(".tmp file should not exist after successful Revoke")
	}
}
