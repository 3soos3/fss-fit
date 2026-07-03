package revocation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one record in the revocation list (FSS-0006 §6.4).
type Entry struct {
	JTI              string `json:"jti"`
	ISS              string `json:"iss"`
	RevokedAt        string `json:"revoked_at"`
	RevocationReason string `json:"revocation_reason"`
	RevokedBy        string `json:"revoked_by"`
}

// Store manages the on-disk revocation list and an in-memory set.
type Store struct {
	mu         sync.Mutex
	path       string
	set        map[string]struct{}
	lastLoaded time.Time
	cacheValid bool
}

func profileTTL(profile string) time.Duration {
	switch profile {
	case "B":
		return 60 * time.Second
	case "C":
		return 120 * time.Second
	default: // "A" and unset
		return 300 * time.Second
	}
}

// New opens (or creates) the revocation file and loads it into memory.
func New(dataDir string) (*Store, error) {
	path := filepath.Join(dataDir, "revoked_jtis.json")
	s := &Store{path: path, set: make(map[string]struct{})}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := s.writeFileLocked(nil); err != nil {
			return nil, fmt.Errorf("create revocation file: %w", err)
		}
	}
	if err := s.reloadLocked(); err != nil {
		return nil, fmt.Errorf("load revocation list: %w", err)
	}
	return s, nil
}

// Revoke appends an entry atomically and updates the in-memory set.
func (s *Store) Revoke(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.readFileLocked()
	if err != nil {
		return err
	}
	entries = append(entries, e)
	if err := s.writeFileLocked(entries); err != nil {
		return err
	}
	s.set[e.JTI] = struct{}{}
	s.cacheValid = false
	return nil
}

// IsRevoked checks the in-memory set, reloading from disk if the
// profile-based TTL has elapsed.
func (s *Store) IsRevoked(jti, profile string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cacheValid || time.Since(s.lastLoaded) > profileTTL(profile) {
		if err := s.reloadLocked(); err != nil {
			return false, err
		}
	}
	_, found := s.set[jti]
	return found, nil
}

// InvalidateCache forces the next IsRevoked call to reload from disk.
func (s *Store) InvalidateCache() {
	s.mu.Lock()
	s.cacheValid = false
	s.mu.Unlock()
}

func (s *Store) reloadLocked() error {
	entries, err := s.readFileLocked()
	if err != nil {
		return err
	}
	newSet := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		newSet[e.JTI] = struct{}{}
	}
	s.set = newSet
	s.lastLoaded = time.Now()
	s.cacheValid = true
	return nil
}

func (s *Store) readFileLocked() ([]Entry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse revocation file: %w", err)
	}
	return entries, nil
}

func (s *Store) writeFileLocked(entries []Entry) error {
	if entries == nil {
		entries = []Entry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
