package oidc

import (
	"sync"
	"time"
)

// pendingLogin is one authorization request waiting for its callback.
type pendingLogin struct {
	binding  string
	nonce    string
	verifier string
	expires  time.Time
}

// pendingStore keeps in-flight logins in memory. Entries expire after the
// TTL and are consumed by the first callback that names them.
type pendingStore struct {
	mu      sync.Mutex
	entries map[string]pendingLogin
	ttl     time.Duration
	now     func() time.Time
}

const pendingPurgeScanLimit = 32

func newPendingStore(ttl time.Duration, now func() time.Time) *pendingStore {
	return &pendingStore{entries: make(map[string]pendingLogin), ttl: ttl, now: now}
}

func (s *pendingStore) put(state string, login pendingLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	inspected := 0
	for key, entry := range s.entries {
		if inspected == pendingPurgeScanLimit {
			break
		}
		inspected++
		if !now.Before(entry.expires) {
			delete(s.entries, key)
		}
	}
	login.expires = now.Add(s.ttl)
	s.entries[state] = login
}

func (s *pendingStore) take(state string) (pendingLogin, bool) {
	if state == "" {
		return pendingLogin{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[state]
	if !ok {
		return pendingLogin{}, false
	}
	delete(s.entries, state)
	if !s.now().Before(entry.expires) {
		return pendingLogin{}, false
	}
	return entry, true
}
