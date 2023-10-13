package util

import (
	"sync"
	"time"
)

// TokenFactory holds an access token together with a read write mutex.
type TokenFactory struct {
	token  string
	mutex  *sync.RWMutex
	expiry time.Time
}

// NewTokenFactory creates a new instance of an access token factory.
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{
		mutex: &sync.RWMutex{},
	}
}

// Get returns the current access token of the factory.
// If the token is already expired, an empty string gets returned.
func (t *TokenFactory) Get() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if time.Now().After(t.expiry) {
		t.token = ""
	}

	return t.token
}

// Set creates a new access token inside the factory with a lifetime until expiry.
func (t *TokenFactory) Set(token string, expiry time.Time) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.token = token
	t.expiry = expiry
}
