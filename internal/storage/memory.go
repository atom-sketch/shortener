package storage

import (
	"strconv"
	"sync"
)

type Link struct {
	ID          string
	OriginalURL string
}

type Memory struct {
	mu     sync.RWMutex
	nextID uint64
	byID   map[string]string
	byUser map[string][]Link
}

func NewMemory() *Memory {
	return &Memory{
		byID:   make(map[string]string),
		byUser: make(map[string][]Link),
	}
}

func (m *Memory) Add(userID, originalURL string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	id := strconv.FormatUint(m.nextID, 36)
	m.byID[id] = originalURL
	m.byUser[userID] = append(m.byUser[userID], Link{ID: id, OriginalURL: originalURL})
	return id
}

func (m *Memory) OriginalURL(id string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	originalURL, ok := m.byID[id]
	return originalURL, ok
}

func (m *Memory) UserLinks(userID string) []Link {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return append([]Link(nil), m.byUser[userID]...)
}
