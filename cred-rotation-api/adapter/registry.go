package adapter

import (
	"fmt"
	"sync"
)

// Registry holds named adapters and routes rotation requests to the correct one.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds an adapter under its own Name(). Panics on duplicate registration.
func (r *Registry) Register(a Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := a.Name()
	if _, exists := r.adapters[name]; exists {
		panic(fmt.Sprintf("adapter %q already registered", name))
	}
	r.adapters[name] = a
}

// Get returns the adapter for the given name, or an error if not found.
func (r *Registry) Get(name string) (Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	if !ok {
		return nil, fmt.Errorf("no adapter registered for provider %q", name)
	}
	return a, nil
}

// Names returns the registered adapter names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.adapters))
	for n := range r.adapters {
		names = append(names, n)
	}
	return names
}
