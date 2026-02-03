package transport

import (
	"errors"
	"sync"
)

var (
	// ErrTransportNotFound is returned when a requested transport is not registered
	ErrTransportNotFound = errors.New("transport not found")

	// ErrTransportExists is returned when trying to register a transport that already exists
	ErrTransportExists = errors.New("transport already registered")
)

// Factory is a function that creates a new Transport instance
type Factory func(cfg interface{}) (Transport, error)

// Registry manages registered transport types
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry creates a new transport registry
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
	}
}

// Register adds a transport factory to the registry
func (r *Registry) Register(name string, factory Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		return ErrTransportExists
	}

	r.factories[name] = factory
	return nil
}

// Create instantiates a transport by name with the given configuration
func (r *Registry) Create(name string, cfg interface{}) (Transport, error) {
	r.mu.RLock()
	factory, exists := r.factories[name]
	r.mu.RUnlock()

	if !exists {
		return nil, ErrTransportNotFound
	}

	return factory(cfg)
}

// List returns the names of all registered transports
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// Has checks if a transport is registered
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.factories[name]
	return exists
}

// DefaultRegistry is the global transport registry
var DefaultRegistry = NewRegistry()

// Register adds a transport to the default registry
func Register(name string, factory Factory) error {
	return DefaultRegistry.Register(name, factory)
}

// Create instantiates a transport from the default registry
func Create(name string, cfg interface{}) (Transport, error) {
	return DefaultRegistry.Create(name, cfg)
}

// List returns all transports in the default registry
func List() []string {
	return DefaultRegistry.List()
}

// Has checks if a transport exists in the default registry
func Has(name string) bool {
	return DefaultRegistry.Has(name)
}
