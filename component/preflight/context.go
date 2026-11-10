// Package preflight holds the one-shot read-only parser context.
package preflight

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
)

// 作者 long：只有独立校验进程启用此上下文，运行核心默认完全不经过资源替身；一次解析后销毁进程。
type Context struct {
	mu             sync.Mutex
	loader         func(string) ([]byte, error)
	resources      map[string][]byte
	section        string
	index          int
	failure        string
	failureSection string
	failureIndex   int
	deferred       int
}

var active atomic.Pointer[Context]
var ErrReadOnly = errors.New("preflight external resource unavailable")
var ErrNetwork = errors.New("preflight network forbidden")

func Enable(loader func(string) ([]byte, error)) error {
	c := &Context{loader: loader, resources: map[string][]byte{}, section: "config", index: -1}
	if !active.CompareAndSwap(nil, c) {
		return errors.New("preflight context already active")
	}
	return nil
}
func Enabled() bool { return active.Load() != nil }
func Location(section string, index int) {
	if c := active.Load(); c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.section = section
		c.index = index
	}
}
func Reject(code string) error {
	if c := active.Load(); c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.failure == "" {
			c.failure = code
			c.failureSection = c.section
			c.failureIndex = c.index
		}
	}
	return ErrReadOnly
}
func Resource(name string) ([]byte, error) {
	c := active.Load()
	if c == nil {
		return nil, ErrReadOnly
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.resources[name]; ok {
		return b, nil
	}
	b, err := c.loader(name)
	if err != nil {
		if c.failure == "" {
			c.failure = "resource_unavailable"
			c.failureSection = c.section
			c.failureIndex = c.index
		}
		return nil, ErrReadOnly
	}
	c.resources[name] = b
	return b, nil
}
func ReadFile(path string) ([]byte, error) {
	if Enabled() {
		return Resource(path)
	}
	return os.ReadFile(path)
}
func DeferExternal() {
	if c := active.Load(); c != nil {
		c.mu.Lock()
		c.deferred++
		c.mu.Unlock()
	}
}
func Status() (section string, index int, failure string, deferred int) {
	if c := active.Load(); c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.failure != "" {
			return c.failureSection, c.failureIndex, c.failure, c.deferred
		}
		return c.section, c.index, c.failure, c.deferred
	}
	return "config", -1, "not_isolated", 0
}
