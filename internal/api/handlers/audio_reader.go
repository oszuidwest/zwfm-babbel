package handlers

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// audioReadTracker exposes errors ServeContent does not return. Writer/socket
// failures are deliberately not classified as storage failures. Multipart
// ranges read from a goroutine, so failure inspection is synchronized too.
type audioReadTracker struct {
	source         io.ReadSeeker
	size, position int64
	mu             sync.Mutex
	err            error
}

func (r *audioReadTracker) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.position += int64(n)
	if err != nil && r.err == nil {
		if errors.Is(err, io.EOF) {
			if r.position < r.size {
				r.err = fmt.Errorf("audio ended at byte %d of %d: %w", r.position, r.size, io.ErrUnexpectedEOF)
			}
		} else {
			r.err = err
		}
	}
	return n, err
}

func (r *audioReadTracker) Seek(offset int64, whence int) (int64, error) {
	position, err := r.source.Seek(offset, whence)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.position = position
	} else if r.err == nil {
		r.err = err
	}
	return position, err
}

func (r *audioReadTracker) failure() error {
	// Do not wait for filesystem I/O: ServeContent can return after a socket
	// failure while a multipart read is still in flight.
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
