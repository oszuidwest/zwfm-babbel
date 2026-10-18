package tts

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Returning less than Content-Length closes the server response mid-body.
func TestGenerateSpeech_TruncatedBodyIsTransportFailure(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("partial"))
			}))
			t.Cleanup(server.Close)
			service := &Service{baseURL: server.URL, client: server.Client()}
			_, err := service.GenerateSpeech(t.Context(), "news", "voice", Options{})
			if _, ok := errors.AsType[*TransportError](err); !ok || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want TransportError wrapping unexpected EOF", err)
			}
		})
	}
}

// Cancelling in Read exercises the body-read path after client.Do succeeded.
func TestGenerateSpeech_CancelledBodyReadIsNotTransportFailure(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		for _, readErr := range []error{context.Canceled, io.ErrUnexpectedEOF} {
			t.Run(strconv.Itoa(status)+"/"+readErr.Error(), func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				service := &Service{baseURL: "http://tts.test", client: &http.Client{
					Transport: bodyCancelTransport{status: status, cancel: cancel, err: readErr},
				}}
				_, err := service.GenerateSpeech(ctx, "news", "voice", Options{})
				if _, ok := errors.AsType[*TransportError](err); ok || !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want context.Canceled without TransportError", err)
				}
				if !errors.Is(err, readErr) {
					t.Fatalf("error = %v, want original read error %v preserved", err, readErr)
				}
			})
		}
	}
}

// bodyCancelTransport returns a response whose first read cancels the caller.
type bodyCancelTransport struct {
	status int
	cancel context.CancelFunc
	err    error
}

func (c bodyCancelTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: c.status, Header: make(http.Header), Body: cancelBody{cancel: c.cancel, err: c.err}}, nil
}

type cancelBody struct {
	cancel context.CancelFunc
	err    error
}

func (c cancelBody) Read([]byte) (int, error) { c.cancel(); return 0, c.err }
func (cancelBody) Close() error               { return nil }
