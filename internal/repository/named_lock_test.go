package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNamedLockReleaseConnectionReuse(t *testing.T) {
	releaseFailure := errors.New("release failed")
	tests := []struct {
		name       string
		release    driver.Value
		releaseErr error
		wantConnID int
	}{
		{name: "confirmed release reuses session", release: int64(1), wantConnID: 1},
		{name: "query error discards session", releaseErr: releaseFailure, wantConnID: 2},
		{name: "zero result discards session", release: int64(0), wantConnID: 2},
		{name: "null result discards session", release: nil, wantConnID: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := &namedLockTestConnector{
				releaseValue: tt.release,
				releaseErr:   tt.releaseErr,
			}
			db := sql.OpenDB(connector)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Errorf("db.Close() error = %v", err)
				}
			})

			release, err := NewNamedLockManager(db).acquire(t.Context(), "test-lock", time.Second)
			if err != nil {
				t.Fatalf("acquire() error = %v", err)
			}
			release()

			conn, err := db.Conn(t.Context())
			if err != nil {
				t.Fatalf("db.Conn() error = %v", err)
			}
			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("conn.Close() error = %v", err)
				}
			})

			gotConnID := 0
			if err := conn.Raw(func(raw any) error {
				gotConnID = raw.(*namedLockTestConn).id
				return nil
			}); err != nil {
				t.Fatalf("Conn.Raw() error = %v", err)
			}
			if gotConnID != tt.wantConnID {
				t.Fatalf("connection ID after release = %d, want %d", gotConnID, tt.wantConnID)
			}
		})
	}
}

type namedLockTestConnector struct {
	mu           sync.Mutex
	nextID       int
	releaseValue driver.Value
	releaseErr   error
}

func (c *namedLockTestConnector) Connect(context.Context) (driver.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	return &namedLockTestConn{parent: c, id: c.nextID}, nil
}

func (*namedLockTestConnector) Driver() driver.Driver { return namedLockTestDriver{} }

type namedLockTestDriver struct{}

func (namedLockTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use connector")
}

type namedLockTestConn struct {
	parent *namedLockTestConnector
	id     int
}

func (*namedLockTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (*namedLockTestConn) Close() error { return nil }

func (*namedLockTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (c *namedLockTestConn) QueryContext(
	_ context.Context,
	query string,
	_ []driver.NamedValue,
) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "GET_LOCK"):
		return &namedLockTestRows{value: int64(1)}, nil
	case strings.Contains(query, "RELEASE_LOCK"):
		if c.parent.releaseErr != nil {
			return nil, c.parent.releaseErr
		}
		return &namedLockTestRows{value: c.parent.releaseValue}, nil
	default:
		return nil, errors.New("unexpected query")
	}
}

type namedLockTestRows struct {
	value driver.Value
	done  bool
}

func (*namedLockTestRows) Columns() []string { return []string{"result"} }
func (*namedLockTestRows) Close() error      { return nil }

func (r *namedLockTestRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}
