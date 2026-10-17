package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestWithTransactionKeepsContextErrorWhenCommitFindsTxDone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// request returns the request context and a func that fn calls
		// after the last statement.
		request func(t *testing.T) (context.Context, func())
		want    error
	}{
		{"canceled", func(t *testing.T) (context.Context, func()) {
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			return ctx, cancel
		}, context.Canceled},
		{"deadline", func(t *testing.T) (context.Context, func()) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			return ctx, func() {}
		}, context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The bubble's fake clock lets the deadline pass only once fn
			// waits for the rollback.
			synctest.Test(t, func(t *testing.T) {
				rolledBack := make(chan struct{})
				db := fakeTxDB(t, &fakeTx{rolledBack: rolledBack})

				ctx, end := tt.request(t)
				err := NewTxManager(db).WithTransaction(ctx, func(context.Context) error {
					// The request ends after the last statement: database/sql
					// rolls the transaction back before the commit.
					end()
					<-rolledBack
					return nil
				})
				if !errors.Is(err, sql.ErrTxDone) || !errors.Is(err, tt.want) {
					t.Fatalf("WithTransaction = %v, want sql.ErrTxDone and %v", err, tt.want)
				}
			})
		})
	}
}

func TestWithTransactionKeepsCommitFailureWhenCanceledLater(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	commitErr := errors.New("connection lost")
	db := fakeTxDB(t, &fakeTx{commit: func() error {
		cancel()
		return commitErr
	}})

	err := NewTxManager(db).WithTransaction(ctx, func(context.Context) error { return nil })
	if !errors.Is(err, commitErr) || errors.Is(err, context.Canceled) {
		t.Fatalf("WithTransaction = %v, want only the commit failure", err)
	}
}

// fakeTxDB returns a GORM handle whose connections run every transaction on tx.
func fakeTxDB(t *testing.T, tx *fakeTx) *gorm.DB {
	t.Helper()
	sqlDB := sql.OpenDB(fakeTxConnector{tx: tx})
	t.Cleanup(func() { _ = sqlDB.Close() })
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true}),
		&gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

type fakeTxConnector struct{ tx *fakeTx }

func (c fakeTxConnector) Connect(context.Context) (driver.Conn, error) { return fakeTxConn(c), nil }

func (fakeTxConnector) Driver() driver.Driver { return nil }

type fakeTxConn struct{ tx *fakeTx }

func (fakeTxConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }

func (fakeTxConn) Close() error { return nil }

func (c fakeTxConn) Begin() (driver.Tx, error) { return c.tx, nil }

// fakeTx runs commit on Commit and closes rolledBack on Rollback; nil fields
// make either a no-op.
type fakeTx struct {
	commit     func() error
	rolledBack chan struct{}
}

func (tx *fakeTx) Commit() error {
	if tx.commit == nil {
		return nil
	}
	return tx.commit()
}

func (tx *fakeTx) Rollback() error {
	if tx.rolledBack != nil {
		close(tx.rolledBack)
	}
	return nil
}
