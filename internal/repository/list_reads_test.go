package repository

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gorm.io/gorm"
)

func TestApplyListQueryOverlapsCountAndPage(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		db := dryRunDB(t)
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatal(err)
		}
		// The pool's opener goroutine must end inside the bubble.
		defer func() { _ = sqlDB.Close() }()
		countStarted, pageStarted := make(chan struct{}), make(chan struct{})
		// Each query waits for the other to start, so sequential reads deadlock.
		if err := db.Callback().Query().Replace("gorm:query", func(db *gorm.DB) {
			if count, ok := db.Statement.Dest.(*int64); ok {
				close(countStarted)
				<-pageStarted
				*count = 12
			} else {
				close(pageStarted)
				<-countStarted
				*db.Statement.Dest.(*[]struct{ ID int64 }) = []struct{ ID int64 }{{ID: 7}}
			}
			db.RowsAffected = 1
		}); err != nil {
			t.Fatal(err)
		}
		result, err := ApplyListQuery[struct{ ID int64 }](db.Table("stories"), &ListQuery{Limit: 2, Offset: 3}, storyFieldMapping, nil, nil)
		if err != nil || result.Total != 12 || len(result.Data) != 1 || result.Data[0].ID != 7 || result.Limit != 2 || result.Offset != 3 {
			t.Fatalf("result = %+v, error = %v", result, err)
		}
	})
}

func TestApplyListQueryRejectsSortBeforeQuerying(t *testing.T) {
	t.Parallel()
	db := dryRunDB(t)
	var queries atomic.Int64
	if err := db.Callback().Query().Replace("gorm:query", func(*gorm.DB) { queries.Add(1) }); err != nil {
		t.Fatal(err)
	}
	_, err := ApplyListQuery[struct{ ID int64 }](db.Table("stories"),
		&ListQuery{Sort: []SortField{{Field: "unknown"}}}, storyFieldMapping, nil, nil)
	if _, ok := errors.AsType[*UnknownFieldError](err); !ok || queries.Load() != 0 {
		t.Fatalf("error = %v, queries = %d; want unknown sort field before any query", err, queries.Load())
	}
}

func TestConcurrentlyReturnsFirstErrorInArgumentOrder(t *testing.T) {
	t.Parallel()
	first, second := errors.New("first failed"), errors.New("second failed")
	for _, test := range []struct {
		name          string
		first, second error
		want          error
	}{
		{name: "both fail", first: first, second: second, want: first},
		{name: "second fails", second: second, want: second},
		{name: "none fail"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ran atomic.Int64
			err := concurrently(dryRunDB(t),
				func() error { ran.Add(1); return test.first },
				func() error { ran.Add(1); return test.second },
			)
			if !errors.Is(err, test.want) || (test.want == nil && err != nil) || ran.Load() != 2 {
				t.Fatalf("error = %v, ran = %d; want %v after both ran", err, ran.Load(), test.want)
			}
		})
	}
}

func TestConcurrentlyResumesPanicOnCaller(t *testing.T) {
	t.Parallel()
	var finished atomic.Bool
	defer func() {
		p := recover()
		err, ok := p.(error)
		if !ok || !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), t.Name()) || !finished.Load() {
			t.Fatalf("recovered %v, other query finished = %v; want the panic and its origin after all queries finish", p, finished.Load())
		}
	}()
	_ = concurrently(dryRunDB(t),
		func() error { panic("boom") },
		func() error { finished.Store(true); return nil },
	)
	t.Fatal("concurrently returned, want panic")
}

func TestConcurrentlyKeepsTransactionsSequential(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		tx := fakeTxDB(t, &fakeTx{}).Begin()
		defer tx.Rollback()
		var completed atomic.Bool
		failed := errors.New("first failed")
		err := concurrently(tx,
			func() error {
				time.Sleep(time.Second)
				completed.Store(true)
				return nil
			},
			func() error {
				if !completed.Load() {
					return errors.New("second query ran before the first completed")
				}
				return failed
			},
			func() error {
				t.Error("query ran after an earlier failure")
				return nil
			},
		)
		if !errors.Is(err, failed) {
			t.Fatalf("error = %v, want %v", err, failed)
		}
	})
}
