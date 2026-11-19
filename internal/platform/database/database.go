// Package database holds the Postgres pool and runs work in a transaction carried by the context, so
// repositories stay unaware of whether they run inside one.
package database

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is what repositories need; both the pool and a transaction provide it.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type DB struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	// Sessions run in UTC whatever the server's or the caller's region: now() and every timestamptz read are UTC.
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &DB{Pool: pool}, nil
}

type txKey struct{}

// Q returns the transaction of ctx when there is one, else the pool.
func (d *DB) Q(ctx context.Context) Querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return d.Pool
}

// InTx runs fn in one transaction: committed when fn returns nil, rolled back otherwise. Nested calls join the outer one.
// A transaction Postgres aborts to break a deadlock or a serialization conflict is run again (fn must only touch
// the database and its own results), up to maxAttempts times, so racing saves are ordered instead of failing.
func (d *DB) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err = d.once(ctx, fn); !retryable(err) {
			return err
		}
		time.Sleep(time.Duration(attempt*attempt*5+rand.IntN(10)) * time.Millisecond)
	}
	return err
}

const maxAttempts = 4

func (d *DB) once(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// retryable: deadlock_detected (40P01) or serialization_failure (40001).
func retryable(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == "40P01" || pg.Code == "40001")
}

// WithTx puts an existing transaction in ctx (tests roll it back afterwards).
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}
