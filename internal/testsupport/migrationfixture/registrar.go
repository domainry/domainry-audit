// Package migrationfixture supplies the owner-qualified migration ledger used
// by Audit integration tests. It mirrors the Runtime contract closely enough
// to catch shared-kernel owner/version collisions.
package migrationfixture

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	ormmigration "github.com/domainry/domainry-orm/migration"
)

type Registrar struct{ Database *sql.DB }

func (r Registrar) Apply(ctx context.Context, owner string, migrations []ormmigration.Migration) error {
	if r.Database == nil || owner == "" {
		return fmt.Errorf("test migration registrar is incomplete")
	}
	if _, err := r.Database.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _schema_migrations (
owner TEXT NOT NULL, version BIGINT NOT NULL, name TEXT NOT NULL, checksum TEXT NOT NULL,
dirty BOOLEAN NOT NULL, applied_at BIGINT NOT NULL, PRIMARY KEY (owner, version))`); err != nil {
		return err
	}
	for _, migration := range migrations {
		checksum := ormmigration.Checksum(migration)
		var recorded string
		var dirty bool
		err := r.Database.QueryRowContext(ctx, `SELECT checksum, dirty FROM _schema_migrations WHERE owner = ? AND version = ?`, owner, migration.Version).Scan(&recorded, &dirty)
		if err == nil {
			if dirty || recorded != checksum {
				return fmt.Errorf("test migration %s/%d drift or dirty", owner, migration.Version)
			}
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		tx, err := r.Database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO _schema_migrations (owner, version, name, checksum, dirty, applied_at) VALUES (?, ?, ?, ?, ?, ?)`, owner, migration.Version, migration.Name, checksum, true, int64(0)); err == nil {
			for _, statement := range migration.Statements {
				if _, err = tx.ExecContext(ctx, statement); err != nil {
					break
				}
			}
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE _schema_migrations SET dirty = ?, applied_at = ? WHERE owner = ? AND version = ? AND checksum = ?`, false, time.Now().UTC().UnixMilli(), owner, migration.Version, checksum)
		}
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
