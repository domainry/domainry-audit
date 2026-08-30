package module

import (
	"context"
	"database/sql"
	"testing"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	_ "modernc.org/sqlite"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type testHost struct {
	database modulehost.Database
	dialect  modulehost.Dialect
}

func newTestHost(t *testing.T, db *sql.DB) testHost {
	t.Helper()
	dialect, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return testHost{database: db, dialect: dialect}
}
func (h testHost) Database() modulehost.Database             { return h.database }
func (h testHost) Dialect() modulehost.Dialect               { return h.dialect }
func (h testHost) Migrations() modulehost.MigrationRegistrar { return testMigrationRegistrar{host: h} }

type testMigrationRegistrar struct{ host testHost }

func (testMigrationRegistrar) Driver() string { return "sqlite" }
func (testMigrationRegistrar) Schema() string { return "" }
func (r testMigrationRegistrar) ApplyOwnedMigrations(ctx context.Context, _ string, migrations []modulehost.SchemaMigration) error {
	runner, err := ormmigration.NewRunner(r.host.database, r.host.dialect, ormmigration.Options{})
	if err != nil {
		return err
	}
	return runner.Apply(ctx, migrations)
}

type testTransaction struct{ *sql.Tx }

func (t testTransaction) ExecContext(ctx context.Context, q string, args ...any) (contract.Result, error) {
	return t.Tx.ExecContext(ctx, q, args...)
}
func (t testTransaction) QueryRowContext(ctx context.Context, q string, args ...any) contract.Row {
	return t.Tx.QueryRowContext(ctx, q, args...)
}

func TestModuleUsesBorrowedHostDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	binding, err := NewFactory(Options{}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = binding.Appender().Append(t.Context(), contract.AppendRequest{Event: "record.updated", ObjectKey: "record", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user"}}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM _audit_events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_export_artifacts`).Scan(&count); err != nil {
		t.Fatalf("neutral Audit export artifact table is missing: %v", err)
	}
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM business_audit_export_artifacts`).Scan(&count); err == nil {
		t.Fatal("legacy Runtime-specific Audit export table must not be created")
	}
}

func TestTransactionalAppendClassificationReplayAndSubjectLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	binding, err := NewFactory(Options{}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.AppendRequest{Event: "identity.role.changed", ObjectKey: "role", IdempotencyKey: "one", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user"}}
	if _, err = binding.TransactionalAppender().AppendWithin(t.Context(), testTransaction{tx}, request); err != nil {
		t.Fatal(err)
	}
	if _, err = binding.TransactionalAppender().AppendWithin(t.Context(), testTransaction{tx}, request); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	events, err := binding.Reader().List(t.Context(), "workspace", contract.Query{Class: contract.EventClassGovernance})
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	preview, err := binding.SubjectLifecycle().PreviewSubject(t.Context(), "workspace", "user")
	if err != nil || string(preview) != `{"audit_references":1}` {
		t.Fatalf("preview=%s err=%v", preview, err)
	}
	if _, err = binding.SubjectLifecycle().EraseSubject(t.Context(), "workspace", "user"); err != nil {
		t.Fatal(err)
	}
	events, err = binding.Reader().List(t.Context(), "workspace", contract.Query{})
	if err != nil || len(events) != 1 || events[0].ActorID == "user" {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestBusinessExportLifecycleIsOwnedByModule(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	binding, err := NewFactory(Options{Clock: fixedClock{now}}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	_, err = binding.Appender().Append(t.Context(), contract.AppendRequest{Event: "order.completed", ObjectKey: "order", RecordID: "one", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user", RoleKey: "member"}, Metadata: map[string]any{"result": "completed"}})
	if err != nil {
		t.Fatal(err)
	}
	binding.Exporter().ConfigureExport([]byte("0123456789abcdef0123456789abcdef"), nil)
	principal := contract.ExportPrincipal{WorkspaceID: "workspace", UserID: "user", RoleKey: "member", AuthorizationRevision: "r1"}
	prepared, err := binding.Exporter().PrepareExport(t.Context(), contract.ExportRequest{}, "idem-1", principal)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := binding.Exporter().PrepareExport(t.Context(), contract.ExportRequest{}, "idem-1", principal)
	if err != nil || replayed.ID != prepared.ID {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	content, filename, err := binding.Exporter().DownloadExport(t.Context(), prepared.DownloadToken, principal)
	if err != nil || len(content) == 0 || filename == "" {
		t.Fatalf("filename=%q content=%d err=%v", filename, len(content), err)
	}
	if _, _, err = binding.Exporter().DownloadExport(t.Context(), prepared.DownloadToken, contract.ExportPrincipal{WorkspaceID: "workspace", UserID: "other", RoleKey: "member", AuthorizationRevision: "r1"}); err == nil {
		t.Fatal("requester mismatch accepted")
	}
}
