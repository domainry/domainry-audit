package architecture_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditModuleUsesLayeredSourceLayout(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	for _, required := range []string{
		"internal/application/audit",
		"internal/application/export",
		"internal/domain/audit/service",
		"internal/domain/export/policy",
		"internal/domain/export/repository",
		"internal/infrastructure/persistence/database/audit",
		"internal/infrastructure/persistence/database/export",
		"internal/infrastructure/persistence/database/schema",
		"internal/module",
		"module",
	} {
		if info, err := os.Stat(filepath.Join(root, required)); err != nil || !info.IsDir() {
			t.Errorf("required Audit boundary %q is missing", required)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "internal/audit")); !os.IsNotExist(err) {
		t.Error("flat internal/audit package is forbidden")
	}
	entries, err := os.ReadDir(filepath.Join(root, "module"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || entry.Name() == "module.go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		t.Errorf("public module package must remain a thin facade; unexpected production file %q", entry.Name())
	}
}

func TestAuditSchemaUsesORMMigrationHost(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	required := map[string]string{
		"internal/infrastructure/persistence/database/schema/migrations.go": "ormschema.NewTable",
		"internal/module/factory.go":                                        "ApplyOwnedMigrations",
	}
	for name, marker := range required {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), marker) {
			t.Errorf("%s must retain ORM contract %q", name, marker)
		}
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return err
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, forbidden := range []string{"SchemaManager", "OpenWithDatabase", "ParseRenderer"} {
			if strings.Contains(string(content), forbidden) {
				t.Errorf("production Audit source %s contains forbidden ad-hoc database seam %q", path, forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuditDatabaseChoiceIsConfinedToEngineFactoryAndProfiles(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return err
		}
		normalized := filepath.ToSlash(path)
		if filepath.Base(path) == "engine.go" || strings.Contains(normalized, "/schema/sqlite/") || strings.Contains(normalized, "/schema/mysql/") || strings.Contains(normalized, "/schema/postgres/") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := strings.ToLower(string(content))
		for _, database := range []string{"sqlite", "sqlite3", "mysql", "postgres", "postgresql", "pgx"} {
			if strings.Contains(text, database) {
				t.Errorf("Audit database %q escaped engine/profile boundary: %s", database, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
