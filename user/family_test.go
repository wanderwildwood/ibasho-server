package user

import (
	"path/filepath"
	"testing"
)

// A database left at schema version 5 (before family sharing) gains the new columns and table
// when the server next starts, and keeps its accounts.
func TestMigrationFromVersion5(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fmd.sqlite")
	db := initSQLite(path)
	db.DB.Create(&FMDUser{Username: "old"})

	for _, q := range []string{
		"DROP TABLE family_locations",
		"ALTER TABLE fmd_users DROP COLUMN identity_public",
		"ALTER TABLE fmd_users DROP COLUMN identity_enc_private",
		"ALTER TABLE fmd_users DROP COLUMN sharing_paused",
		"UPDATE db_settings SET value = '5' WHERE setting = 'fmd_db_version'",
	} {
		if err := db.DB.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = db.Close()

	db = initSQLite(path)
	defer db.Close()
	var u FMDUser
	if err := db.DB.Where("username = ?", "old").First(&u).Error; err != nil {
		t.Fatal(err)
	}
	if u.IdentityPublic != "" || u.SharingPaused {
		t.Errorf("new columns should start empty: %+v", u)
	}
	if err := db.DB.Create(&FamilyLocation{OwnerId: u.Id, ViewerId: u.Id, UnixMillis: 1, Ciphertext: "x"}).Error; err != nil {
		t.Errorf("family_locations missing after migration: %v", err)
	}
}
