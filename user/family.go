package user

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"time"

	"gorm.io/gorm"
)

// Family sharing.
//
// Every account can carry an identity key pair (P-256). The public half is kept in the clear so
// that others can seal to it; the private half is kept only in a form the account's own
// password can open (the clients encrypt it under a key derived from the master key), so the
// server cannot read it. Each phone seals its last known place separately for every other
// person, and the server keeps one such sealed copy per (owner, viewer), replacing it as newer
// ones come in. Nothing here ever sees a coordinate.

var (
	ErrIdentityInvalid = errors.New("identity key is invalid")
	ErrIdentityTaken   = errors.New("identity already set")
	ErrPaused          = errors.New("sharing is paused")
	ErrNoIdentity      = errors.New("account has no identity key")
	ErrBadViewer       = errors.New("unknown viewer")
)

// Largest sealed copy accepted. A location sealed for one viewer is a few hundred bytes.
const MaxSealedBytes = 4096

// Longest a sealed copy's time may run ahead of the server's clock.
const maxClockAhead = 10 * time.Minute

// FamilyLocation is one sealed copy: the last known place of Owner, sealed to Viewer.
type FamilyLocation struct {
	Id         uint64 `gorm:"primaryKey"`
	OwnerId    uint64
	ViewerId   uint64 `gorm:"index"`
	UnixMillis uint64
	Ciphertext string
}

type Person struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey64"`
	Paused    bool   `json:"paused"`
}

type SealedPut struct {
	Viewer     string `json:"viewer"`
	UnixMillis uint64 `json:"unixMillis"`
	Ciphertext string `json:"ciphertext64"`
}

type SealedGet struct {
	Owner      string `json:"owner"`
	UnixMillis uint64 `json:"unixMillis"`
	Ciphertext string `json:"ciphertext64"`
}

// ValidIdentityPublic reports whether s is the base64 of a real uncompressed P-256 point.
func ValidIdentityPublic(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 65 {
		return false
	}
	_, err = ecdh.P256().NewPublicKey(raw)
	return err == nil
}

// SetIdentity stores the account's identity once. If one is already stored it is left alone and
// ErrIdentityTaken comes back, so two devices racing to make one end up agreeing on the first.
func (u *UserRepository) SetIdentity(user *FMDUser, publicKey, encPrivate string) error {
	if !ValidIdentityPublic(publicKey) {
		return ErrIdentityInvalid
	}
	raw, err := base64.StdEncoding.DecodeString(encPrivate)
	if err != nil || len(raw) < 16 || len(raw) > 1024 {
		return ErrIdentityInvalid
	}
	res := u.UB.DB.Model(&FMDUser{}).
		Where("id = ? AND identity_public = ''", user.Id).
		Updates(map[string]any{"identity_public": publicKey, "identity_enc_private": encPrivate})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrIdentityTaken
	}
	user.IdentityPublic = publicKey
	user.IdentityEncPrivate = encPrivate
	return nil
}

// Identity returns the stored identity of the account, fresh from the database.
func (u *UserRepository) Identity(user *FMDUser) (publicKey, encPrivate string, err error) {
	var row FMDUser
	if err = u.UB.DB.Select("identity_public", "identity_enc_private").First(&row, user.Id).Error; err != nil {
		return "", "", err
	}
	return row.IdentityPublic, row.IdentityEncPrivate, nil
}

// People lists everyone else on the server, whether or not they have a key yet.
func (u *UserRepository) People(user *FMDUser) ([]Person, error) {
	var rows []FMDUser
	err := u.UB.DB.Select("username", "identity_public", "sharing_paused").
		Where("id <> ?", user.Id).Order("username ASC").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]Person, 0, len(rows))
	for _, r := range rows {
		out = append(out, Person{r.Username, r.IdentityPublic, r.SharingPaused})
	}
	return out, nil
}

func (u *UserRepository) IsPaused(user *FMDUser) (bool, error) {
	var row FMDUser
	if err := u.UB.DB.Select("sharing_paused").First(&row, user.Id).Error; err != nil {
		return false, err
	}
	return row.SharingPaused, nil
}

// SetPaused turns the account's sharing off or on. Pausing also erases every sealed copy of its
// place, so that nobody is left looking at a last known position the person has withdrawn.
func (u *UserRepository) SetPaused(user *FMDUser, paused bool) error {
	return u.UB.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&FMDUser{}).Where("id = ?", user.Id).
			Update("sharing_paused", paused).Error; err != nil {
			return err
		}
		if paused {
			if err := tx.Where("owner_id = ?", user.Id).Delete(&FamilyLocation{}).Error; err != nil {
				return err
			}
		}
		user.SharingPaused = paused
		return nil
	})
}

// PutSealed stores the sealed copies, one per viewer, keeping only the newest. Copies for the
// owner themself, for unknown people, or older than what is already held are skipped. It returns
// how many were stored.
func (u *UserRepository) PutSealed(owner *FMDUser, items []SealedPut) (int, error) {
	stored := 0
	limit := uint64(time.Now().Add(maxClockAhead).UnixMilli())

	err := u.UB.DB.Transaction(func(tx *gorm.DB) error {
		var row FMDUser
		if err := tx.Select("sharing_paused", "identity_public").First(&row, owner.Id).Error; err != nil {
			return err
		}
		if row.SharingPaused {
			return ErrPaused
		}
		if row.IdentityPublic == "" {
			return ErrNoIdentity
		}

		for _, it := range items {
			raw, err := base64.StdEncoding.DecodeString(it.Ciphertext)
			if err != nil || len(raw) == 0 || len(raw) > MaxSealedBytes {
				continue
			}
			if it.UnixMillis == 0 || it.UnixMillis > limit {
				continue
			}
			var viewer FMDUser
			res := tx.Select("id").Where("username = ? AND id <> ?", it.Viewer, owner.Id).Limit(1).Find(&viewer)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				continue
			}
			res = tx.Exec(`INSERT INTO family_locations (owner_id, viewer_id, unix_millis, ciphertext)
				VALUES (?, ?, ?, ?)
				ON CONFLICT (owner_id, viewer_id) DO UPDATE
				SET unix_millis = excluded.unix_millis, ciphertext = excluded.ciphertext
				WHERE excluded.unix_millis > family_locations.unix_millis`,
				owner.Id, viewer.Id, it.UnixMillis, it.Ciphertext)
			if res.Error != nil {
				return res.Error
			}
			stored += int(res.RowsAffected)
		}
		return nil
	})
	return stored, err
}

// SealedFor returns the copies sealed to this viewer, one per person.
func (u *UserRepository) SealedFor(viewer *FMDUser) ([]SealedGet, error) {
	var out []SealedGet
	err := u.UB.DB.Raw(`SELECT o.username AS owner, f.unix_millis AS unix_millis, f.ciphertext AS ciphertext
		FROM family_locations f JOIN fmd_users o ON o.id = f.owner_id
		WHERE f.viewer_id = ? AND o.sharing_paused = 0
		ORDER BY o.username ASC`, viewer.Id).Scan(&out).Error
	return out, err
}
