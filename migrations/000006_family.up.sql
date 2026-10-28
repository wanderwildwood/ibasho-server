-- Family sharing: each account has an identity key pair (the public half in the clear, the
-- private half encrypted on the client under a key only the account's password can derive),
-- a pause flag, and one sealed copy of its last known place per allowed viewer.

-- fmd_users
ALTER TABLE fmd_users ADD COLUMN identity_public TEXT NOT NULL DEFAULT "";
ALTER TABLE fmd_users ADD COLUMN identity_enc_private TEXT NOT NULL DEFAULT "";
ALTER TABLE fmd_users ADD COLUMN sharing_paused INTEGER NOT NULL DEFAULT 0;

-- family_locations: the server cannot read `ciphertext`; it is sealed to the viewer's key.
CREATE TABLE IF NOT EXISTS `family_locations` (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  `owner_id` integer NOT NULL,
  `viewer_id` integer NOT NULL,
  `unix_millis` integer NOT NULL,
  `ciphertext` text NOT NULL,
  CONSTRAINT `fk_family_owner` FOREIGN KEY (`owner_id`) REFERENCES `fmd_users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_family_viewer` FOREIGN KEY (`viewer_id`) REFERENCES `fmd_users` (`id`) ON DELETE CASCADE
);

-- One row per (owner, viewer): only the last known position is kept.
CREATE UNIQUE INDEX IF NOT EXISTS `idx_family_owner_viewer` ON `family_locations` (`owner_id`, `viewer_id`);
CREATE INDEX IF NOT EXISTS `idx_family_viewer` ON `family_locations` (`viewer_id`);
