-- A mount lease must survive client-certificate renewal without allowing a
-- displaced holder to refresh its way back in.  The opaque lease token is
-- returned only to the successful acquirer; renewals keep it, while every
-- takeover replaces it.  Store only its SHA-256 digest.
--
-- +goose Up
ALTER TABLE disk_allocations
    ADD COLUMN IF NOT EXISTS mount_lease_token_hash text;

-- +goose Down
ALTER TABLE disk_allocations
    DROP COLUMN IF EXISTS mount_lease_token_hash;
