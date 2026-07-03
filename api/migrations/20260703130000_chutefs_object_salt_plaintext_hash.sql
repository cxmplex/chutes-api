-- migrate:up

-- ChuteFS H1: anchor the per-object encryption salt in the attested tracker (instead of the
-- host-controlled object file) and hold the plaintext integrity hash, so the storage node binds
-- decryption to (volume_id, object_id, salt) and the SDK can verify end-to-end on get().
--   salt             : base64 of the 32-byte HKDF salt for the v3 at-rest container (NULL for
--                      legacy v1/v2 objects whose salt is still carried in the file).
--   plaintext_sha256 : sha256 of the object plaintext (the existing sha256 column stays the
--                      ciphertext hash used for cross-replica integrity).
ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS salt VARCHAR;
ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS plaintext_sha256 VARCHAR;

-- migrate:down

ALTER TABLE storage_objects DROP COLUMN IF EXISTS plaintext_sha256;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS salt;
