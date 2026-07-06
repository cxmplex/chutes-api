-- migrate:up

-- Fleet L0 updates: record which L0 host-image version each bare-metal box is running (reported by
-- the node-agent from /etc/chutes/l0-version at registration + heartbeat). Lets the validator tell
-- which L0 a box booted and drive re-netboot updates (publish a new squashfs + reboot the box, which
-- re-fetches it since the L0 is a RAM-root live appliance). Informational -- the host is not attested.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS l0_version VARCHAR;

-- migrate:down

ALTER TABLE hosts DROP COLUMN IF EXISTS l0_version;
