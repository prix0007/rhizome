-- v2: learned device information and user-set metadata (all optional).
ALTER TABLE devices ADD COLUMN custom_name TEXT;
ALTER TABLE devices ADD COLUMN notes TEXT;
ALTER TABLE devices ADD COLUMN friendly_name TEXT;
ALTER TABLE devices ADD COLUMN manufacturer TEXT;
ALTER TABLE devices ADD COLUMN model TEXT;
ALTER TABLE devices ADD COLUMN dns_name TEXT;
ALTER TABLE devices ADD COLUMN netbios_name TEXT;
ALTER TABLE devices ADD COLUMN os_hint TEXT;
