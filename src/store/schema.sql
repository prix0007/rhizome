CREATE TABLE IF NOT EXISTS devices (
    network_id TEXT NOT NULL,
    id         TEXT NOT NULL,
    mac        TEXT NOT NULL,
    last_ip    TEXT NOT NULL,
    hostname   TEXT,
    vendor     TEXT,
    kind       TEXT NOT NULL,
    randomized INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (network_id, id)
);

CREATE TABLE IF NOT EXISTS meta (
    network_id TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (network_id, key)
);
