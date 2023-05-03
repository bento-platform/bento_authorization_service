CREATE TABLE IF NOT EXISTS subjects (
    "id"  SERIAL PRIMARY KEY,
    "def" JSONB  NOT NULL,  -- Subject JSON definition

    CONSTRAINT subject_def_unique UNIQUE ("def")
);

CREATE TABLE IF NOT EXISTS resources (
    "id"  SERIAL PRIMARY KEY,
    "def" JSONB  NOT NULL,  -- Resource JSON definition

    CONSTRAINT resource_def_unique UNIQUE ("def")
);

CREATE TABLE IF NOT EXISTS grants (
    "id"          SERIAL  PRIMARY KEY,
    "subject"     INTEGER NOT NULL REFERENCES subjects("id") ON DELETE CASCADE,
    "resource"    INTEGER NOT NULL REFERENCES resources("id") ON DELETE CASCADE,
    "notes"       TEXT NOT NULL DEFAULT '',  -- For human-readable notes on what the grant is for/extra information.

    "created"     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    "expiry"      TIMESTAMP(0) WITH TIME ZONE
);

-- Each grant can have many permissions associated with it:
CREATE TABLE IF NOT EXISTS grant_permissions (
    "grant"      INTEGER NOT NULL REFERENCES grants("id") ON DELETE CASCADE,
    "permission" VARCHAR(127) NOT NULL,

    PRIMARY KEY ("grant", "permission")
);

CREATE TABLE IF NOT EXISTS groups (
    "id"         SERIAL PRIMARY KEY,
    "name"       TEXT   NOT NULL CHECK ("name" <> ''),
    "membership" JSONB  NOT NULL,
    "notes"      TEXT NOT NULL DEFAULT '',  -- For human-readable notes on what the group is for/extra information.

    "created"    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    "expiry"     TIMESTAMP(0) WITH TIME ZONE,

    CONSTRAINT group_name_unique UNIQUE ("name")
);
