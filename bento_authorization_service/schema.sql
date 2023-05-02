CREATE TABLE IF NOT EXISTS subjects (
    id  SERIAL PRIMARY KEY,
    def JSONB  NOT NULL,  -- Subject JSON definition

    CONSTRAINT subject_def_unique UNIQUE (def)
);

CREATE TABLE IF NOT EXISTS resources (
    id  SERIAL PRIMARY KEY,
    def JSONB  NOT NULL,  -- Resource JSON definition

    CONSTRAINT resource_def_unique UNIQUE (def)
);

CREATE TABLE IF NOT EXISTS grants (
    id SERIAL   PRIMARY KEY,
    subject     INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    resource    INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    permission  VARCHAR(127),
    extra JSONB NOT NULL DEFAULT '{}'::jsonb,

    created     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    expiry      TIMESTAMP(0) WITH TIME ZONE,

    CONSTRAINT grant_unique UNIQUE (subject, resource, permission, expiry)  -- TODO: what to do?
);

CREATE TABLE IF NOT EXISTS groups (
    id         SERIAL PRIMARY KEY,
    name       TEXT   NOT NULL CHECK (name <> ''),
    membership JSONB  NOT NULL,

    created     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    expiry      TIMESTAMP(0) WITH TIME ZONE,

    CONSTRAINT group_name_unique UNIQUE (name)
);
