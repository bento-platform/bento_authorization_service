CREATE TABLE IF NOT EXISTS grants (
    id SERIAL PRIMARY KEY,
    subject JSONB NOT NULL,
    resource JSONB NOT NULL,
    permission VARCHAR(127),
    extra JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS groups (
    id         SERIAL PRIMARY KEY,
    name       TEXT   NOT NULL CHECK (name <> ''),
    membership JSONB  NOT NULL,

    CONSTRAINT group_name_unique UNIQUE (name)
);
