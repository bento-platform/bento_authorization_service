CREATE TABLE IF NOT EXISTS grants (
    id SERIAL PRIMARY KEY,
    subject JSONB NOT NULL,
    resource JSONB NOT NULL,
    permission VARCHAR(127),
    extra JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    membership JSONB NOT NULL
);
