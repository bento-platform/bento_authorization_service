CREATE TABLE IF NOT EXISTS grants (
    id SERIAL PRIMARY KEY,
    subject JSON NOT NULL,
    resource JSON NOT NULL,
    permission VARCHAR(127),
    extra JSON NOT NULL DEFAULT '{}'::json
);

CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    membership JSON NOT NULL
);
