-- Your SQL goes here
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sess_id INTEGER NOT NULL
);

INSERT INTO sessions (sess_id) VALUES (10);
