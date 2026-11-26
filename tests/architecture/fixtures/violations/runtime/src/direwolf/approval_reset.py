"""FIXTURE: the runtime giving a spent approval its uses back (TX068)."""

RESET = "UPDATE approval SET uses = 0, state = 'OPEN'"
FORGE = "INSERT INTO approval_use (approval_id, seq) VALUES (?1, 1)"
