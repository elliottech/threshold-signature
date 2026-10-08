package coordinator

import (
	"database/sql"
	"errors"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS rooms (
	id         TEXT PRIMARY KEY,
	threshold  INTEGER NOT NULL,
	total      INTEGER NOT NULL,
	allowed    TEXT NOT NULL DEFAULT '',
	group_pk   TEXT,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS participants (
	room        TEXT NOT NULL,
	idx         INTEGER NOT NULL,
	address     TEXT NOT NULL,
	auth_pk     TEXT NOT NULL,
	enc_pk      TEXT NOT NULL,
	eth_sig     TEXT NOT NULL,
	commitments TEXT,
	pok         TEXT,
	created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (room, idx),
	UNIQUE (room, address)
);
-- share holds an ECIES ciphertext only decryptable by to_idx; the server never sees plaintext.
CREATE TABLE IF NOT EXISTS shares (
	room     TEXT NOT NULL,
	from_idx INTEGER NOT NULL,
	to_idx   INTEGER NOT NULL,
	share    TEXT NOT NULL,
	PRIMARY KEY (room, from_idx, to_idx)
);
CREATE TABLE IF NOT EXISTS proposals (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	room        TEXT NOT NULL,
	message     TEXT NOT NULL,
	proposer    INTEGER NOT NULL,
	sig         TEXT NOT NULL DEFAULT '',
	nonce       TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'signing',
	signer_set  TEXT,
	final_sig   TEXT,
	valid       INTEGER,
	created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (room, proposer, nonce)
);
CREATE TABLE IF NOT EXISTS nonce_commits (
	proposal_id INTEGER NOT NULL,
	idx         INTEGER NOT NULL,
	d           TEXT NOT NULL,
	e           TEXT NOT NULL,
	PRIMARY KEY (proposal_id, idx)
);
CREATE TABLE IF NOT EXISTS partials (
	proposal_id INTEGER NOT NULL,
	idx         INTEGER NOT NULL,
	s           TEXT NOT NULL,
	PRIMARY KEY (proposal_id, idx)
);
`

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	success := false
	defer func() {
		if !success {
			_ = db.Close()
		}
	}()
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := rejectLegacySchema(tx); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(schema); err != nil {
		return nil, err
	}
	if err := addAllowedColumn(tx); err != nil {
		return nil, err
	}
	if err := addProposalSigColumn(tx); err != nil {
		return nil, err
	}
	if err := addProposalNonceColumn(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	success = true
	return db, nil
}

// addProposalSigColumn backfills the proposals.sig column on databases created before
// authenticated proposals. Old proposals keep an empty signature (shown as unverified).
func addProposalSigColumn(db *sql.Tx) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proposals') WHERE name='sig'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := db.Exec(`ALTER TABLE proposals ADD COLUMN sig TEXT NOT NULL DEFAULT ''`)
	return err
}

// addProposalNonceColumn backfills the proposals.nonce column and its uniqueness constraint on
// databases created before replay-resistant proposals. Existing rows keep an empty nonce, the
// same as addProposalSigColumn does for proposals predating authenticated signing: their sig was
// computed over the old (nonceless) payload and cannot be re-verified against the new payload
// format, so clients show them as unverified rather than re-deriving a nonce for them. An empty
// nonce is unique per (room, proposer) among legacy rows in practice; the rare pre-existing
// collision fails this migration loudly (a constraint error) rather than silently, so operators
// notice before any replay protection is assumed to be in place for that data.
func addProposalNonceColumn(db *sql.Tx) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('proposals') WHERE name='nonce'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`ALTER TABLE proposals ADD COLUMN nonce TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	_, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS proposals_room_proposer_nonce ON proposals(room, proposer, nonce)`)
	return err
}

// addAllowedColumn backfills the rooms.allowed column on databases created before the
// address-allowlist feature. Old rooms keep an empty allowlist (open room).
func addAllowedColumn(db *sql.Tx) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('rooms') WHERE name='allowed'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := db.Exec(`ALTER TABLE rooms ADD COLUMN allowed TEXT NOT NULL DEFAULT ''`)
	return err
}

// rejectLegacySchema rejects pre-FROST databases without modifying incompatible ceremonies.
func rejectLegacySchema(db *sql.Tx) error {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('participants') WHERE name='auth_pk'`).Scan(&n)
	if err != nil || n > 0 {
		return err
	}
	var hasOld int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='participants'`).Scan(&hasOld); err != nil {
		return err
	}
	if hasOld == 0 {
		return nil
	}
	return errors.New("incompatible pre-FROST database: back it up and use a new database path; automatic archival is disabled")
}
