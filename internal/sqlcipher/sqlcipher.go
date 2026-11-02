// Package sqlcipher is a deliberately small binding to the system SQLCipher.
// Keys use sqlite3_key, never SQL text or a connection string. DB is not safe
// for concurrent use; its owner must serialize access and close all statements.
package sqlcipher

/*
#cgo pkg-config: sqlcipher
#cgo CFLAGS: -DSQLITE_HAS_CODEC
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
static int bind_text(sqlite3_stmt *s, int n, const char *p, int len) {
    return sqlite3_bind_text(s, n, p, len, SQLITE_TRANSIENT);
}
static void wipe_free(void *p, size_t n) {
    if (p) { volatile unsigned char *v = p; while (n--) *v++ = 0; free(p); }
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

type DB struct{ ptr *C.sqlite3 }

func Open(path string, password []byte) (*DB, error) {
	if len(password) == 0 {
		return nil, errors.New("master password must not be empty")
	}
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	db := &DB{}
	if C.sqlite3_open_v2(name, &db.ptr, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_NOFOLLOW, nil) != C.SQLITE_OK {
		db.Close()
		return nil, errors.New("cannot open encrypted database")
	}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	key := C.CBytes(password)
	defer C.wipe_free(key, C.size_t(len(password)))
	if C.sqlite3_key(db.ptr, key, C.int(len(password))) != C.SQLITE_OK {
		return nil, errors.New("cannot set database key")
	}
	version, err := db.Query("PRAGMA cipher_version")
	if err != nil || len(version) != 1 || len(version[0]) != 1 || !strings.HasPrefix(version[0][0], "4.") {
		return nil, errors.New("SQLCipher 4 encryption is required")
	}
	if _, err = db.Query("SELECT count(*) FROM sqlite_master"); err != nil {
		return nil, errors.New("incorrect master password or damaged vault")
	}
	for _, pragma := range []string{"PRAGMA cipher_memory_security = ON", "PRAGMA temp_store = MEMORY", "PRAGMA journal_mode = DELETE", "PRAGMA synchronous = FULL", "PRAGMA secure_delete = ON", "PRAGMA locking_mode = EXCLUSIVE"} {
		if err = db.Exec(pragma); err != nil {
			return nil, err
		}
	}
	journal, err := db.Query("PRAGMA journal_mode")
	if err != nil || len(journal) != 1 || journal[0][0] != "delete" {
		return nil, errors.New("could not enable encrypted rollback journal mode")
	}
	ok = true
	return db, nil
}

func (db *DB) Close() error {
	if db == nil || db.ptr == nil {
		return nil
	}
	if C.sqlite3_close(db.ptr) != C.SQLITE_OK {
		return errors.New("cannot close database")
	}
	db.ptr = nil
	return nil
}

func (db *DB) prepare(query string, args []string) (*C.sqlite3_stmt, error) {
	if db.ptr == nil {
		return nil, errors.New("database is closed")
	}
	q := C.CString(query)
	defer C.free(unsafe.Pointer(q))
	var stmt *C.sqlite3_stmt
	if C.sqlite3_prepare_v2(db.ptr, q, -1, &stmt, nil) != C.SQLITE_OK {
		return nil, errors.New("cannot prepare database operation")
	}
	for i, arg := range args {
		p := C.CString(arg)
		rc := C.bind_text(stmt, C.int(i+1), p, C.int(len(arg)))
		C.wipe_free(unsafe.Pointer(p), C.size_t(len(arg)+1))
		if rc != C.SQLITE_OK {
			C.sqlite3_finalize(stmt)
			return nil, errors.New("cannot bind database value")
		}
	}
	return stmt, nil
}

func (db *DB) Exec(query string, args ...string) error {
	stmt, err := db.prepare(query, args)
	if err != nil {
		return err
	}
	defer C.sqlite3_finalize(stmt)
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			return nil
		}
		if rc != C.SQLITE_ROW {
			return fmt.Errorf("database operation failed (code %d)", int(rc))
		}
	}
}

func (db *DB) Query(query string, args ...string) ([][]string, error) {
	stmt, err := db.prepare(query, args)
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(stmt)
	rows := [][]string{}
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			return rows, nil
		}
		if rc != C.SQLITE_ROW {
			return nil, fmt.Errorf("database query failed (code %d)", int(rc))
		}
		row := make([]string, int(C.sqlite3_column_count(stmt)))
		for i := range row {
			p := C.sqlite3_column_text(stmt, C.int(i))
			n := C.sqlite3_column_bytes(stmt, C.int(i))
			row[i] = C.GoStringN((*C.char)(unsafe.Pointer(p)), n)
		}
		rows = append(rows, row)
	}
}

func (db *DB) Rekey(password []byte) error {
	if len(password) < 12 || len(password) > 4096 {
		return errors.New("new master password must contain 12–4096 bytes")
	}
	p := C.CBytes(password)
	defer C.wipe_free(p, C.size_t(len(password)))
	if C.sqlite3_rekey(db.ptr, p, C.int(len(password))) != C.SQLITE_OK {
		return errors.New("master password change failed")
	}
	return nil
}
