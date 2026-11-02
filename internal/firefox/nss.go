package firefox

/*
#cgo pkg-config: nss
#include <nss.h>
#include <pk11pub.h>
#include <pk11sdr.h>
#include <secmod.h>
#include <stdlib.h>
static void wipe_password(char *p, size_t n) {
    volatile char *v = p; while (n--) *v++ = 0; free(p);
}
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"unsafe"

	"pq/internal/secure"
)

var ErrPrimaryPassword = errors.New("Firefox Primary Password is required or incorrect")
var nssMu sync.Mutex

func openNSS(profile string, password []byte) (func(string) (string, error), func(), error) {
	if bytes.IndexByte(password, 0) >= 0 || len(password) > 4096 {
		return nil, nil, errors.New("invalid Firefox Primary Password")
	}
	nssMu.Lock()
	path := C.CString("sql:" + profile)
	defer C.free(unsafe.Pointer(path))
	empty := C.CString("")
	defer C.free(unsafe.Pointer(empty))
	// Do not load third-party PKCS#11 modules from the imported profile.
	ctx := C.NSS_InitContext(path, empty, empty, empty, nil, C.NSS_INIT_READONLY|C.NSS_INIT_NOROOTINIT|C.NSS_INIT_NOMODDB)
	if ctx == nil {
		nssMu.Unlock()
		return nil, nil, errors.New("cannot open Firefox NSS key database")
	}
	slot := C.PK11_GetInternalKeySlot()
	closeNSS := func() {
		if slot != nil {
			C.PK11_Logout(slot)
			C.PK11_FreeSlot(slot)
		}
		C.NSS_ShutdownContext(ctx)
		nssMu.Unlock()
	}
	if slot == nil {
		closeNSS()
		return nil, nil, errors.New("cannot access Firefox encryption key")
	}
	if C.PK11_NeedLogin(slot) != 0 {
		pw := C.CString(string(password))
		rc := C.PK11_CheckUserPassword(slot, pw)
		C.wipe_password(pw, C.size_t(len(password)+1))
		if rc != C.SECSuccess {
			closeNSS()
			return nil, nil, ErrPrimaryPassword
		}
	}
	decrypt := func(encoded string) (string, error) {
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(data) == 0 || len(data) > modelMaxEncrypted {
			return "", errors.New("invalid Firefox encrypted credential")
		}
		defer secure.Wipe(data)
		p := C.CBytes(data)
		defer C.free(p)
		input := C.SECItem{_type: C.siBuffer, data: (*C.uchar)(p), len: C.uint(len(data))}
		var output C.SECItem
		if C.PK11SDR_Decrypt(&input, &output, nil) != C.SECSuccess {
			return "", errors.New("cannot decrypt Firefox credential")
		}
		defer C.SECITEM_ZfreeItem(&output, 0)
		return C.GoStringN((*C.char)(unsafe.Pointer(output.data)), C.int(output.len)), nil
	}
	return decrypt, closeNSS, nil
}

const modelMaxEncrypted = 2 << 20
