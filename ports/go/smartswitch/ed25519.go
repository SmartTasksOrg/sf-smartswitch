package smartswitch

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"regexp"
)

var (
	groupOrderL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	hex64          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex128         = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// IsKeyHex reports whether v is a string of 64 lower-case hex characters.
func IsKeyHex(v any) bool {
	s, ok := v.(string)
	return ok && hex64.MatchString(s)
}

// Verify is the engine's Ed25519 check (spec/SEMANTICS.md, "Signatures"): publicHex 64 and sig 128
// lower-case hex characters, S (signature bytes 32-63, little-endian) below the group order L, then
// the library verifies (RFC 8032). Any other input, or any library failure, is false.
func Verify(publicHex any, message []byte, sigHex any) (ok bool) {
	pk, isStr := publicHex.(string)
	sg, isStr2 := sigHex.(string)
	if !isStr || !isStr2 || !hex64.MatchString(pk) || !hex128.MatchString(sg) {
		return false
	}
	sig, _ := hex.DecodeString(sg)
	key, _ := hex.DecodeString(pk)
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = sig[63-i]
	}
	if new(big.Int).SetBytes(le).Cmp(groupOrderL) >= 0 {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return ed25519.Verify(ed25519.PublicKey(key), message, sig)
}
