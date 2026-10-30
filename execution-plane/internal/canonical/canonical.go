// Package canonical reproduces, byte for byte, the control plane's canonical JSON
// (Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)) for the
// restricted value set used in signed material: string, integer, bool, null, array, object.
package canonical

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// Marshal encodes v canonically. Numbers must be json.Number holding integers, or Go ints.
func Marshal(v any) (string, error) {
	var b strings.Builder
	if err := enc(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func enc(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		encString(b, x)
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return fmt.Errorf("non-integer number %q not allowed in canonical material", x)
		}
		b.WriteString(string(x))
	case int:
		fmt.Fprintf(b, "%d", x)
	case int64:
		fmt.Fprintf(b, "%d", x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := enc(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Python sorts by code point; identical for the ASCII keys we use.
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encString(b, k)
			b.WriteByte(':')
			if err := enc(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T in canonical material", v)
	}
	return nil
}

func encString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || r > 0x7e {
				if r > 0xffff {
					r1, r2 := utf16.EncodeRune(r)
					fmt.Fprintf(b, `\u%04x\u%04x`, r1, r2)
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Normalize round-trips a value through JSON with UseNumber so structs/maps become canonical-ready.
func Normalize(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out any
	err = d.Decode(&out)
	return out, err
}

func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func HMACHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func HMACVerify(key []byte, msg, sigHex string) bool {
	want, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hmac.Equal(m.Sum(nil), want)
}

// DerivedKey mirrors Settings.derived_key in the control plane: HMAC(master, purpose).
func DerivedKey(master, purpose string) []byte {
	m := hmac.New(sha256.New, []byte(master))
	m.Write([]byte(purpose))
	return m.Sum(nil)
}
