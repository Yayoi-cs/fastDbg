package common

import "bytes"

// CyclicGenerate produces a De Bruijn B(26, 4) sequence of `length` bytes
// using the lowercase alphabet a..z. Every 4-character substring of the
// (untruncated) sequence is unique, which is what makes it usable as a
// stack-overflow offset finder. Maximum length is 26^4 = 456,976.
//
// The algorithm is the standard recursive Lyndon-word enumeration; it
// matches pwntools' default `cyclic()` exactly so offsets line up.
func CyclicGenerate(length int) []byte {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	const sublen = 4
	if length <= 0 {
		return nil
	}
	k := len(alphabet)
	a := make([]int, k*sublen+1)
	seq := make([]byte, 0, length)

	var db func(t, p int)
	db = func(t, p int) {
		if len(seq) >= length {
			return
		}
		if t > sublen {
			if sublen%p == 0 {
				for i := 1; i <= p; i++ {
					if len(seq) >= length {
						return
					}
					seq = append(seq, alphabet[a[i]])
				}
			}
			return
		}
		a[t] = a[t-p]
		db(t+1, p)
		for j := a[t-p] + 1; j < k; j++ {
			a[t] = j
			db(t+1, t)
		}
	}
	db(1, 1)
	return seq
}

// CyclicFind returns the byte offset of `pattern` within the full B(26,4)
// sequence, or -1 if `pattern` doesn't appear (e.g. it contains a non-a..z
// byte or just isn't a valid substring of the De Bruijn sequence).
func CyclicFind(pattern []byte) int {
	if len(pattern) == 0 {
		return -1
	}
	seq := CyclicGenerate(26 * 26 * 26 * 26)
	return bytes.Index(seq, pattern)
}
