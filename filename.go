package docgate

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxFilenameBytes bounds the accepted filename length (UTF-8 bytes) — beyond
// common filesystem limits a name is attacker noise, not a document.
const maxFilenameBytes = 255

// checkFilename applies format-independent filename hygiene, in every mode:
// uploads' names travel into storage rows, response bodies, and log lines, so
// a hostile name must die at the gate. Rejections wrap ErrMalformed.
func checkFilename(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty filename", ErrMalformed)
	case len(name) > maxFilenameBytes:
		return fmt.Errorf("%w: filename exceeds %d bytes", ErrMalformed, maxFilenameBytes)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: filename is not valid UTF-8", ErrMalformed)
	case strings.ContainsAny(name, `/\`):
		return fmt.Errorf("%w: filename contains a path separator", ErrMalformed)
	case name == "." || name == "..":
		return fmt.Errorf("%w: filename is a path segment", ErrMalformed)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("%w: filename contains a control character", ErrMalformed)
		}
		// Bidirectional-override characters spoof the visible extension
		// (e.g. a right-to-left override making "…fdp.exe" render as "…exe.pdf").
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return fmt.Errorf("%w: filename contains a bidirectional-override character", ErrMalformed)
		}
	}
	return nil
}

// ext returns the lower-cased filename extension including the dot ("" when
// none). The name has already passed checkFilename, so it holds no separators.
func ext(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return strings.ToLower(name[i:])
}
