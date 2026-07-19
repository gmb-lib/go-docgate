package docgate

import (
	"bytes"

	"github.com/pdfcpu/pdfcpu/pkg/api"
)

// pdfMagic is the PDF header at offset 0. The PDF specification tolerates
// content before the header, but accepting that would admit polyglot files
// (e.g. HTML prepended to a valid PDF tail), so the gate requires it first.
var pdfMagic = []byte("%PDF-")

// isPDF reports whether data begins with the PDF header at offset 0.
func isPDF(data []byte) bool {
	return bytes.HasPrefix(data, pdfMagic)
}

// pdfSignatures reports whether a PDF structurally carries a signature, and
// surfaces the parser's error instead of swallowing it (a parse failure is
// otherwise indistinguishable from a clean "unsigned" verdict).
//
// Two independent detectors, either positive counts:
//   - the PDF library's document-info signature flag (parses the xref);
//   - a byte scan for a signature dictionary — a /Type /Sig entry together
//     with a /ByteRange — which survives files the library cannot fully parse.
//
// No cryptographic verification happens here; presence only.
func pdfSignatures(data []byte) (has bool, parseErr error) {
	info, err := api.PDFInfo(bytes.NewReader(data), "upload.pdf", nil, false, nil)
	if err == nil && info != nil && info.Signatures {
		return true, nil
	}
	if scanForSigDict(data) {
		return true, nil
	}
	return false, err
}

// scanForSigDict looks for the byte shape of a PDF signature dictionary.
func scanForSigDict(data []byte) bool {
	hasSigType := bytes.Contains(data, []byte("/Type /Sig")) || bytes.Contains(data, []byte("/Type/Sig"))
	return hasSigType && bytes.Contains(data, []byte("/ByteRange"))
}
