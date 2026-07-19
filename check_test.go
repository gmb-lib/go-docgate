package docgate

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	asice "github.com/gmb-lib/go-asice"
)

// --- fixtures ------------------------------------------------------------------

func sha256b64(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// minXAdES builds a minimal detached XAdES signature file over one document,
// shaped like real signing output closely enough for structural parsing.
func minXAdES(docName string, docData []byte) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S0"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>`+
		`<ds:Reference Id="r0" URI="%s">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`+
		`<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp-S0">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`+
		`</ds:SignedInfo>`+
		`<ds:SignatureValue>Zm9v</ds:SignatureValue>`+
		`</ds:Signature>`,
		docName, sha256b64(docData), sha256b64([]byte("props"))))
}

// signedContainer assembles a genuine signed ASiC-E via the container library.
func signedContainer(t *testing.T) []byte {
	t.Helper()
	doc := asice.File{Name: "doc1.txt", Data: []byte("hello world")}
	sig := asice.File{Name: "xades.xml", Data: minXAdES(doc.Name, doc.Data)}
	container, err := asice.BuildContainer([]asice.File{doc}, []asice.File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	return container
}

type zipEntry struct {
	name    string
	content []byte
	method  uint16
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method})
		if err != nil {
			t.Fatalf("create %q: %v", e.name, err)
		}
		if _, err := w.Write(e.content); err != nil {
			t.Fatalf("write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// unsignedContainer is strict ASiC-E in shape but holds no signature.
func unsignedContainer(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, []zipEntry{
		{name: "mimetype", content: []byte(asice.MimeType), method: zip.Store},
		{name: "doc1.txt", content: []byte("hello"), method: zip.Deflate},
	})
}

func plainZip(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, []zipEntry{
		{name: "readme.txt", content: []byte("just a zip"), method: zip.Deflate},
	})
}

// minimalPDF assembles a tiny but structurally complete unsigned PDF, with a
// correct cross-reference table (offsets computed while writing).
func minimalPDF(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	offsets := make([]int, 0, 4)
	write := func(s string) { b.WriteString(s) }
	obj := func(s string) {
		offsets = append(offsets, b.Len())
		write(s)
	}
	write("%PDF-1.4\n")
	obj("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	obj("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	obj("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n")
	xrefAt := b.Len()
	write("xref\n0 4\n0000000000 65535 f \n")
	for _, off := range offsets {
		write(fmt.Sprintf("%010d 00000 n \n", off))
	}
	write(fmt.Sprintf("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefAt))
	return b.Bytes()
}

// signedPDF extends the minimal PDF with an incremental update carrying an
// INVISIBLE signature: a /Type /Sig dictionary (detached CAdES subfilter, a
// /ByteRange, hex /Contents), an AcroForm signature field with a zero-rect
// widget, and a second cross-reference section chaining to the first — the
// shape an external desktop signing tool produces. The signature is
// structural, not cryptographically valid: the gate detects presence only.
func signedPDF(t *testing.T) []byte {
	t.Helper()
	base := minimalPDF(t)
	prevXref := bytes.LastIndex(base, []byte("xref"))
	if prevXref < 0 {
		t.Fatal("no xref in base pdf")
	}

	var b bytes.Buffer
	b.Write(base)
	offsets := map[int]int{}
	obj := func(num int, body string) {
		offsets[num] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", num, body)
	}
	// The signature value dictionary (contents are placeholder hex).
	obj(4, "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached"+
		" /ByteRange [0 1024 2048 512] /Contents <3082000a0500> >>")
	// The invisible signature field/widget holding it.
	obj(5, "<< /FT /Sig /T (Signature1) /V 4 0 R /Type /Annot /Subtype /Widget"+
		" /Rect [0 0 0 0] /F 132 /P 3 0 R >>")
	// The catalog, re-declared to hang the AcroForm off it.
	obj(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>")

	xrefAt := b.Len()
	fmt.Fprintf(&b, "xref\n0 1\n0000000000 65535 f \n1 1\n%010d 00000 n \n4 2\n%010d 00000 n \n%010d 00000 n \n",
		offsets[1], offsets[4], offsets[5])
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", prevXref, xrefAt)
	return b.Bytes()
}

// --- verify mode -----------------------------------------------------------------

func TestVerify_SignedPDF(t *testing.T) {
	res, err := Check(ModeVerify, "signed.pdf", signedPDF(t))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Kind != KindPDF || !res.HasSignatures {
		t.Fatalf("want signed pdf, got %+v", res)
	}
}

func TestVerify_UnsignedPDFRejected(t *testing.T) {
	_, err := Check(ModeVerify, "plain.pdf", minimalPDF(t))
	if !errors.Is(err, ErrNoSignature) {
		t.Fatalf("want ErrNoSignature, got %v", err)
	}
}

func TestVerify_SignedContainer(t *testing.T) {
	for _, name := range []string{"c.asice", "c.edoc", "c.sce", "C.ASICE"} {
		res, err := Check(ModeVerify, name, signedContainer(t))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Kind != KindASiCE || !res.HasSignatures {
			t.Fatalf("%s: want signed asice, got %+v", name, res)
		}
	}
}

func TestVerify_UnsignedContainerRejected(t *testing.T) {
	_, err := Check(ModeVerify, "c.asice", unsignedContainer(t))
	if !errors.Is(err, ErrNoSignature) {
		t.Fatalf("want ErrNoSignature, got %v", err)
	}
}

func TestVerify_Rejections(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		data     []byte
		want     error
	}{
		{"disallowed extension", "notes.txt", []byte("text"), ErrUnsupportedType},
		{"no extension", "README", []byte("text"), ErrUnsupportedType},
		{"html renamed to pdf", "fake.pdf", []byte("<html><script>x()</script></html>"), ErrMalformed},
		{"garbage named pdf", "fake.pdf", []byte{0xde, 0xad, 0xbe, 0xef}, ErrMalformed},
		{"plain zip named asice", "fake.asice", nil, ErrMalformed}, // data filled below
		{"pdf named asice (extension vs bytes)", "doc.asice", nil, ErrMalformed},
	}
	cases[4].data = plainZip(t)
	cases[5].data = signedPDF(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Check(ModeVerify, tc.filename, tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestVerify_PolyglotPrefixedPDFRejected(t *testing.T) {
	// HTML prepended to a genuine signed PDF: the magic-at-offset-0 rule kills it.
	polyglot := append([]byte("<html>hi</html>"), signedPDF(t)...)
	_, err := Check(ModeVerify, "poly.pdf", polyglot)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

// --- signing mode ----------------------------------------------------------------

func TestSigning_AnyOpaqueFormatPasses(t *testing.T) {
	cases := []struct {
		filename string
		data     []byte
		want     Kind
	}{
		{"notes.txt", []byte("hello"), KindOther},
		{"data.bin", []byte{0xde, 0xad}, KindOther},
		{"page.html", []byte("<html><script>x()</script></html>"), KindOther},
		{"archive.zip", nil, KindZip}, // data filled below
	}
	cases[3].data = plainZip(t)
	for _, tc := range cases {
		res, err := Check(ModeSigning, tc.filename, tc.data)
		if err != nil {
			t.Fatalf("%s: %v", tc.filename, err)
		}
		if res.Kind != tc.want || res.HasSignatures {
			t.Fatalf("%s: got %+v", tc.filename, res)
		}
	}
}

func TestSigning_PDFChecked(t *testing.T) {
	res, err := Check(ModeSigning, "plain.pdf", minimalPDF(t))
	if err != nil {
		t.Fatalf("unsigned pdf must pass in signing mode: %v", err)
	}
	if res.Kind != KindPDF || res.HasSignatures {
		t.Fatalf("got %+v", res)
	}
	res, err = Check(ModeSigning, "signed.pdf", signedPDF(t))
	if err != nil {
		t.Fatalf("signed pdf: %v", err)
	}
	if !res.HasSignatures {
		t.Fatalf("signature not detected: %+v", res)
	}
	if _, err := Check(ModeSigning, "broken.pdf", []byte("%PDF-1.4 then garbage")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for a broken pdf, got %v", err)
	}
}

func TestSigning_ContainerCheckedAndUnsignedAllowed(t *testing.T) {
	res, err := Check(ModeSigning, "c.asice", unsignedContainer(t))
	if err != nil {
		t.Fatalf("unsigned container must pass in signing mode: %v", err)
	}
	if res.Kind != KindASiCE || res.HasSignatures {
		t.Fatalf("got %+v", res)
	}
	res, err = Check(ModeSigning, "c.asice", signedContainer(t))
	if err != nil || !res.HasSignatures {
		t.Fatalf("signed container: res=%+v err=%v", res, err)
	}
}

func TestSigning_ExtensionMustBeHonest(t *testing.T) {
	if _, err := Check(ModeSigning, "fake.pdf", []byte("not a pdf")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("fake .pdf: want ErrMalformed, got %v", err)
	}
	if _, err := Check(ModeSigning, "fake.asice", plainZip(t)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("plain zip named .asice: want ErrMalformed, got %v", err)
	}
}

// --- caps ------------------------------------------------------------------------

func TestSizeCaps(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 128)
	if _, err := Check(ModeSigning, "a.txt", big, WithMaxBytes(64)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("per-file cap: want ErrTooLarge, got %v", err)
	}
	// Shared budget across a multi-file request: the second file trips it.
	b := NewBudget(200)
	if _, err := Check(ModeSigning, "a.txt", big, WithBudget(b)); err != nil {
		t.Fatalf("first file within budget: %v", err)
	}
	if _, err := Check(ModeSigning, "b.txt", big, WithBudget(b)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("budget: want ErrTooLarge, got %v", err)
	}
}

func TestContainerBombRejected(t *testing.T) {
	bomb := buildZip(t, []zipEntry{
		{name: "mimetype", content: []byte(asice.MimeType), method: zip.Store},
		{name: "META-INF/signatures0.xml", content: bytes.Repeat([]byte{0}, 1<<20), method: zip.Deflate},
	})
	_, err := Check(ModeVerify, "bomb.asice", bomb,
		WithContainerLimits(asice.Limits{MaxEntryBytes: 1 << 10}))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

// --- filename hygiene ---------------------------------------------------------------

func TestFilenameHygiene(t *testing.T) {
	bad := []string{
		"",
		"a/b.pdf",
		`a\b.pdf`,
		"..",
		"evil\x00.pdf",
		"evil" + string(rune(0x202E)) + "fdp.pdf", // right-to-left override (spoofs the visible extension)
		strings.Repeat("a", 300) + ".pdf",
		string([]byte{0xff, 0xfe}) + ".pdf",
	}
	for _, name := range bad {
		if _, err := Check(ModeSigning, name, []byte("x")); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: want ErrMalformed, got %v", name, err)
		}
	}
	if _, err := Check(ModeSigning, "Läkums 2026 (1).txt", []byte("x")); err != nil {
		t.Fatalf("honest unicode name rejected: %v", err)
	}
}

// --- fuzz ------------------------------------------------------------------------

// FuzzCheck asserts the untrusted-input invariant: whatever the bytes and
// name, the gate never panics in either mode.
func FuzzCheck(f *testing.F) {
	f.Add("a.pdf", []byte("%PDF-1.4"))
	f.Add("a.asice", []byte("PK\x03\x04"))
	f.Add("a.txt", []byte("hello"))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		lim := WithContainerLimits(asice.Limits{MaxEntryBytes: 1 << 16, MaxTotalBytes: 1 << 18, MaxEntries: 64})
		_, _ = Check(ModeVerify, name, data, lim)
		_, _ = Check(ModeSigning, name, data, lim)
	})
}
