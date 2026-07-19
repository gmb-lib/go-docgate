// Package docgate is the document gate: a cheap, deterministic admission
// check for untrusted document uploads, run BEFORE anything expensive or
// external touches the bytes (storage, rendering, or a remote validation /
// signing service).
//
// It answers one question — "should this file go further?" — with a typed
// reason when the answer is no, so callers can return clear, actionable
// errors instead of opaque upstream failures. All decisions are structural:
// magic bytes, archive shape, signature *presence*. The gate performs no
// cryptographic verification (that belongs to a validator such as EU DSS) and
// never executes or renders the content.
//
// Two modes cover the two kinds of boundary:
//
//   - ModeVerify — the admission rule for "validate / preserve this signed
//     document" endpoints: only a signed PDF or a signed, well-formed ASiC-E
//     container passes; everything else is rejected with a reason.
//   - ModeSigning — the rule for "sign this file" endpoints: any format is
//     admitted (a file about to be signed need not carry a signature), but
//     content that claims or appears to be PDF or ASiC-E must actually parse
//     as such, and size caps always apply.
//
// The bytes are checked in memory; callers enforce their own transport-level
// body limits and pass the fully-read upload here.
package docgate

import (
	"errors"
	"fmt"

	asice "github.com/gmb-lib/go-asice"
)

// Mode selects which admission rule Check applies.
type Mode int

const (
	// ModeVerify admits only a signed PDF or a signed, well-formed ASiC-E
	// container (extensions .pdf / .asice / .edoc / .sce).
	ModeVerify Mode = iota
	// ModeSigning admits any format under the size caps; PDF and ASiC-E
	// content is structurally checked, other content passes opaque.
	ModeSigning
)

// Kind is the detected document type.
type Kind string

const (
	// KindPDF: the bytes are a PDF (magic at offset 0).
	KindPDF Kind = "pdf"
	// KindASiCE: the bytes are a well-formed ASiC-E container.
	KindASiCE Kind = "asice"
	// KindZip: a plain ZIP archive that is not an ASiC-E container. Admitted
	// in signing mode as an opaque format (nothing downstream unzips it).
	KindZip Kind = "zip"
	// KindOther: any other format, admitted opaque in signing mode.
	KindOther Kind = "other"
)

// Rejection reasons. Wrap-aware: use errors.Is against these sentinels; the
// wrapped detail (including any underlying parser error) is preserved so the
// caller can log the cause — a swallowed detector error would be
// indistinguishable from a clean "unsigned" verdict.
var (
	// ErrUnsupportedType: (verify mode) the file is not one of the supported
	// signed-document types, by extension.
	ErrUnsupportedType = errors.New("docgate: not a supported signed-document type")
	// ErrMalformed: the content does not parse as what it claims or appears
	// to be (broken PDF, broken or non-conformant container, an unsafe
	// filename, or an extension that contradicts the bytes).
	ErrMalformed = errors.New("docgate: malformed document")
	// ErrNoSignature: (verify mode) the document is well-formed but carries no
	// signature — there is nothing to validate or preserve.
	ErrNoSignature = errors.New("docgate: document carries no signature")
	// ErrTooLarge: the file exceeds the per-file cap or the shared budget.
	ErrTooLarge = errors.New("docgate: document exceeds the size limit")
)

// Result describes an admitted document.
type Result struct {
	// Kind is the detected type.
	Kind Kind
	// HasSignatures reports whether a signature was structurally detected.
	// Authoritative for KindPDF and KindASiCE; always false for opaque kinds.
	HasSignatures bool
}

// DefaultMaxBytes is the per-file size cap applied when no option overrides
// it. It matches the common per-file limit of qualified signing services.
const DefaultMaxBytes int64 = 25 << 20 // 25 MB

// Budget tracks a shared byte allowance across several files in one request
// (e.g. a multi-document signing preparation). Create one per request and pass
// it to each Check call via WithBudget; it is not safe for concurrent use.
type Budget struct {
	remaining int64
}

// NewBudget returns a Budget allowing total bytes across all files checked
// against it.
func NewBudget(total int64) *Budget {
	return &Budget{remaining: total}
}

// options collects the per-call configuration.
type options struct {
	maxBytes        int64
	budget          *Budget
	containerLimits []asice.Option
}

// Option tunes a Check call.
type Option func(*options)

// WithMaxBytes overrides the per-file size cap (DefaultMaxBytes when unset; a
// non-positive value keeps the default).
func WithMaxBytes(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.maxBytes = n
		}
	}
}

// WithBudget applies a shared multi-file byte budget in addition to the
// per-file cap.
func WithBudget(b *Budget) Option {
	return func(o *options) { o.budget = b }
}

// WithContainerLimits overrides the decompression limits used when a container
// is inspected (per-entry / total / entry-count caps; the container library's
// defaults otherwise).
func WithContainerLimits(l asice.Limits) Option {
	return func(o *options) { o.containerLimits = []asice.Option{asice.WithLimits(l)} }
}

func resolveOptions(opts []Option) options {
	o := options{maxBytes: DefaultMaxBytes}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// checkSize enforces the per-file cap and, when configured, the shared budget.
func (o *options) checkSize(n int64) error {
	if n > o.maxBytes {
		return fmt.Errorf("%w: %d bytes (limit %d)", ErrTooLarge, n, o.maxBytes)
	}
	if o.budget != nil {
		if n > o.budget.remaining {
			return fmt.Errorf("%w: %d bytes exceed the remaining request budget %d", ErrTooLarge, n, o.budget.remaining)
		}
		o.budget.remaining -= n
	}
	return nil
}
