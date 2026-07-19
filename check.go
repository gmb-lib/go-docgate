package docgate

import (
	"errors"
	"fmt"

	asice "github.com/gmb-lib/go-asice"
)

// Container extensions accepted as ASiC-E (the .edoc and .sce national
// variants are ASiC-E containers under a local name).
var asiceExts = map[string]bool{".asice": true, ".edoc": true, ".sce": true}

// Check gates one uploaded file. It returns the detected Result when the file
// is admitted, or an error wrapping one of the package sentinels
// (ErrUnsupportedType, ErrMalformed, ErrNoSignature, ErrTooLarge) when it must
// be rejected. The wrapped chain preserves any underlying parser error — log
// it; a silent detector failure is indistinguishable from a clean verdict.
//
// In every mode the filename is checked first (hygiene is format-independent)
// and the size caps apply. Beyond that:
//
//   - ModeVerify: the extension must be .pdf / .asice / .edoc / .sce; the
//     bytes must parse as that type (an extension contradicting the bytes is
//     malformed, not re-routed) and must carry at least one signature.
//   - ModeSigning: any format is admitted. Content that claims (by extension)
//     or appears (by bytes) to be PDF or ASiC-E must parse as such; a plain
//     ZIP that is not a container passes opaque, as does everything else.
func Check(mode Mode, filename string, data []byte, opts ...Option) (Result, error) {
	o := resolveOptions(opts)

	if err := checkFilename(filename); err != nil {
		return Result{}, err
	}
	if err := o.checkSize(int64(len(data))); err != nil {
		return Result{}, err
	}

	switch mode {
	case ModeVerify:
		return checkVerify(filename, data, &o)
	case ModeSigning:
		return checkSigning(filename, data, &o)
	default:
		return Result{}, fmt.Errorf("docgate: unknown mode %d", mode)
	}
}

// checkVerify applies the signed-document admission rule.
func checkVerify(filename string, data []byte, o *options) (Result, error) {
	switch e := ext(filename); {
	case e == ".pdf":
		if !isPDF(data) {
			return Result{}, fmt.Errorf("%w: %q does not contain PDF content", ErrMalformed, filename)
		}
		has, parseErr := pdfSignatures(data)
		if has {
			return Result{Kind: KindPDF, HasSignatures: true}, nil
		}
		if parseErr != nil {
			return Result{}, fmt.Errorf("%w: PDF does not parse and no signature was found: %w", ErrMalformed, parseErr)
		}
		return Result{}, fmt.Errorf("%w: the PDF carries no signature", ErrNoSignature)

	case asiceExts[e]:
		res, err := checkContainer(data, o)
		if err != nil {
			return Result{}, err
		}
		if !res.HasSignatures {
			return Result{}, fmt.Errorf("%w: the container carries no signature", ErrNoSignature)
		}
		return res, nil

	default:
		return Result{}, fmt.Errorf("%w: %q (accepted: .pdf, .asice, .edoc, .sce)", ErrUnsupportedType, filename)
	}
}

// checkSigning admits any format, structurally checking only content that
// claims or appears to be PDF or ASiC-E.
func checkSigning(filename string, data []byte, o *options) (Result, error) {
	e := ext(filename)

	// An extension that claims a checked type must be honest about it.
	if e == ".pdf" && !isPDF(data) {
		return Result{}, fmt.Errorf("%w: %q does not contain PDF content", ErrMalformed, filename)
	}
	if asiceExts[e] && asice.Sniff(data, o.containerLimits...) != nil {
		return Result{}, fmt.Errorf("%w: %q is not a well-formed container", ErrMalformed, filename)
	}

	switch {
	case isPDF(data):
		has, parseErr := pdfSignatures(data)
		if !has && parseErr != nil {
			return Result{}, fmt.Errorf("%w: PDF does not parse: %w", ErrMalformed, parseErr)
		}
		return Result{Kind: KindPDF, HasSignatures: has}, nil

	case asice.IsZip(data):
		if asice.Sniff(data, o.containerLimits...) == nil {
			return checkContainer(data, o)
		}
		// A plain ZIP is a legitimate opaque upload — nothing downstream
		// unzips it (the shape probe above is itself bounded).
		return Result{Kind: KindZip}, nil

	default:
		return Result{Kind: KindOther}, nil
	}
}

// checkContainer runs the full strict container checks: outer shape, bounded
// inspection, signature presence.
func checkContainer(data []byte, o *options) (Result, error) {
	if err := asice.Sniff(data, o.containerLimits...); err != nil {
		return Result{}, wrapContainerErr(err)
	}
	_, signatures, _, err := asice.Inspect(data, o.containerLimits...)
	if err != nil {
		return Result{}, wrapContainerErr(err)
	}
	return Result{Kind: KindASiCE, HasSignatures: len(signatures) > 0}, nil
}

// wrapContainerErr maps container-library errors onto the gate's sentinels,
// preserving the original chain.
func wrapContainerErr(err error) error {
	if errors.Is(err, asice.ErrTooLarge) || errors.Is(err, asice.ErrTooManyEntries) {
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	}
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}
