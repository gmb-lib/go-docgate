# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency — what changed, and what it means for code that already
uses it.

## v1.0.4

No library code changed since v1.0.3, so the gate admits and refuses exactly what it did before.
There is one thing to act on: **it now needs Go 1.27**.

### Changed

- **The module declares `go 1.27.0`** (was `1.26.6`), so your own module has to be on Go 1.27
  before it can build against this one. A dependency's `go` line does **not** make the go command
  fetch a newer toolchain for you — measured both ways: a consumer whose own `go` directive is
  lower stops with a `requires go >= 1.27.0 (running go 1.26.6)` error, and it stops there with
  `GOTOOLCHAIN` on its `auto` default just as it does under `local`. Raise your own `go` directive
  to `1.27.0` first; from there the go command downloads and uses the 1.27 toolchain by itself, so
  nobody has to install Go by hand. CI that reads `go-version-file: go.mod` follows the bump with
  no workflow edit — a workflow naming a Go version in the YAML needs that line changed.

### Notes

- **`github.com/gmb-lib/go-asice` → v1.6.2** (was v1.6.1) — the container library this gate reads
  ASiC-E through, and the release that carries the same Go 1.27 requirement. No library source
  changed in it either, so the strict-container checks are unchanged. Also moved, none of them
  called from here directly: `golang.org/x/crypto` → v0.57.0, `golang.org/x/image` → v0.46.0,
  `golang.org/x/text` → v0.42.0 and `github.com/mattn/go-runewidth` → v0.0.30, all through `pdfcpu`
  and the container library.

- **The copyright holder is now named in full** — `SIA "Go Make Bytes"` instead of
  `go-make-bytes`. Same MIT licence, same terms; only the holder's legal name is spelled out. Worth
  a glance if you carry the licence text in a notices file.

- The repository gained the open-source kit it was missing — `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, a secret-scan configuration and the README sections pointing at them —
  plus this file. The advisory DCO workflow was removed now that the sign-off is enforced by the
  organisation's app together with a branch ruleset; what a contribution has to carry is unchanged.
  CI now also runs on pushes to `develop`, and its `setup-go` and `golangci-lint` pins were rolled
  forward. No code changed with any of it.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` with **0 races**; `govulncheck` finds nothing.

---

The entries below were **reconstructed from git history** rather than written at the time, so they
say what each tag contains, not why it was decided. They cover what a consumer would have to act on;
releases that only moved dependencies are named as such.

## v1.0.3

Dependencies only. `github.com/gmb-lib/go-asice` → v1.6.1, `github.com/pdfcpu/pdfcpu` → v0.15.0,
`github.com/mattn/go-runewidth` → v0.0.28, and `golang.org/x/crypto` → v0.55.0, `x/image` →
v0.45.0, `x/text` → v0.41.0. The CI workflows were reworked in the same range. No source change.

## v1.0.2

Dependencies only. `github.com/gmb-lib/go-asice` → v1.6.0 (the release that added
`BuildUnsigned` and document-name validation, neither of which this gate calls) and
`github.com/mattn/go-runewidth` → v0.0.27.

## v1.0.1

Two behaviour changes, both of which you get on bump with nothing to opt into. Neither affects
`ModeVerify`.

### Changed

- **`ModeSigning` no longer refuses a PDF that the detector cannot parse.** A file whose bytes
  start with the PDF magic used to be rejected as `ErrMalformed` when the parse failed; it is now
  admitted, and the signature probe is treated as best-effort — inconclusive, never a rejection.
  The reasoning is whose decision it is: a document *about to be signed* does not have to be
  perfectly parseable by an admission gate, because the signing service is the authority on
  signability, and the offset-0 magic has already excluded non-PDF content. `ModeVerify` is
  untouched — there the document must parse, because there the signature is the whole point.

  **If you have a test asserting that signing-mode refuses a `%PDF` file with garbage after it,
  that test now fails and the new behaviour is the correct one.**

- **PDF parsing works in a hardened container.** `pdfcpu` creates a configuration directory under
  the user's home on first use; in a rootless, read-only container there is no writable home, so
  that step failed and **every** PDF parse errored. The library ships a switch for exactly that
  environment, and this package now sets it at init, running on built-in defaults with no on-disk
  configuration. Nothing to configure on your side.

## v1.0.0

Initial code. The document gate: a cheap, structural admission check for untrusted uploads, run
before storage, rendering or any remote validation or signing service touches the bytes. `Check`
answers *"should this file go further?"* in one of two modes — `ModeVerify` for endpoints that
validate or preserve an already-signed document, `ModeSigning` for endpoints that are about to
sign one — and returns a typed reason when the answer is no (`ErrUnsupportedType`, `ErrMalformed`,
`ErrNoSignature`, `ErrTooLarge`). Decisions are structural only: magic bytes at offset 0, strict
ASiC-E container shape, signature *presence*. No cryptographic verification, no rendering, no
execution; bytes are checked in memory under a size budget (`WithMaxBytes`, `WithBudget`,
`WithContainerLimits`).
