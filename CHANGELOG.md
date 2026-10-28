# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency — what changed, and what it means for code that already
uses it.

## v1.0.6

This release refreshes the document parsers and requires **Go 1.27.3**. Raise your own module's
`go` directive to `1.27.3` before upgrading.

### Changed

- **The module declares `go 1.27.3`** (was `1.27.2`).
- **`github.com/gmb-lib/go-asice` → v1.6.4** (was v1.6.3) and
  **`github.com/pdfcpu/pdfcpu` → v0.16.4** (was v0.16.1); their dependency graph was refreshed.
- The gate's implementation and public API are unchanged.

## v1.0.5

A security release. The PDF parser underneath the gate moves to **pdfcpu v0.16.1**, and the library
**now needs Go 1.27.2**. The gate's API is unchanged, and on every test document it admits and
refuses what it did before.

### Changed

- **The PDF parser, `github.com/pdfcpu/pdfcpu`, → v0.16.1** (was v0.15.0). Its v0.16.0 and v0.16.1
  releases fix seven security advisories, most of them crashes or memory exhaustion on crafted PDFs,
  the kind of input this gate exists to inspect: GHSA-6524-w46v-6399, GHSA-g766-88fx-58h8,
  GHSA-fjh6-rrhv-4g63, GHSA-9mmx-88p2-c8c6, GHSA-prvw-v9vv-6966, GHSA-w2hj-54mc-76r4 and
  GHSA-7v74-phpq-xq6g. Which of them the gate's own calls reach was not traced; the gate parses
  untrusted PDFs, so it takes them all. pdfcpu v0.16 changed its API, and the gate follows it in
  two places:
  - the document-info call now takes a context; the gate passes a background one, since its own
    API takes none, so a parse runs to completion as it always has;
  - the built-in configuration is now passed explicitly, replacing the call pdfcpu deprecated.
    The effect is the same: pdfcpu never creates a configuration directory, so the gate still works
    in a read-only container with no writable home. Measured there: the tests pass, and the same
    code without the explicit configuration fails with *"read-only file system"*.

  On the signed test document, pdfcpu v0.15.0 and v0.16.1 give the same result. Both fail to parse
  it, and the gate's byte scan finds the signature as before.

- **The module declares `go 1.27.2`** (was `1.27.0`). Go 1.27.2 fixes standard-library
  vulnerabilities that this library's code reaches under 1.27.0. `govulncheck` found eight it calls
  before the move and none after it: GO-2026-6603, -6605, -6607, -6608, -6610, -6611, -6613 and
  -6617, in `net/http`, `crypto/tls`, `net/textproto` and `mime/multipart`. Raise your own module's
  `go` directive to `1.27.2`; from there the go command downloads and uses that toolchain by itself.

### Notes

- **Also moved:** `go-asice` → **v1.6.3** (the Go version only, no code change), and pdfcpu's own
  dependencies: `hhrutter/tiff` → v1.0.7, `go-runewidth` → v0.0.31, `golang.org/x/image` → v0.47.0,
  `golang.org/x/crypto` → v0.58.0, `golang.org/x/text` → v0.43.0.

- **CI's linter moved to golangci-lint v2.14.0** (was v2.13.1). The earlier release cannot read Go
  1.27.2's compiled standard library and stops before linting anything. CI's pinned GitHub Actions
  also moved to their current commits.

- The gate is green on Go 1.27.2: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  golangci-lint v2.14.0, `go test -race` with **0 races**, the fuzz target for 30 seconds with no failing
  input, and the tests again inside a read-only container with no writable home; `govulncheck`
  reports nothing this library calls.

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
