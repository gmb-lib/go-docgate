# docgate

The **document gate**: a cheap, deterministic admission check for untrusted
document uploads, run **before** anything expensive or external touches the
bytes — storage, rendering, or a remote validation / signing service. It
answers one question, *"should this file go further?"*, with a **typed reason**
when the answer is no, so callers return clear, actionable errors instead of
opaque upstream failures.

```
go get github.com/gmb-lib/go-docgate
```

All decisions are structural: magic bytes, archive shape, signature
**presence**. The gate performs **no cryptographic verification** (that belongs
to a validator such as EU DSS) and never executes or renders content. Bytes are
checked in memory; enforce your transport-level body limit and pass the
fully-read upload.

## Two modes

| | `ModeVerify` | `ModeSigning` |
|---|---|---|
| For | "validate / preserve this **signed** document" endpoints | "**sign** this file" endpoints |
| Admits | only a signed PDF or a signed, well-formed ASiC-E | **any** format |
| Extensions | allow-list: `.pdf` `.asice` `.edoc` `.sce` — anything else is `ErrUnsupportedType` | no allow-list, but an extension that *claims* a checked type must be honest about it |
| Signature required | yes (`ErrNoSignature` otherwise) | no — the file may be getting its first signature; presence is still reported |
| PDF content | must parse; magic at offset 0 (rejects prefixed/polyglot files) | same checks when the bytes are PDF |
| ZIP content | must be a strict ASiC-E (mimetype first entry, stored, exact media type) | strict ASiC-E → full container checks; a **plain ZIP passes opaque** (`KindZip`) |
| Other content | rejected | passes opaque (`KindOther`) |

In **every** mode: filename hygiene (path separators, control characters,
bidirectional-override spoofing, length, UTF-8 validity → `ErrMalformed`) and
size caps (per file, plus an optional shared multi-file `Budget` →
`ErrTooLarge`).

## Usage

```go
res, err := docgate.Check(docgate.ModeVerify, upload.Filename, data)
switch {
case errors.Is(err, docgate.ErrUnsupportedType): // 422: "not a supported signed-document type"
case errors.Is(err, docgate.ErrNoSignature):     // 422: "this document carries no signature"
case errors.Is(err, docgate.ErrTooLarge):        // 413
case errors.Is(err, docgate.ErrMalformed):
    // 422 — log err: the chain preserves the underlying parser error, so a
    // detector failure is observable instead of reading as a clean verdict.
default:
    _ = res.Kind          // pdf | asice | zip | other
    _ = res.HasSignatures // structural presence (never a crypto verdict)
}
```

Multi-file requests share a byte budget:

```go
b := docgate.NewBudget(64 << 20)
for _, f := range files {
    if _, err := docgate.Check(docgate.ModeSigning, f.Name, f.Data,
        docgate.WithBudget(b)); err != nil { … }
}
```

Options: `WithMaxBytes` (per-file cap; default 25 MB — the common per-file
limit of qualified signing services), `WithBudget`, `WithContainerLimits`
(decompression caps forwarded to the container inspection). A typical service
maps these to environment configuration and puts the whole gate behind an
on/off flag, so a deployment fronted by an already-gated edge can disable it.

## Detection notes

- **PDF signatures** are detected by two independent structural detectors —
  the PDF library's document-info flag and a byte scan for a signature
  dictionary (`/Type /Sig` + `/ByteRange`) — either positive counts. This
  catches signatures in files the library cannot fully parse (e.g. some
  externally-produced invisible signatures over incremental updates).
- **ASiC-E** shape and signature presence come from
  [`go-asice`](https://github.com/gmb-lib/go-asice) (`Sniff` + `Inspect`),
  including its zip-bomb decompression limits.
- `.edoc` / `.sce` are accepted as national ASiC-E variants.

## Scope / non-goals

- No cryptographic validation, no trust decisions — presence and shape only.
- No content scanning (anti-virus is a separate, deployment-specific concern).
- No transport handling — the caller owns HTTP limits and multipart parsing.

## Contributing

Bug reports and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) names the gate a
change has to pass, what a change to this library needs, and the sign-off every commit carries.

Suspected vulnerabilities go through the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

## License

MIT — see [LICENSE](./LICENSE).
