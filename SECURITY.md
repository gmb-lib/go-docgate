# Security policy

This library is the gate that untrusted uploads pass through **before** anything expensive or
external touches them — storage, rendering, a remote validator, a signing service. Its whole value
is that it is the cheap, bounded, in-memory check standing in front of everything that is not.
A wrong answer here either lets attacker-chosen bytes reach code that was never meant to see them,
or costs the caller exactly the expense the gate exists to avoid.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/gmb-lib/go-docgate/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the file or bytes that trigger it, if you can share them, and which mode was in use;
- whether you have told anyone else, and whether a disclosure date already binds you.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

- Bytes admitted in `ModeVerify` that carry no signature at all, or that are not the type they
  claim — a prefixed or polyglot PDF, a plain ZIP passing as an ASiC-E, an extension that lies
  about content the gate checks.
- A filename accepted by the hygiene check while it still carries a path separator, an absolute
  path, a parent-directory segment, a control character or a reserved name — because the caller
  will use that name.
- Any path where the gate does more than look at bytes: executing, rendering, resolving an
  external entity, opening a file, or making a network call. The gate must never leave the buffer.
- Attacker-chosen bytes that cost unbounded time or memory inside the gate — an archive bomb, a
  pathological PDF, an entry count or nesting depth without a limit. This class matters more here
  than in most libraries: the gate runs first, on everything, and unauthenticated.
- A typed reason that misreports the decision in a way a caller acts on — above all, reporting a
  rejection while the caller's code path treats the file as admitted, or the reverse.

Denial of service is not a lower-priority class in this repository; it is one of the things the
gate is for. Findings that need an already-compromised host remain lower priority. Reports about
outdated dependencies are welcome where you can show the vulnerable path is actually reachable.

## What is deliberately not a finding

The gate performs **no cryptographic verification**. It reports signature *presence*, never
signature validity, and admitting a document whose signature later turns out to be invalid is the
designed behaviour — validation belongs to a validator such as EU DSS. A report that an API
implies otherwise is a real finding; a report that a bad signature got through is not.

## Scope

This policy covers the code in this repository. Transport-level body limits are the caller's — the
gate checks bytes that have already been read. It does not cover the storage, rendering, validation
or signing services that sit behind it; report those to the parties that run them.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
