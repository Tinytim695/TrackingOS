# Security model (core runtime)

This is the boundary later GUI and tool integrations have to sit behind. It is
not a complete operating system and it is not a full sandbox.

## What is enforced

- An action request names a tool, a target, a scope object, and an argument
  vector. It has no `authorised`, `allow_active`, or `allow_network` field.
- A grant is a separate object. String values such as `"true"` are rejected.
  A grant cannot enable active work when the scope forbids it.
- Missing, expired, or mismatched grants do not start a process.
- Tools are selected by name from a registry. The registry path must stay
  inside configured executable roots. The request cannot pass an executable path.
- Processes are started with `shell=False`. Arguments are an argv array.
- The child environment is a fixed allowlist. Parent credentials are not copied.
- If the tool's network mode is `none`, or the grant does not allow network,
  the child calls `unshare(CLONE_NEWNET)` before `exec`. Failure refuses to run
  the tool.
- Timeouts and cancellation signal the process group, then SIGKILL after a
  grace period.
- Captured output is capped. The stored SHA-256 covers the captured bytes and
  the result says when the capture was truncated.
- Case ids are filenames. Creates use `O_EXCL` and `link(2)`, not `rename(2)`,
  so an existing evidence object is not replaced. Symlinks in the case layout
  are refused via `O_NOFOLLOW`. Evidence files are never executed.
- Action records store an argument hash, not the argument values.
- Grant files must be owner-readable only (`0600` or `0400`). Policy files that
  are group- or world-writable are refused. Symlink policy files are refused.
- Hostnames are compared as literal strings. DNS is not consulted, so a name
  cannot be steered onto an address outside the scope.

## What is not enforced yet

- Authorised network access is all-or-nothing for that process. Destination is
  not packet-filtered. A tool that is allowed to run with network can contact
  hosts other than the declared target.
- Tools run as the same uid as TrackingOS. There is no seccomp, no user
  namespace, and no privilege drop.
- A tool that calls `setsid` can leave the tracked process group.
- Path confinement applies to `absolute-only` tools. Other tools can still open
  any file the uid can open.
- The executable inode is checked at start. A malicious registered binary is
  trusted, because the registry is operator configuration.
- There is no GUI. A future interface must not mint grants. It should submit
  tool, target, and arguments to a broker that loads grants itself.
- No ISO has been built. Package names in `config/package-tiers.json` are
  unverified candidates.

## Bug-bounty OSINT

`trackingos osint` records a program and checks targets against it before any
lookup. Out-of-scope domains and CIDRs win over in-scope ones. Wildcards cannot
be a public suffix (`*.com`, `*.github.io`). A DNS lookup also needs a grant
with `allow_network`. The OSINT centre does not port-scan, fuzz, or send
exploit payloads. `allow_active` is stored as false and a document that says
otherwise is rejected. Addresses returned by DNS are not automatically in scope.
