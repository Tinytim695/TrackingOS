# TrackingOS

Debian-based investigation workstation. This repository currently contains the
first runtime slice only: authorised tool execution and an append-only case
store. It does not yet build a bootable image.

## Status

| Claim | State |
| --- | --- |
| Secure action gateway and evidence store | Implemented in this tree |
| Host tests | Run `make test` on a Linux machine |
| GitHub Actions | Workflow is present; a green run is a separate fact |
| ISO built | No |
| ISO validated | No |
| QEMU kernel boot | No |
| QEMU GUI | No |
| Physical USB boot | No |

`trackingos build-host` only checks whether `debootstrap`, `mksquashfs`,
`xorriso`, and `qemu-system-x86_64` exist. A ready report is not an image.

## Run the tests

```sh
make test
```

The tests need Linux, Python 3.10+, and permission to create a network
namespace (`unshare`). Root, or an unprivileged user namespace, is required.

## Operator commands

There is no flag that authorises an action. Scope and grant are files.

```sh
PYTHONPATH=src python3 -m trackingos case create \
  --store /srv/cases --title "Lab exercise" --investigator "Sam Jones"
```

See [docs/security-model.md](docs/security-model.md) for what the runtime
actually enforces.

Package tiers live in [config/package-tiers.json](config/package-tiers.json).
`availability` is `unverified` until a builder queries a Debian index. Lab-tier
tools (including masscan and Metasploit) are not part of the default image.
