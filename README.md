# pveforge

A standalone Go CLI for Proxmox VE cluster lifecycle management — token-first
(no permanent root SSH dependency), fully idempotent, and self-describing
down to the property level so its capabilities can be walked and understood
without static documentation.

**Status:** pre-implementation. See [`docs/prd.md`](docs/prd.md) for the
foundational design and the evidence it's built on.

## Why

Every existing option for Proxmox automation — Terraform's providers,
Ansible's collection, Salt's community extension, Kubernetes Cluster API — was
evaluated against a real, unusually demanding workload (raw QEMU device
configuration, exotic NVMe/BMC/PCIe emulation, non-cloud-init boot paths) and
found wanting in a concrete, evidenced way. `docs/prd.md` §0.1 records exactly
what was tested and what broke.

## License

Dual-licensed under your choice of MIT or Apache-2.0. See [`LICENSE`](LICENSE).

The compiled binary also contains third-party code under its own licenses —
including Apache-2.0 code from `go-proxmox`, which pveforge forks. See
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
