IONA OS — Unified Patch Bundle Applied

This bundle consolidates the prior patch passes into a single base:

- patched-full:
  - build-ionafs searches 3 locations for iona-node
  - fork path updated to spawn a concrete child task via scheduler
- improved-full:
  - improved userspace packaging and artifact staging
  - better installer/update flow
  - consensus sync dedupe/local_height updates
  - TLS x25519 key-share scan instead of fixed offset
- ultra-focus-pass:
  - recovery serial shell (help/fsck/crashlog/reboot)
  - terminal crashlog command and better ps visibility
  - wallet window footprint reduced
- major-update-full:
  - release-manifest generation
  - verify-release tooling
  - richer IONAFS image defaults and metadata
  - installer/update payload handling for wasm/json/manifests

Notes:
- This is a unified static patch bundle. Build/boot/runtime validation is still required.
- The goal is to give a single working base for further bug-fixing and stabilization.
