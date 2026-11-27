# GAP-04 — signing and publication lineage

The source-only qualification covers five implementation promises:

- P01: read-only immutable journal reservation export; exact promoted Git tree,
  provider diagnostic identity, version floor and protected signer use in F06.
- P02: committed signer trust anchor and append-only reservation history; actual
  DER check, private transient key/properties, cleanup, APK signature, exact
  version and ABI proof (including riscv64 and universal).
- P03: separately reviewed exact F06 attempt, provider ZIP identities and raw
  signed report, committed-source/compatibility and monotonic version proof.
- P04: fail-closed F07 publication transaction with bounded intent history, draft
  identity, byte readback, explicit resume and no automatic duplicate creation.
- P05: independent read-only F08 original provider ZIP, retained report, release
  tag, asset digest, compatibility and APK signature audit. Preserve F03 updater
  metadata shape and support the configured riscv64 variant.

Behavioral regression uses disposable Git repositories, a temporary test-only
certificate/keystore with real keytool, controlled provider transport fixtures,
ZIP extraction checks and native ABI metadata fixtures. These are not evidence
of real signed APKs, actual GitHub publication, physical-device compatibility,
or protection/secret configuration. Source review requires no local Gradle or
credential access. Full signed acceptance requires actual protected F06, F07,
F08 and owner/device gates. The registries intentionally authorize nothing yet.
