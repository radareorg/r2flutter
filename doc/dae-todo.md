# DAE Gap Implementation TODO

This roadmap tracks the high-confidence Dart AOT format and restoration gaps
identified by comparing `third_party/dae` with r2flutter. IDs are stable so an
item can be selected by name in follow-up work.

Items are ordered by dependency: stream framing and codecs first, versioned
cluster layouts next, then metadata/value restoration and profile detection.

- [x] **R2F-DAE-001 — Parse version-specific snapshot headers**
  - Read the profile-defined header field count and semantics.
  - Preserve canonical-cluster and field-table fields where present.
  - Commit: `Parse Version-Specific Snapshot Headers`
- [x] **R2F-DAE-002 — Add versioned snapshot reference decoding**
  - Use unsigned LEB128 references through Dart 2.17.
  - Use the `ReadRefId` +128 encoding from Dart 2.18 onward.
  - Commit: `Add Versioned Snapshot Reference Decoding`
- [x] **R2F-DAE-003 — Handle versioned ObjectPool entry bits**
  - Model low-seven-bit, swapped low-seven-bit, and modern bitfield eras.
  - Commit: `Handle Versioned ObjectPool Entry Bits`
- [x] **R2F-DAE-004 — Parse versioned Code cluster layouts**
  - Profile Code reference counts, text-offset deltas, and leading refs.
  - Commit: `Parse Versioned Code Cluster Layouts`
- [x] **R2F-DAE-005 — Support Dart 3.13 single snapshots**
  - Add hashes/CIDs and merged VM/isolate snapshot handling.
  - Add the alternate symbols and 3.13 Class, Code, and Closure layouts.
  - Test complete and truncated combined snapshots, including partial-fill failure reporting.
  - Commit: `Support Dart 3.13 Single Snapshots`
- [ ] **R2F-DAE-006 — Retain serialized class layout metadata**
  - Keep class ID, library/super references, next-field offset, and bitmap.
  - Commit: `Retain Serialized Class Layout Metadata`
- [ ] **R2F-DAE-007 — Retain snapshot object value graph**
  - Preserve Instance, Array, Map, and Set values by object reference.
  - Expose bounded recursive values through the object inspector.
  - Commit: `Retain Snapshot Object Value Graph`
- [ ] **R2F-DAE-008 — Probe snapshot layouts for unknown hashes**
  - Validate candidate layouts structurally instead of selecting the newest.
  - Commit: `Probe Snapshot Layouts for Unknown Hashes`
