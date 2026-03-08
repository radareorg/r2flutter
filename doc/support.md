# Support Matrix

r2flutter currently carries layout profiles for Dart AOT snapshots from **Dart 2.10.0 to 3.10.7** (roughly Flutter **1.22.x to 3.38.x**).

This matrix describes parser/layout support, not exhaustive regression coverage for every engine patch release. Platform notes summarize the binary/container differences the current parser accounts for when applying the same Dart snapshot profile.

| Dart Version | Flutter Version | Tag Style | Notes | Platform Details |
|--------------|-----------------|-----------|-------|------------------|
| 2.10.0 | 1.22.x | Int32 CID | Pre-FunctionType split | Android: legacy `libapp.so` ELF snapshots in the pre-compressed-pointer era. iOS: same Int32 profile in Mach-O-style app binaries, typically with full-width pointers. |
| 2.13.0 | 2.2.x - 2.3.x | Int32 CID | Split canonical clusters | Android: ELF parser still sees older non-ObjectHeader snapshots. iOS: same snapshot layout family, with platform differences mostly limited to Mach-O container handling. |
| 2.14.0 | 2.4.x - 2.5.x | CID Shift1 | TypeParameters added | Android: first Shift1-era `libapp.so` layouts. iOS: matching Shift1 snapshot profile, usually without Android-style compressed-pointer behavior. |
| 2.15.0 | 2.6.x - 2.7.x | CID Shift1 | NativePointer inserted | Android: ELF snapshots with updated CID table. iOS: same Dart layout profile applied through Mach-O snapshot discovery. |
| 2.16.0 | 2.8.x - 2.16.x | CID Shift1 | ConstMap/ConstSet added | Android: broader Flutter 2.x coverage on `libapp.so`. iOS: same Shift1 decoding, with iOS-specific work mostly in binary loading rather than object layout. |
| 2.17.6 | 2.17.x | CID Shift1 | WeakReference added | Android: final pre-2.18 range before compressed pointers become common. iOS: same snapshot family, generally still treated as full-width-pointer binaries. |
| 2.18.0 | 3.3.x | CID Shift1 | SuspendState added | Android: compressed-pointer-era builds become common and cluster counts can grow significantly. iOS: still uses the same Shift1 layout profile, but current samples remain easier to walk due to smaller metadata. |
| 2.19.0 | 3.7.x | CID Shift1 | RecordType/Record added | Android: ELF snapshots continue in the compressed-pointer era. iOS: same profile on Mach-O, with platform deltas still centered on container parsing and address mapping. |
| 3.0.5 | 3.10.x - 3.12.x | CID Shift1 | WeakArray added | Android: Shift1 + compressed pointers remain the main path. iOS: Mach-O snapshots still use the matching Shift1 layout without moving to ObjectHeader yet. |
| 3.1.0 | 3.13.x | CID Shift1 | TypeRef removed | Android: updated CID table in ELF snapshots. iOS: same layout transition applied in Mach-O binaries. |
| 3.2.5 | 3.16.x | CID Shift1 | PoolType swapped | Android: late Shift1 profile before ObjectHeader. iOS: same late-Shift1 profile, still generally observed with full-width pointers. |
| 3.3.0 | 3.19.x | CID Shift1 | Last Shift1 format | Android: last Shift1 generation before the ObjectHeader change. iOS: same final Shift1 profile on Mach-O binaries. |
| 3.4.3 | 3.22.x | ObjectHeader | New tag encoding | Android: ObjectHeader + compressed pointers are the main modern `libapp.so` target. iOS: ObjectHeader too, but current samples keep full-width pointers and smaller cluster metadata. |
| 3.5.0 | 3.24.x | ObjectHeader | ObjectHeader family stabilized | Android: modern ELF path with ObjectHeader parsing. iOS: same tag format with Mach-O container differences only. |
| 3.6.2 | 3.27.x | ObjectHeader | Incremental CID/profile updates | Android: ObjectHeader remains the expected format. iOS: same ObjectHeader profile, typically with simpler address translation in current samples. |
| 3.7.0 | 3.29.x | ObjectHeader | Ongoing ObjectHeader era | Android: modern compressed-pointer snapshots. iOS: same ObjectHeader layout profile in app binaries. |
| 3.8.1 | 3.32.x | ObjectHeader | Ongoing ObjectHeader era | Android: ELF support continues with the same high-level parser flow. iOS: Mach-O support continues with the same snapshot profile selection. |
| 3.9.2 | 3.35.x | ObjectHeader | Fallback baseline for unknown hashes | Android: default fallback profile for unknown modern ELF hashes. iOS: default fallback profile for unknown modern Mach-O hashes. |
| 3.10.7 | 3.38.x | ObjectHeader | Current latest | Android: newest known `libapp.so` profile in-tree. iOS: newest known app-binary profile in-tree. |

Unknown snapshot hashes currently fall back to the **v3.9.2** profile with ObjectHeader encoding.
