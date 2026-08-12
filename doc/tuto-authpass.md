# AuthPass.app Dart AOT TLS tutorial

This tutorial uses the iOS fixture:

```text
test/bins/ios/AuthPass.app
```

Run commands from the repository root. The Dart AOT image is not the top-level
`Runner` executable; it is:

```sh
IOS_BUNDLE=test/bins/ios/AuthPass.app
IOS_APP="$IOS_BUNDLE/Frameworks/App.framework/App"
```

Rebuild the tools and plugin before following the r2 steps:

```sh
make
make r2
make user-install
```

## Challenge 1: recover Dart AOT method names and map the TLS handshake path

Start by verifying that r2flutter recognizes the snapshot:

```sh
bin/r2flutter -j -H "$IOS_BUNDLE"
```

Expected important values:

```text
"dart_version":"3.2.5"
"hash":"f71c76320d35b65f1164dbaa6d95fe09"
"it_len":37092
"tag_style":"CID_SHIFT1"
```

Dump recovered functions and resolve the TLS methods by semantic name. Do not
hardcode the private suffix; AuthPass uses `14069316`, but that value changes
between snapshots.

```sh
FUNCS=$(mktemp)
bin/r2flutter -q -f "$IOS_BUNDLE" > "$FUNCS"

BAD_CERT_ADDR=$(awk '/method\._RawSecureSocket_.*\._onBadCertificateWrapper_/ { print $1; exit }' "$FUNCS")
REGISTER_ADDR=$(awk '/method\._SecureFilterImpl_.*\.registerBadCertificateCallback$/ { print $1; exit }' "$FUNCS")
REGISTER_IMPL_ADDR=$(awk '/method\._SecureFilterImpl_.*\._registerBadCertificateCallback_/ { print $1; exit }' "$FUNCS")
HANDSHAKE_ADDR=$(awk '/method\._RawSecureSocket_.*\._secureHandshake_/ { print $1; exit }' "$FUNCS")
MARK_TRUSTED_ADDR=$(awk '/method\._SecureFilterImpl_.*\._markAsTrusted_/ { print $1; exit }' "$FUNCS")

printf 'wrapper=%s register=%s register_impl=%s handshake=%s mark=%s\n' \
  "$BAD_CERT_ADDR" "$REGISTER_ADDR" "$REGISTER_IMPL_ADDR" "$HANDSHAKE_ADDR" "$MARK_TRUSTED_ADDR"
rm -f "$FUNCS"
```

Expected output:

```text
wrapper=0x3199d4 register=0x3194ec register_impl=0x31954c handshake=0x31749c mark=0x31925c
```

Apply r2flutter flags in r2 and confirm that the same method flags exist:

```sh
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'r2flutter -A' \
  -c 'f~onBadCertificateWrapper' \
  -c 'f~registerBadCertificateCallback' \
  -c 'f~secureHandshake' \
  -c q "$IOS_APP"
```

Expected method flags:

```text
0x003199d4 0 method._RawSecureSocket_14069316._onBadCertificateWrapper_14069316
0x003194ec 0 method._SecureFilterImpl_14069316.registerBadCertificateCallback
0x0031954c 0 method._SecureFilterImpl_14069316._registerBadCertificateCallback_14069316
0x0031749c 0 method._RawSecureSocket_14069316._secureHandshake_14069316
```

Now disassemble the handshake:

```sh
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'r2flutter -A' \
  -c "s ${HANDSHAKE_ADDR:-0x31749c}" \
  -c 'pd 104' \
  -c q "$IOS_APP"
```

Useful lines:

```asm
0x003174e4  bl method._SecureFilterImpl_14069316.handshake
0x00317514  bl method._RawSecureSocket_14069316._secureHandshake_14069316
0x0031752c  add x1, x22, 0x30
0x0031753c  bl method._RawSecureSocket_14069316._readSocket_14069316
0x00317548  bl method._RawSecureSocket_14069316._writeSocket_14069316
0x00317554  bl method._RawSecureSocket_14069316._scheduleFilter_14069316
0x00317588  bl method._RawSecureSocket_14069316._reportError_14069316
0x003175ac  add x0, x22, 0x20
```

The boolean constants are visible in this cluster:

- `x22 + 0x20` is Dart `true`.
- `x22 + 0x30` is Dart `false`.

## Challenge 2: patch `_RawSecureSocket._onBadCertificateWrapper`

Disassemble the wrapper:

```sh
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'r2flutter -A' \
  -c "s ${BAD_CERT_ADDR:-0x3199d4}" \
  -c 'pd 24' \
  -c q "$IOS_APP"
```

Important instructions:

```asm
0x003199d4  stp x29, x30, [x15, -0x10]!
0x003199ec  ldr x0, [x29, 0x18]
0x003199f0  ldur x1, [x0, 0x5f]
0x003199f4  cmp x1, x22
0x003199f8  b.eq 0x319a28
0x00319a00  stp x16, x1, [x15]
0x00319a0c  ldur x2, [x0, 0x37]
0x00319a10  blr x2
0x00319a1c  ret
```

AuthPass differs from the Android samples: on the normal path the wrapper
returns the app-provided bad-certificate callback result unchanged. The bypass
target is still the wrapper entry. Returning Dart `true` before the callback
logic makes the certificate decision succeed.

For this fixture, `rabin2 -S "$IOS_APP"` reports equal `__text` physical and
virtual addresses:

```sh
rabin2 -S "$IOS_APP" | rg '__TEXT.__text'
```

Expected:

```text
0   0x00005a80  0x6f8bd0 0x00005a80  0x6f8bd0 -r-x 0x0   REGULAR  0.__TEXT.__text
```

That means the recovered method virtual address is also the raw file offset for
this fixture. If this is not true for another Mach-O, translate with:

```text
section_paddr + (method_vaddr - section_vaddr)
```

Patch a copy first:

```sh
cp "$IOS_APP" "$IOS_APP.bak"

r2 -q -w -n -e scr.color=0 \
  -c "s ${BAD_CERT_ADDR:-0x3199d4}" \
  -c 'wx c0820091c0035fd6' \
  -c q "$IOS_APP"
```

Patch bytes:

```text
c0820091 c0035fd6
```

Decoded AArch64:

```asm
add x0, x22, 0x20
ret
```

Verify:

```sh
r2 -q -n -a arm -b 64 -e scr.color=0 \
  -c "s ${BAD_CERT_ADDR:-0x3199d4}" \
  -c 'p8 8' \
  -c 'pd 2' \
  -c q "$IOS_APP"
```

Expected:

```text
c0820091c0035fd6
add x0, x22, 0x20
ret
```

Restore the fixture after testing:

```sh
cp "$IOS_APP.bak" "$IOS_APP"
```

You can also use the generic qjs helper on a copy:

```sh
TMP_APP=$(mktemp /tmp/r2flutter-authpass-app.XXXXXX)
cp "$IOS_APP" "$TMP_APP"
r2 -q -w -e bin.relocs.apply=true \
  -i scripts/dart_cert_bypass.qjs \
  "$TMP_APP"
r2 -q -n -a arm -b 64 -e scr.color=0 \
  -c 's 0x3199d4' \
  -c 'p8 8' \
  -c 'pd 2' \
  -c q "$TMP_APP"
rm -f "$TMP_APP"
```

The script resolves `method._RawSecureSocket_*._onBadCertificateWrapper_*`
through r2flutter flags, translates the method address to a file offset using
section metadata, and writes the same two AArch64 instructions. It expects the
actual Dart image to be opened in r2: Android `libapp.so` or iOS
`Frameworks/App.framework/App`.

## Challenge 3: trace callback registration and direct xrefs

Disassemble callback registration:

```sh
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'r2flutter -A' \
  -c "s ${REGISTER_ADDR:-0x3194ec}" \
  -c 'pd 44' \
  -c q "$IOS_APP"
```

Useful lines:

```asm
0x0031950c  stur x0, [x1, 0xf]
0x00319530  bl method._SecureFilterImpl_14069316._registerBadCertificateCallback_14069316
0x00319534  mov x0, x22
0x00319540  ret
```

Run lightweight reference analysis and query the resolved TLS addresses:

```sh
r2 -q -e scr.color=0 -e bin.relocs.apply=true \
  -c 'r2flutter -A' \
  -c 'aar' \
  -c "axt @ ${BAD_CERT_ADDR:-0x3199d4}" \
  -c "axt @ ${REGISTER_ADDR:-0x3194ec}" \
  -c "axt @ ${REGISTER_IMPL_ADDR:-0x31954c}" \
  -c "axt @ ${HANDSHAKE_ADDR:-0x31749c}" \
  -c q "$IOS_APP"
```

Observed direct xrefs:

```text
0x3199bc -> 0x3199d4  _RawSecureSocket._anon_closure -> _onBadCertificateWrapper
0x316cd8 -> 0x3194ec  _RawSecureSocket constructor -> registerBadCertificateCallback
0x319530 -> 0x31954c  registerBadCertificateCallback -> _registerBadCertificateCallback
0x317028 -> 0x31749c  _RawSecureSocket constructor -> _secureHandshake
0x317514 -> 0x31749c  _secureHandshake -> _secureHandshake
0x3178b4 -> 0x31749c  _tryFilter -> _secureHandshake
0x317e04 -> 0x31749c  _closeHandler -> _secureHandshake
```

The call into the app-provided certificate callback inside the wrapper is
indirect (`blr x2`), so it is not expected to produce a stable direct `axt`
target. The stable evidence is the callback registration, the wrapper body, the
TLS method cluster, and the direct references to the wrapper.

## Regression tests

The tutorial workflow is covered by:

```sh
r2r -u test/db/cmd/authpass-r2-tutorial
```

The tests validate:

- r2 plugin flag recovery for the AuthPass TLS methods.
- wrapper and handshake disassembly landmarks.
- direct xref/callsite sources without running full analysis in the test.
- the generic qjs bypass script on a temporary copy.

Patching the embedded iOS framework invalidates the bundle code signature. A
real deployment requires re-signing with the appropriate identity/provisioning
workflow.
