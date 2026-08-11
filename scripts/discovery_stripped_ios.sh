#!/bin/sh
# Strip the iOS Runner App snapshot and verify structural instruction
# discovery still works without symbols. Run from the test/ directory.
A=bins/ios/Runner.app/Frameworks/App.framework/App
T=$(mktemp)
if python3 ../scripts/strip_macho_symbols.py "$A" "$T" > /dev/null 2>&1; then
	printf "kdart=%s\n" "$(r2 -qc "is~kDart" "$T" 2> /dev/null | grep -c kDart)"
	../bin/r2flutter -q -H "$T" 2> /dev/null | grep -oE "vm_instr=\S+ iso_data=\S+ iso_instr=\S+"
fi
rm -f "$T"
