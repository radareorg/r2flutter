$ErrorActionPreference = 'Stop'

meson setup build-windows --buildtype=release
meson compile -C build-windows

$r2v = if ($env:R2V) { $env:R2V } else { (r2 -qv).Trim() }
$root = 'build-windows/bindist'
$archive = "r2flutter-$r2v-windows-x86-64.zip"
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
Remove-Item -Force $archive -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root/bin,$root/plugins | Out-Null
Copy-Item build-windows/r2flutter.exe $root/bin/
Copy-Item build-windows/core_flutter.dll $root/plugins/
Copy-Item dist/README.md $root/
Compress-Archive -Path $root/* -DestinationPath $archive -Force
