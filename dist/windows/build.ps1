$ErrorActionPreference = 'Stop'

meson setup build-windows --buildtype=release
meson compile -C build-windows

$root = 'dist/windows/r2flutter-windows-x86_64'
$archive = 'dist/windows/r2flutter-windows-x86_64.zip'
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
Remove-Item -Force $archive -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root/bin | Out-Null
New-Item -ItemType Directory -Force $root/plugins | Out-Null
Copy-Item build-windows/r2flutter.exe $root/bin/
Copy-Item build-windows/core_flutter.dll $root/plugins/
Copy-Item dist/README.md $root/
Compress-Archive -Path $root -DestinationPath $archive -Force
