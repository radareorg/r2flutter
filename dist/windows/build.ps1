$ErrorActionPreference = 'Stop'

meson setup build-windows --buildtype=release
meson compile -C build-windows

$root = 'dist/windows/r2flutter-windows-x86_64'
$archive = 'dist/windows/r2flutter-windows-x86_64.zip'
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
Remove-Item -Force $archive -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root | Out-Null
Copy-Item build-windows/r2flutter.exe $root/
Compress-Archive -Path $root -DestinationPath $archive -Force
