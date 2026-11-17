<#
    Collect-Fixtures.ps1 - Sammelt echte Testdaten dieses PCs fuer tests\Run-Tests.ps1.

    Kopiert C:\Windows\System32\SecureBootUpdates\*.bin und liest PK, KEK, db, dbx aus
    nach tests\fixtures\<PC>_<Build>\. Es wird nichts in die Firmware geschrieben.
    Die Microsoft-Dateien gehoeren nicht ins Repository (tests\fixtures ist in .gitignore).
#>
param([switch]$NoPause)

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($NoPause) { $argList += '-NoPause' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$build = [Environment]::OSVersion.Version.Build
try { $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop).UBR; $build = "$build.$ubr" } catch {}
$dest = Join-Path (Join-Path (Split-Path -Parent $PSCommandPath) 'fixtures') ("{0}_{1}" -f $env:COMPUTERNAME, $build)
$upd  = Join-Path $dest 'SecureBootUpdates'
$vars = Join-Path $dest 'Variablen'
New-Item -ItemType Directory -Path $upd, $vars -Force | Out-Null

$src = Join-Path $env:windir 'System32\SecureBootUpdates'
$n = 0
foreach ($f in @(Get-ChildItem $src -Filter *.bin -ErrorAction SilentlyContinue)) { Copy-Item $f.FullName $upd -Force; $n++ }
Write-Host ("{0} Dateien aus {1} kopiert" -f $n, $src)

foreach ($v in 'PK','KEK','db','dbx') {
    try {
        $b = (Get-SecureBootUEFI -Name $v -ErrorAction Stop).Bytes
        if ($b) { [IO.File]::WriteAllBytes((Join-Path $vars "$v.bin"), $b); Write-Host ("{0,-4} {1} Bytes" -f $v, $b.Length) }
        else    { Write-Host "$v leer" }
    } catch { Write-Host "$v nicht lesbar: $($_.Exception.Message)" }
}
Write-Host ""
Write-Host "Gespeichert in $dest"
Write-Host "Jetzt Tests_ausfuehren.cmd starten."
if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }
