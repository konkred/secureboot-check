<#
.SYNOPSIS
    Prueft die Windows-11-Voraussetzungen (6_Windows11_Voraussetzungen_pruefen.cmd). Aendert nichts.

.DESCRIPTION
    Bewertet Prozessor, Arbeitsspeicher, Systemdatentraeger, Grafik, TPM und Secure Boot:
      gruen = offiziell erfuellt, gelb = laeuft, aber nicht offiziell oder knapp, rot = geht nicht.
    Ergebnis zusaetzlich in Win11_Uebersicht.csv (eine Zeile pro Lauf).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Win11Check.ps1
#>
[CmdletBinding()]
param([switch]$NoPause)
$scriptDir = Split-Path -Parent $PSCommandPath
. (Join-Path $scriptDir 'SecureBootCommon.ps1')
Assert-Admin $PSCommandPath $PSBoundParameters
$ErrorActionPreference = 'Continue'
Initialize-Tool 'Win11Check'

function New-Rating([string]$Level, [string]$Text) { [pscustomobject]@{ Level = $Level; Text = $Text } }

# ================================================================ Bewertungen (ohne Systemzugriff, testbar)
function Test-CpuOfficial([string]$Name) {
    # $true = steht auf Microsofts Liste, $false = sicher nicht, $null = unbekannt
    $n = ($Name -replace '\((R|TM|tm)\)', '' -replace '\s+', ' ').Trim()
    if ($n -match 'Snapdragon|Microsoft SQ') { return $true }
    if ($n -match 'Intel') {
        if ($n -match 'Core Ultra|Core [3579] \d{3}') { return $true }
        if ($n -match '\bi[3579]-N\d{3}|Intel Processor N\d{2,3}\b|\bN(50|97|100|150|200|250|300|350)\b') { return $true }
        if ($n -match '\bi[3579]-(\d{3,5})([A-Z]*)') {
            $num = $Matches[1]; $suf = $Matches[2]
            $gen = if ($num.Length -eq 3) { 1 } elseif ($num.Length -eq 5 -or $num[0] -eq '1') { [int]$num.Substring(0, 2) } else { [int]"$($num[0])" }
            if ($gen -ge 8) { return $true }
            if ($gen -eq 7 -and ($num -eq '7820' -and $suf -eq 'HQ' -or $suf -match '^X')) { return $true }
            return $false
        }
        if ($n -match 'Xeon') {
            if ($n -match 'E-2\d{3}|W-(2[2-9]|3[2-9])\d{2}|W-1[2-9]\d{2}|\bw[3579]-\d{4}|Xeon 6\d{3}') { return $true }
            if ($n -match '(Bronze|Silver|Gold|Platinum) \d(\d)\d{2}') { return ([int]$Matches[2] -ge 2) }
            if ($n -match 'E3-|E5-|E7-|W-[23]1\d{2}|X\d{4}|W\d{4}|L\d{4}|E\d{4}') { return $false }
            return $null
        }
        if ($n -match 'Pentium') {
            if ($n -match 'Silver') { return $true }
            if ($n -match 'Gold [A-Z]?(\d{4})') { return ([int]$Matches[1] -ge 5000) }
            return $false
        }
        if ($n -match 'Celeron') {
            if ($n -match '\bG(\d{4})') { return ([int]$Matches[1] -ge 4900) }
            if ($n -match '\b[A-Z]?(\d{4})') { return ([int]$Matches[1] -ge 4000) }
            return $false
        }
        if ($n -match 'Atom') { return [bool]($n -match 'x6\d{3}') }
        if ($n -match 'Core ?2|Core Duo|Core Solo|\bi[3579] CPU \d{3}\b') { return $false }
        return $null
    }
    if ($n -match 'AMD') {
        if ($n -match 'Ryzen AI|Ryzen Z\d') { return $true }
        if ($n -match 'Threadripper (PRO )?(\d)\d{3}') { return ([int]$Matches[2] -ge 2) }
        if ($n -match 'Ryzen [3579] (PRO )?(\d)\d{3}') { return ([int]$Matches[2] -ge 2) }
        if ($n -match 'EPYC \d{3}(\d)') { return ([int]$Matches[1] -ge 2) }
        if ($n -match 'Athlon (Gold|Silver)') { return $true }
        if ($n -match 'Athlon (PRO )?(\d{3,4})') { $v = [int]$Matches[2]; return ($v -ge 3000 -or ($v -ge 300 -and $v -lt 1000)) }
        if ($n -match 'Phenom|Athlon|FX-|\bA\d{1,2}-|\bE\d?-\d|Opteron|Sempron|Turion') { return $false }
        return $null
    }
    $null
}

function Get-CpuRating([string]$Name, [bool]$Sse42, [bool]$Is64, [int]$Cores = 2, [int]$Mhz = 2000) {
    if (-not $Is64)  { return New-Rating 'Bad' 'kein 64-Bit-Prozessor, Windows 11 gibt es nur mit 64 Bit' }
    if (-not $Sse42) { return New-Rating 'Bad' 'ohne SSE4.2/POPCNT: Windows 11 ab 24H2 startet nicht mehr, aeltere Versionen bekommen keine Updates' }
    if ($Cores -lt 2 -or $Mhz -lt 1000) { return New-Rating 'Bad' ("zu schwach ({0} Kern(e), {1} MHz), Windows 11 braucht 2 Kerne und 1 GHz" -f $Cores, $Mhz) }
    $off = Test-CpuOfficial $Name
    if ($off -eq $true)  { return New-Rating 'Ok' 'offiziell unterstuetzt' }
    if ($off -eq $false) { return New-Rating 'Warn' 'laeuft, ist aber nicht offiziell unterstuetzt' }
    New-Rating 'Warn' 'nicht in der eingebauten Liste, bitte bei Microsoft pruefen ("Windows 11 supported processors")'
}

function Get-RamRating([double]$Gb) {
    if ($Gb -lt 3.5) { return New-Rating 'Bad' ("{0:N0} GB, Windows 11 braucht mindestens 4 GB" -f $Gb) }
    if ($Gb -le 8.5) { return New-Rating 'Warn' ("{0:N0} GB, reicht, mehr als 8 GB waeren angenehmer" -f $Gb) }
    New-Rating 'Ok' ("{0:N0} GB" -f $Gb)
}

function Get-DiskRating([double]$Gb, [string]$Media) {
    $t = "{0:N0} GB, {1}" -f $Gb, $(if ($Media) { $Media } else { 'Typ unbekannt' })
    if ($Gb -lt 64)        { return New-Rating 'Bad' "$t, Windows 11 braucht mindestens 64 GB" }
    if ($Media -eq 'HDD')  { return New-Rating 'Warn' "$t, eine SSD waere deutlich schneller" }
    if ($Gb -lt 128)       { return New-Rating 'Warn' "$t, knapp fuer Updates (128 GB empfohlen)" }
    if ($Media -ne 'SSD')  { return New-Rating 'Warn' "$t, SSD oder HDD nicht erkennbar" }
    New-Rating 'Ok' $t
}

function Get-WddmFromDriverVersion([string]$Version) {
    # Erstes Feld der Treiberversion: 20 = WDDM 2.0, 21 = 2.1, ... 30 = 3.0, 31 = 3.1. Darunter WDDM 1.x.
    if ($Version -notmatch '^(\d+)\.') { return $null }
    $f = [int]$Matches[1]
    if ($f -ge 30) { return [double]("3.{0}" -f ($f - 30)) }
    if ($f -ge 20) { return [double]("2.{0}" -f ($f - 20)) }
    if ($f -ge 6)  { return 1.0 }
    $null
}

function Get-MaxFeatureLevel([string]$List) {
    # "12_1,12_0,11_1" -> 12.1
    $best = $null
    foreach ($x in ($List -split '[,;\s]+')) { if ($x -match '^(\d+)_(\d+)$') { $v = [double]("{0}.{1}" -f $Matches[1], $Matches[2]); if ($null -eq $best -or $v -gt $best) { $best = $v } } }
    $best
}

function Get-GpuRating([string]$Name, $Wddm, $FeatureLevel) {
    if ($Name -match 'Basic Display|Basic Render|Standard-VGA|Standard VGA') { return New-Rating 'Warn' 'kein Grafiktreiber installiert, erst den Treiber des Herstellers installieren' }
    if ($null -eq $Wddm -and $null -eq $FeatureLevel) { return New-Rating 'Warn' 'Treibermodell nicht erkennbar' }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $fl = if ($null -ne $FeatureLevel) { ', DirectX Feature Level ' + ([double]$FeatureLevel).ToString('0.0', $inv).Replace('.', '_') } else { '' }
    $wd = if ($null -ne $Wddm) { 'WDDM ' + ([double]$Wddm).ToString('0.0', $inv) } else { 'WDDM ?' }
    if ($null -ne $Wddm -and $Wddm -lt 2.0) { return New-Rating 'Bad' "$wd$fl, Windows 11 braucht WDDM 2.0 und DirectX 12" }
    if ($null -ne $FeatureLevel -and $FeatureLevel -lt 11.0) { return New-Rating 'Bad' "$wd$fl, zu alt fuer DirectX 12" }
    if ($null -eq $Wddm) { return New-Rating 'Warn' "$wd$fl" }
    New-Rating 'Ok' "$wd$fl"
}

function Get-TpmRating([string]$Spec, $Enabled) {
    if (-not $Spec) { return New-Rating 'Bad' 'kein TPM gefunden. Im BIOS nach "PTT" (Intel) bzw. "fTPM" (AMD) oder "TPM" suchen und einschalten' }
    $major = if ($Spec -match '^\s*(\d+)\.(\d+)') { [double]("{0}.{1}" -f $Matches[1], $Matches[2]) } else { 0 }
    if ($major -ge 2.0) {
        if ($Enabled -eq $false) { return New-Rating 'Warn' "TPM $Spec vorhanden, aber deaktiviert: im BIOS einschalten" }
        return New-Rating 'Ok' "TPM $Spec"
    }
    New-Rating 'Warn' "TPM $Spec, nicht offiziell. Manche PCs (z.B. HP, Dell, Lenovo) lassen sich per Firmware-Update auf TPM 2.0 umstellen"
}

function Get-SbRating($Uefi, $On, [bool]$Kek23, [bool]$Win23) {
    if ($Uefi -ne $true) { return New-Rating 'Bad' 'Legacy-Start ohne UEFI. Windows 11 braucht UEFI: Datentraeger mit MBR2GPT umstellen, im BIOS auf UEFI und Secure Boot an' }
    if ($On -ne $true)   { return New-Rating 'Bad' 'Secure Boot ist aus: im Firmware-Setup einschalten' }
    if ($Kek23 -and $Win23) { return New-Rating 'Ok' 'an, Zertifikate 2023 vorhanden' }
    New-Rating 'Warn' 'an, aber noch mit den Zertifikaten von 2011 (laufen 2026 ab): 1_Pruefen.cmd, dann 2_Update_anstossen.cmd bzw. 3_Zertifikate_einspielen.cmd'
}

function Get-Summary($Ratings) {
    # $Ratings: geordnete Hashtable Bereich -> Bewertung
    $bad  = @($Ratings.Keys | Where-Object { $Ratings[$_].Level -eq 'Bad' })
    $warn = @($Ratings.Keys | Where-Object { $Ratings[$_].Level -eq 'Warn' })
    if ($bad -contains 'CPU' -and $Ratings['CPU'].Text -match 'SSE4|64-Bit') { return New-Rating 'Bad' 'Windows 11 (ab 24H2) laeuft auf diesem PC nicht: der Prozessor ist zu alt.' }
    if ($bad.Count)  { return New-Rating 'Bad' ("Windows 11 so nicht moeglich. Erst beheben: {0}" -f ($bad -join ', ')) }
    if ($warn.Count) { return New-Rating 'Warn' ("Windows 11 laeuft, aber nicht alles ist offiziell oder optimal: {0}" -f ($warn -join ', ')) }
    New-Rating 'Ok' 'Windows 11 ist offiziell moeglich.'
}

# ================================================================ Daten sammeln
Section "System"
$sys = Show-SystemInfo
$ratings = [ordered]@{}

Section "Prozessor"
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$cpuName = "$($cpu.Name)".Trim()
if (-not ('SbTool.Win11Probe' -as [type])) {
    Add-Type -Namespace 'SbTool' -Name 'Win11Probe' -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(uint f);' -ErrorAction SilentlyContinue
}
$isArm = $env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64'
$is64  = [Environment]::Is64BitOperatingSystem -or $cpu.AddressWidth -eq 64 -or $cpu.DataWidth -eq 64
$sse42 = $isArm -or [SbTool.Win11Probe]::IsProcessorFeaturePresent(38)
Info ("{0}" -f $cpuName)
Info ("{0} Kerne / {1} Threads, {2} MHz, SSE4.2: {3}" -f $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors, $cpu.MaxClockSpeed, $(if ($sse42) { 'ja' } else { 'nein' }))
if (-not [Environment]::Is64BitOperatingSystem -and $is64) { Info "Windows ist 32 Bit, der Prozessor kann 64 Bit (Neuinstallation noetig)" }
$ratings['CPU'] = Get-CpuRating $cpuName $sse42 $is64 ([int]$cpu.NumberOfCores) ([int]$cpu.MaxClockSpeed)
Show-Level $ratings['CPU'].Level ("CPU: " + $ratings['CPU'].Text)

Section "Arbeitsspeicher"
$ramBytes = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum
if (-not $ramBytes) { $ramBytes = $sys.Cs.TotalPhysicalMemory }
$ramGb = [double]$ramBytes / 1GB
$ratings['RAM'] = Get-RamRating $ramGb
Show-Level $ratings['RAM'].Level ("RAM: " + $ratings['RAM'].Text)

Section "Systemdatentraeger"
$diskGb = 0; $media = ''; $style = ''; $freeGb = 0
try {
    $letter = $env:SystemDrive.TrimEnd(':')
    $part = Get-Partition -DriveLetter $letter -ErrorAction Stop
    $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    $diskGb = [double]$disk.Size / 1GB; $style = "$($disk.PartitionStyle)"
    $pd = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { "$($_.DeviceId)" -eq "$($part.DiskNumber)" } | Select-Object -First 1
    if ($pd) {
        if     ("$($pd.MediaType)" -eq 'SSD' -or "$($pd.MediaType)" -eq 'SCM') { $media = 'SSD' }
        elseif ("$($pd.MediaType)" -eq 'HDD') { $media = 'HDD' }
        elseif ("$($pd.BusType)" -eq 'NVMe' -or $pd.SpindleSpeed -eq 0) { $media = 'SSD' }
        elseif ($pd.SpindleSpeed -gt 0 -and $pd.SpindleSpeed -lt 100000) { $media = 'HDD' }
        Info ("{0}  ({1}, {2})" -f "$($pd.FriendlyName)".Trim(), $pd.BusType, $pd.MediaType)
    } else { Info ("{0}" -f "$($disk.FriendlyName)".Trim()) }
    $vol = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
    if ($vol) { $freeGb = [double]$vol.SizeRemaining / 1GB; Info ("{0} frei: {1:N0} GB" -f $env:SystemDrive, $freeGb) }
} catch { Warn "Datentraeger nicht lesbar: $_" }
$ratings['Festplatte'] = Get-DiskRating $diskGb $media
Show-Level $ratings['Festplatte'].Level ("Festplatte: " + $ratings['Festplatte'].Text)
if ($style -eq 'MBR') { Warn "Partitionsstil MBR: fuer UEFI und Secure Boot vorher mit MBR2GPT auf GPT umstellen" }
elseif ($style) { Info "Partitionsstil: $style" }
if ($freeGb -gt 0 -and $freeGb -lt 20) { Warn ("Nur {0:N0} GB frei, fuer ein Funktionsupdate besser 20 GB oder mehr" -f $freeGb) }

Section "Grafik"
Info "Lese DirectX-Daten (dxdiag, dauert einige Sekunden) ..."
$gpus = @()
$xml = Join-Path $env:TEMP ("dxdiag_{0}.xml" -f $PID)
try {
    $pr = Start-Process dxdiag.exe -ArgumentList '/whql:off', "/x `"$xml`"" -PassThru -WindowStyle Hidden
    if (-not $pr.WaitForExit(90000)) { try { $pr.Kill() } catch {} }
    for ($i = 0; $i -lt 20 -and -not (Test-Path $xml); $i++) { Start-Sleep -Milliseconds 500 }
    if (Test-Path $xml) {
        [xml]$dx = Get-Content $xml -Raw
        foreach ($d in @($dx.DxDiag.DisplayDevices.DisplayDevice)) {
            $wd = if ("$($d.DriverModel)" -match '(\d+\.\d+)') { [double]$Matches[1] } else { Get-WddmFromDriverVersion "$($d.DriverVersion)" }
            $gpus += [pscustomobject]@{ Name = "$($d.CardName)".Trim(); Wddm = $wd; Fl = (Get-MaxFeatureLevel "$($d.FeatureLevels)") }
        }
    }
} catch { Info "dxdiag nicht auswertbar: $_" }
finally { Remove-Item $xml -Force -ErrorAction SilentlyContinue }
if ($gpus.Count -eq 0) {
    foreach ($v in @(Get-CimInstance Win32_VideoController)) { $gpus += [pscustomobject]@{ Name = "$($v.Name)".Trim(); Wddm = (Get-WddmFromDriverVersion "$($v.DriverVersion)"); Fl = $null } }
}
$best = $null
foreach ($g in $gpus) {
    $r = Get-GpuRating $g.Name $g.Wddm $g.Fl
    Show-Level $r.Level ("{0}: {1}" -f $g.Name, $r.Text)
    $rank = @{ Ok = 3; Warn = 2; Bad = 1 }[$r.Level]
    if (-not $best -or $rank -gt $best.Rank) { $best = [pscustomobject]@{ Rank = $rank; R = $r; Name = $g.Name } }
}
$ratings['Grafik'] = if ($best) { $best.R } else { New-Rating 'Warn' 'keine Grafikkarte gefunden' }
$gpuName = if ($best) { $best.Name } else { '' }

Section "TPM"
$tpm = $null
try { $tpm = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1 } catch {}
$tpmSpec = if ($tpm) { ("$($tpm.SpecVersion)" -split ',')[0].Trim() } else { '' }
$tpmOn = if ($tpm) { [bool]$tpm.IsEnabled_InitialValue } else { $null }
if ($tpm) { Info ("Hersteller-ID {0}, Version {1}, aktiv: {2}" -f $tpm.ManufacturerIdTxt, $tpm.SpecVersion, $(if ($tpmOn) { 'ja' } else { 'nein' })) }
$ratings['TPM'] = Get-TpmRating $tpmSpec $tpmOn
Show-Level $ratings['TPM'].Level ("TPM: " + $ratings['TPM'].Text)

Section "Secure Boot"
$sbOn = $null; try { $sbOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch {}
$uefi = ($null -ne $sbOn)
$kek23 = [bool]((Parse-Esl (Get-VarBytes 'KEK')).Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' })
$win23 = [bool]((Parse-Esl (Get-VarBytes 'db')).Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })
Info ("UEFI: {0}, Secure Boot: {1}, KEK 2023: {2}, Windows UEFI CA 2023: {3}" -f $(if ($uefi) { 'ja' } else { 'nein' }), $(if ($sbOn) { 'an' } else { 'aus' }), $(if ($kek23) { 'ja' } else { 'nein' }), $(if ($win23) { 'ja' } else { 'nein' }))
$ratings['Secure Boot'] = Get-SbRating $uefi $sbOn $kek23 $win23
Show-Level $ratings['Secure Boot'].Level ("Secure Boot: " + $ratings['Secure Boot'].Text)

# ================================================================ Ergebnis
Section "ERGEBNIS fuer $env:COMPUTERNAME ($($sys.Model))"
foreach ($k in $ratings.Keys) { Show-Level $ratings[$k].Level ("{0,-12} {1}" -f $k, $ratings[$k].Text) }
Write-Host ""
$sum = Get-Summary $ratings
Show-Level $sum.Level $sum.Text
if ($sum.Level -eq 'Warn' -and ($ratings['CPU'].Level -eq 'Warn' -or $ratings['TPM'].Level -eq 'Warn') -and $tpmSpec) {
    Info "Nicht unterstuetzter Prozessor oder TPM 1.2: Microsoft dokumentiert dafuer den Registry-Wert"
    Info "  HKLM\SYSTEM\Setup\MoSetup  AllowUpgradesWithUnsupportedTPMOrCPU = 1 (DWORD)."
    Info "Das Upgrade laeuft dann, Microsoft sagt aber keine Updates zu. Ohne TPM geht das nicht."
}
if ([int]$sys.Cv.CurrentBuildNumber -ge 22000) { Info ("Auf diesem PC laeuft bereits {0}." -f $sys.Windows) }

function Color([string]$l) { switch ($l) { 'Ok' { 'gruen' } 'Warn' { 'gelb' } 'Bad' { 'rot' } default { '?' } } }
Add-CsvLine 'Win11_Uebersicht.csv' 'Datum;Hostname;Seriennummer;Hersteller;Modell;Windows;Skriptversion;CPU;CPU-Bewertung;RAM-GB;RAM-Bewertung;Datentraeger-GB;Datentraeger-Typ;Datentraeger-Bewertung;Grafik;Grafik-Bewertung;TPM;TPM-Bewertung;SecureBoot-Bewertung;Ergebnis' @(
    (Get-Date -Format 'yyyy-MM-dd HH:mm'), $env:COMPUTERNAME, $serial, $sys.Cs.Manufacturer, $sys.Cs.Model, $sys.Windows, $ToolVersion,
    $cpuName, (Color $ratings['CPU'].Level), [math]::Round($ramGb), (Color $ratings['RAM'].Level),
    [math]::Round($diskGb), $media, (Color $ratings['Festplatte'].Level), $gpuName, (Color $ratings['Grafik'].Level),
    $tpmSpec, (Color $ratings['TPM'].Level), (Color $ratings['Secure Boot'].Level), (Color $sum.Level))
Write-Host ""
Write-Host "         Win11_Uebersicht.csv ergaenzt" -ForegroundColor DarkGray
Finish
