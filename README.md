# Secure-Boot-Zertifikate 2011 → 2023 – Werkzeugkasten

Die Microsoft-Secure-Boot-Zertifikate von 2011 laufen 2026 ab. Diese Skripte prüfen den Stand
eines PCs, stoßen das Windows-Update an, tragen die 2023-Zertifikate bei Bedarf von Hand ein
und bauen KEK/db/dbx notfalls über den Setup Mode neu auf.

- Windows 10/11 (aktuelle Updates) mit UEFI und Secure Boot
- herstellerunabhängig: HP, Dell, Lenovo, Fujitsu, Surface, Chromebox/MrChromebox, Eigenbau, Hyper-V, VMware …
- alle `.cmd`-Dateien per Doppelklick starten, sie fragen selbst nach Adminrechten
- vom USB-Stick aus: vor dem Abziehen **„sicher entfernen“**

> Die Textfassung für den Stick ist [`LIESMICH.txt`](LIESMICH.txt) (gleicher Inhalt, ohne Umlaute).

## Kurzanleitung (bewährter Ablauf)

| Schritt | Datei | Zweck |
|---|---|---|
| 1 | `1_Pruefen.cmd` | Ist-Stand ansehen. Alles grün? → fertig. |
| 2 | `4_Manuell_einspielen.cmd` | 2023-CAs von Hand in die db (jede Frage mit `JA`). |
|   | bzw. `5_Manuell_mit_dbx.cmd` | … wenn 1_ „Sperrliste praktisch LEER“ meldet. |
| 3 | `2_Update_anstossen.cmd` | Windows installiert den 2023-Boot-Manager (und den KEK 2023, falls der Hersteller ihn liefert). |
| 4 | Neustart, dann `1_Pruefen.cmd` | Kontrolle |

- **DBX nachträglich:** `5_Manuell_mit_dbx.cmd`, neu starten, `1_Pruefen.cmd`
- **KEK 2023 fehlt danach noch?** Optional `6_Schluessel_neu_aufbauen.cmd` (siehe unten).
  Ohne KEK 2023 bootet der PC trotzdem normal.

Dasselbe von Hand in einer Admin-PowerShell im Skript-Ordner:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute -IncludeDbx
powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1 -Apply -Force
powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1
```

## ⚠️ Die wichtigste Regel

Nach dem Update im BIOS/UEFI die Secure-Boot-Schlüssel **nie löschen oder auf Werkseinstellung
zurücksetzen** – außer `1_Pruefen.cmd` meldet in Abschnitt 5b *„Werkseinstellungen enthalten die
Windows UEFI CA 2023“*.

**Notfall immer:** Secure Boot AUS → booten → `5_Manuell_mit_dbx.cmd` → Secure Boot AN.

## Die Dateien im Einzelnen

| Datei | Beschreibung |
|---|---|
| `1_Pruefen.cmd` | Liest alles aus, ändert **nichts**. Immer zuerst. |
| `2_Update_anstossen.cmd` | Normaler Weg: Windows spielt db, KEK und Boot-Manager selbst ein. |
| `3_Manuell_Trockenlauf.cmd` | Zeigt, was von Hand eingespielt würde. Ändert nichts. |
| `4_Manuell_einspielen.cmd` | Trägt die 2023-CAs **von Hand** in die db ein (umgeht Microsofts Sperre „Firmware_KI“ / Ereignis 1802). Jeder Schritt mit `JA`. |
| `5_Manuell_mit_dbx.cmd` | Wie 4, zusätzlich die Sperrliste (dbx), falls sie leer ist. |
| `6_Schluessel_neu_aufbauen.cmd` | **Experten:** baut KEK/db/dbx über den Setup Mode neu auf und setzt dabei auch den Microsoft KEK 2023. |

### Ablauf von `6_Schluessel_neu_aufbauen.cmd`

1. Erster Lauf bereitet vor.
2. Im Firmware-Setup die Schlüssel **löschen** („Clear Secure Boot Keys“).
3. Windows starten, zweiter Lauf schreibt alles zurück (Original-PK zuletzt).
4. Neu starten, dann `5_Manuell_mit_dbx.cmd`, `2_Update_anstossen.cmd` (→ Ereignis 1808), neu starten, `1_Pruefen.cmd`.

Eine PK-Fehlermeldung im zweiten Lauf ist bei HP normal – die Firmware stellt ihren PK beim
Neustart selbst wieder her.

### Ablage

Lokal in `C:\ProgramData\SecureBootCheck\` und als Kopie neben den Skripten:

| Ordner | Inhalt |
|---|---|
| `Logs\<PC-Name>\` | Protokolle aller Läufe |
| `Backups\<PC-Name>\` | Sicherungen von PK/KEK/db/dbx vor jedem manuellen Schreiben |
| `Rebuild\<PC-Name>\` | Daten für `6_Schluessel_neu_aufbauen` (zwischen den zwei Läufen) |

Diese Ordner enthalten gerätebezogene Daten und sind per `.gitignore` vom Repository ausgeschlossen.

## Erfahrungen (Stand 16.11.2026)

| Gerät | Ergebnis |
|---|---|
| HP ProDesk 400 G5 | Kurzanleitung + 6_ → alles 2023 (KEK, db, Boot-Manager, dbx). |
| HP EliteBook 840 G3 | Kurzanleitung + 6_ → alles 2023. |
| Chromebox (Google Teemo, MrChromebox-UEFI) | Nur `2_Update_anstossen.cmd` → alles 2023. Firmware bringt die 2023-Zertifikate schon mit, Schlüssel-Reset dort ungefährlich. Firmware-Setup: Esc beim Start. |
| HP Compaq Pro 6300 | db + Boot-Manager 2023 ok. KEK 2023 und dbx **nicht möglich**: Firmware lehnt dbx ab (`0xC0000022`), „Clear Secure Boot Keys“ lädt die Werksschlüssel statt Setup Mode → 6_ **nicht** benutzen. |
| Lenovo ThinkCentre M93 (10A4, BIOS FBKTE0AUS) | Kurzanleitung + 6_ → alles 2023. dbx-Anhängen lehnt die Firmware ab (`0xC0000022`), über 6_ klappt es. Der Original-PK wird angenommen, User Mode erst nach dem Neustart. |
| 10ZiG Thin Client | Kein Secure Boot → nicht betroffen. |

## Ziel – was „fertig“ heißt

- **Pflicht:** db hat „Windows UEFI CA 2023“ und der Boot-Manager kettet zur „Windows UEFI CA 2023“.
  Damit startet der PC auch nach Ablauf der 2011er-Zertifikate.
- **Kür:** KEK 2023 (für künftige db/dbx-Updates) und volle dbx (~300+ Einträge).
- Ein verbleibendes `AvailableUpdates = 0x4000` ist nur eine Bedingung, kein Fehler.

## Notfall (PC startet nach einem Schritt nicht)

Ins Firmware-Setup (BIOS/UEFI) und **Secure Boot ausschalten**. Das ist immer sicher.
`1_Pruefen.cmd` zeigt die Taste für den erkannten Hersteller an (HP: F10).
Booten, `5_Manuell_mit_dbx.cmd` (bzw. `4_`), Secure Boot wieder einschalten.

**Vorsicht mit „Schlüssel auf Werkseinstellung“:** Das entfernt die von Hand eingetragenen
2023-CAs wieder. Ist der Boot-Manager schon 2023-signiert, startet Windows danach mit Secure
Boot **nicht** mehr (roter Fehler beim Start). `1_Pruefen.cmd` warnt, wenn das zutrifft.
Die Sicherung der alten Schlüssel liegt in `Backups\<PC-Name>\`.

## Nie einspielen

`DBXUpdate2024*.bin` sperrt die alte „Windows Production PCA 2011“. Danach starten der alte
Boot-Manager und alle älteren Windows-/Rettungs-USB-Sticks nicht mehr.
Die Skripte überspringen diese Dateien immer.

## Haftung

Eingriffe in die Secure-Boot-Variablen können einen PC unbootbar machen. Benutzung auf eigene
Gefahr – vorher `1_Pruefen.cmd` und `3_Manuell_Trockenlauf.cmd` lesen.
