# Secure Boot: Zertifikate von 2011 auf 2023 umstellen

Die Microsoft-Zertifikate, mit denen Secure Boot seit 2012 arbeitet, laufen 2026 ab. Windows soll
die Nachfolger von 2023 selbst einspielen, scheitert aber auf vielen älteren PCs an der Firmware
oder an einer Sperre von Microsoft. Diese Skripte zeigen, wo ein PC steht, stoßen das Windows-Update
an und tragen die neuen Zertifikate bei Bedarf von Hand ein.

Die Textfassung für den USB-Stick ist [`LIESMICH.txt`](LIESMICH.txt). Sie hat denselben Inhalt,
nur ohne Umlaute.

## Inhalt

1. [Hintergrund](#hintergrund)
2. [Voraussetzungen](#voraussetzungen)
3. [Schnellstart](#schnellstart)
4. [Die Werkzeuge im Detail](#die-werkzeuge-im-detail)
5. [Ergebnis prüfen](#ergebnis-prüfen)
6. [Notfall und Regeln](#notfall-und-regeln)
7. [Ablage der Protokolle und Sicherungen](#ablage-der-protokolle-und-sicherungen)
8. [Erfahrungen mit getesteten Geräten](#erfahrungen-mit-getesteten-geräten)
9. [Aufruf per PowerShell](#aufruf-per-powershell)
10. [Selbsttest](#selbsttest)
11. [Haftung](#haftung)

## Hintergrund

### Wie Secure Boot prüft

Beim Start prüft die UEFI-Firmware jede Datei, die sie lädt (Boot-Manager, Treiber von
Steckkarten), anhand von vier Variablen im Firmware-Speicher:

| Variable | Inhalt | Wer darf sie ändern |
|---|---|---|
| PK (Platform Key) | Schlüssel des Geräteherstellers, z.B. HP oder Lenovo | nur der Hersteller |
| KEK (Key Exchange Key) | Schlüssel, die db und dbx ändern dürfen, darunter Microsofts KEK | Inhaber des PK |
| db | erlaubte Zertifikate: was damit signiert ist, darf starten | Inhaber eines KEK |
| dbx | Sperrliste: bekannte unsichere Boot-Manager und Zertifikate | Inhaber eines KEK |

Eine Änderung an db oder dbx muss also mit einem Schlüssel aus dem KEK signiert sein. Eine Änderung
am KEK muss mit dem PK des Herstellers signiert sein.

### Was abläuft und was es ersetzt

| Zertifikat von 2011 | läuft ab | Nachfolger von 2023 | Zweck |
|---|---|---|---|
| Microsoft Corporation KEK CA 2011 | Juni 2026 | Microsoft Corporation KEK 2K CA 2023 | signiert Änderungen an db und dbx |
| Microsoft Windows Production PCA 2011 | Oktober 2026 | Windows UEFI CA 2023 | signiert den Windows-Boot-Manager |
| Microsoft Corporation UEFI CA 2011 | Juni 2026 | Microsoft UEFI CA 2023 | signiert Fremd-Bootloader, z.B. Linux |
| (dieselbe UEFI CA 2011) | | Microsoft Option ROM UEFI CA 2023 | signiert Firmware von Steckkarten |

Ein bereits eingerichteter PC startet nach dem Ablaufdatum in der Regel weiter, weil die Firmware
das Datum meist nicht prüft. Problematisch wird es bei allem, was neu dazukommt: Boot-Manager,
Installationsmedien und Sperrlisten-Updates, die nur noch mit den 2023-Zertifikaten signiert sind,
werden von einem PC ohne diese Zertifikate abgelehnt.

### Wie Windows das eigentlich selbst erledigt

Windows bringt die neuen Zertifikate als signierte Dateien in
`C:\Windows\System32\SecureBootUpdates\` mit. Der geplante Task `Secure-Boot-Update` spielt sie
ein, gesteuert über den Registry-Wert
`HKLM\SYSTEM\CurrentControlSet\Control\Secureboot\AvailableUpdates`:

| Bit | Aufgabe |
|---|---|
| `0x0040` | Windows UEFI CA 2023 in die db |
| `0x0800` | Microsoft UEFI CA 2023 in die db |
| `0x1000` | Option ROM UEFI CA 2023 in die db |
| `0x0004` | KEK 2023 eintragen |
| `0x0100` | Boot-Manager gegen die 2023-signierte Fassung tauschen |
| `0x4000` | Bedingung: Fremd-CAs nur, wenn die alte UEFI CA 2011 vorhanden ist |

Zusammen ergibt das `0x5944`. Erledigte Bits löscht Windows wieder. Auf vielen Geräten bleibt es
dabei aber hängen:

- **Microsoft sperrt das Modell** (Ereignis 1802, Grund `Firmware_KI_...`), weil bei diesem Modell
  Firmwarefehler bekannt sind. Dann passiert gar nichts.
- **Der KEK fehlt** (Ereignis 1803), weil Microsoft für dieses Modell keine vom Hersteller mit dem
  PK signierte KEK-Datei hat. Bei älteren Geräten liefern die Hersteller diese Datei oft nicht mehr.

Genau hier setzen die Skripte an.

## Voraussetzungen

- Windows 10 oder 11 mit aktuellen Updates, damit die Dateien in `SecureBootUpdates` vorhanden sind
- UEFI-Start mit eingeschaltetem Secure Boot
- herstellerunabhängig; getestet mit HP, Lenovo und Chromebox (MrChromebox), mit Hinweisen für Dell,
  Fujitsu, Surface, Acer, ASUS, MSI, Gigabyte, ASRock, Hyper-V und VMware
- alle `.cmd`-Dateien per Doppelklick starten, sie fordern selbst Administratorrechte an
- vom USB-Stick aus: den Stick vor dem Abziehen über „Hardware sicher entfernen“ abmelden, sonst
  fehlen Protokolle

## Schnellstart

Dieser Ablauf hat sich auf allen getesteten Geräten bewährt:

| Schritt | Datei | Was passiert |
|---|---|---|
| 1 | `1_Pruefen.cmd` | Ist-Stand ansehen. Ist alles grün, ist nichts zu tun. |
| 2 | `5_Manuell_mit_dbx.cmd` | 2023-Zertifikate und Sperrliste von Hand einspielen. Jede Änderung muss mit `JA` bestätigt werden. |
| 3 | `2_Update_anstossen.cmd` | Windows tauscht den Boot-Manager gegen die 2023-Fassung. |
| 4 | Neustart, dann `1_Pruefen.cmd` | Kontrolle |

Wird die Sperrliste in Schritt 2 abgelehnt, hilft eventuell `8_dbx_schrittweise.cmd`. Fehlt nach
Schritt 4 der KEK 2023 oder bleibt die Sperrliste leer, kommt optional
`6_Schluessel_neu_aufbauen.cmd` dazu (siehe unten). Ohne KEK 2023 startet der PC trotzdem normal.

## Die Werkzeuge im Detail

### `1_Pruefen.cmd`

Liest alles aus und ändert nichts. Die Abschnitte im Protokoll:

| Abschnitt | Inhalt |
|---|---|
| 1 | System: Modell, BIOS, Windows-Version, Seriennummer, Skriptversion, Taste fürs Firmware-Setup |
| 2 | Secure-Boot-Status: eingeschaltet, User Mode oder Setup Mode |
| 3 bis 6 | Inhalt von PK, KEK, db und dbx mit dem Ablaufdatum jedes Zertifikats. Jede Variable wird außerdem auf ein sauberes Format geprüft; ein unlesbarer Rest (wie beim Fehler in Version 1.1) wird rot gemeldet, mit dem passenden Rettungsweg. |
| 5b | Werkseinstellungen der Firmware (`dbDefault`). Fehlt dort die Windows UEFI CA 2023, ist ein Zurücksetzen der Schlüssel im BIOS nach dem Boot-Manager-Tausch gefährlich. |
| 7 | Boot-Manager auf der EFI-Partition: mit welchem Zertifikat er signiert ist. Dazu der Ausweich-Bootloader `\EFI\Boot\bootx64.efi` und die Booteinträge der Firmware. Ist der Ausweich-Bootloader noch eine Windows-Fassung von 2011, gibt es einen Hinweis. |
| 8 | Registry-Werte der Windows-Wartung |
| 9 | BitLocker-Status |
| 10 | Ereignisse der letzten 60 Tage (siehe [Ergebnis prüfen](#ergebnis-prüfen)) |

Am Ende steht eine Zusammenfassung mit den nächsten Schritten. Zusätzlich hängt jeder Lauf eine
Zeile an `Uebersicht.csv` an (lokal und neben den Skripten). Darin steht pro Lauf und Gerät der
Stand von KEK, db, Boot-Manager und dbx sowie ein kurzer Status (`fertig`, `fertig ausser KEK`,
`offen`, `dbx beschaedigt` usw.). Die Datei lässt sich direkt in Excel öffnen und zeigt, welche
PCs noch fehlen.

### `2_Update_anstossen.cmd`

Setzt `AvailableUpdates` auf `0x5944`, startet den Task `Secure-Boot-Update`, wartet auf das Ende
und prüft danach erneut. Das ist derselbe Weg, den Windows von sich aus geht, nur sofort statt
irgendwann. Hat das Modell eine Sperre von Microsoft, trägt dieser Schritt allein nichts in die db
ein. Ist die Windows UEFI CA 2023 aber schon in der db (von Hand oder ab Werk), tauscht er trotzdem
den Boot-Manager.

### `3_`, `4_` und `5_`: von Hand einspielen

Die Dateien in `SecureBootUpdates` sind von Microsoft mit dem alten KEK 2011 signiert. Die Firmware
nimmt sie deshalb auch an, wenn Windows selbst sie wegen der Modellsperre nicht verwendet. Das
Skript `SecureBootManual.ps1`

1. sichert PK, KEK, db und dbx nach `Backups\<PC>\`,
2. zerlegt jede Datei in Zeitstempel, Signatur und Inhalt und liest daraus, welche Zertifikate
   oder Hashes sie enthält,
3. sortiert aus, was schon vorhanden ist oder nicht eingespielt werden darf,
4. hängt den Rest nach Bestätigung mit `Set-SecureBootUEFI -AppendWrite` an db bzw. dbx an.

| Datei | Wirkung |
|---|---|
| `3_Manuell_Trockenlauf.cmd` | zeigt nur den Plan, ändert nichts |
| `4_Manuell_einspielen.cmd` | trägt die fehlenden 2023-Zertifikate in die db ein |
| `5_Manuell_mit_dbx.cmd` | wie 4, zusätzlich die Hash-Sperren in die dbx |

Den KEK kann dieser Weg nicht eintragen, denn dafür bräuchte es eine Signatur mit dem PK des
Herstellers.

Manche Firmwares lehnen das Anhängen an die dbx mit `0xC0000022` ab. Das ist harmlos, die dbx
bleibt dann einfach, wie sie war. Den nächsten Versuch macht `8_dbx_schrittweise.cmd`.

### `6_Schluessel_neu_aufbauen.cmd`

Für Fälle, in denen der KEK 2023 oder die dbx auf normalem Weg nicht hineinkommen. Der Trick: Löscht
man im Firmware-Setup alle Schlüssel, geht die Firmware in den **Setup Mode**. In diesem Zustand
prüft sie keine Signaturen und lässt jede Variable schreiben. Das Skript läuft deshalb zweimal:

1. **Erster Lauf** (Firmware im User Mode): liest PK, KEK, db und dbx aus, fügt den KEK 2023
   (aus `KEKUpdateCombined.bin`), die fehlenden db-Zertifikate und die dbx-Hashes hinzu und speichert
   das Ergebnis in `Rebuild\<PC>\`. Die Originale landen in `Rebuild\<PC>\Original\`.
2. Neustart, im Firmware-Setup die Schlüssel löschen (bei HP „Clear Secure Boot Keys“, bei Lenovo
   „Reset to Setup Mode“ oder „Clear All Secure Boot Keys“), Windows starten.
3. **Zweiter Lauf** (Firmware im Setup Mode): prüft, ob die Daten zu diesem Gerät gehören, und
   schreibt db, dbx, KEK und zuletzt den originalen PK zurück. Mit dem PK wechselt die Firmware
   zurück in den User Mode.
4. Neustart, dann `5_Manuell_mit_dbx.cmd` (falls die dbx zurückgefallen ist), `2_Update_anstossen.cmd`
   und nach einem weiteren Neustart `1_Pruefen.cmd`.

Wie die Firmware mit dem zurückgeschriebenen PK umgeht, ist je nach Hersteller verschieden:

| Verhalten | Beispiel | Folge |
|---|---|---|
| nimmt den PK an, User Mode erst nach dem Neustart | Lenovo ThinkCentre M93 | alles bleibt erhalten |
| lehnt den PK ab, trägt ihren Werks-PK beim Neustart selbst ein | HP ProDesk 400 G5, EliteBook 840 G3 | KEK und db bleiben, die dbx fällt zurück und wird mit `5_` nachgezogen |
| lädt beim Löschen die Werksschlüssel statt in den Setup Mode zu gehen | HP Compaq Pro 6300 | so nicht möglich, siehe Hinweis zu „Key Ownership“ |

**HP und „Key Ownership“:** Manche HP-Firmwares haben unter Secure Boot Configuration die
Einstellung „Key Ownership“ mit den Werten „HP Keys“ und „Custom Keys“. Steht sie auf HP Keys, lädt
die Firmware nach „Clear Secure Boot Keys“ möglicherweise beim nächsten Start wieder ihre
Werksschlüssel, statt in den Setup Mode zu gehen. Vor einem erneuten Versuch mit `6_` deshalb
nachsehen, ob es die Einstellung gibt, und sie auf Custom Keys stellen. Ob die Firmware danach den
zurückgeschriebenen HP-PK annimmt, ist nicht getestet. Das Skript erkennt nach dem Neustart, wenn
doch wieder die Werksschlüssel geladen wurden, und hält an.

Die dbx übernimmt das Skript ausschließlich als saubere SHA256-Hashlisten. Vor dem Schreiben prüft
es alle Daten auf ein gültiges Format.

### `7_Sicherung_zurueckspielen.cmd`

Schreibt einen früheren Stand zurück in die Firmware. Zur Auswahl stehen alle Sicherungen dieses
Geräts, also `Backups\<PC>\Backup_*` (angelegt von `4_` und `5_` vor jedem Schreiben) und
`Rebuild\<PC>\Original` (angelegt vom ersten Lauf von `6_`). Zu jeder Sicherung zeigt das Skript,
ob KEK 2023 und Windows UEFI CA 2023 enthalten sind und wie viele Hashes die dbx hat.

Wie bei `6_` geht das nur im Setup Mode:

1. `7_Sicherung_zurueckspielen.cmd` starten. Im User Mode listet es die Sicherungen auf und
   erklärt, wie man bei diesem Hersteller die Schlüssel löscht.
2. Neustart, im Firmware-Setup die Schlüssel löschen, Windows starten.
3. `7_` erneut starten, die Nummer der Sicherung eingeben und mit `JA` bestätigen. Geschrieben
   werden db, dbx, KEK und zuletzt der PK.

Enthält die gewählte Sicherung die Windows UEFI CA 2023 nicht, warnt das Skript: Ist der
Boot-Manager schon getauscht, muss Secure Boot dann aus bleiben, bis `5_` die Zertifikate wieder
eingetragen hat. Eine beschädigte dbx in der Sicherung wird vor dem Schreiben bereinigt.

### `8_dbx_schrittweise.cmd`

Für Firmwares, die die aktuelle Sperrliste von Windows mit `0xC0000022` ablehnen. Die Liste ist
inzwischen gut 24 KB groß. Ältere Firmwares haben teils eine Grenze pro Schreibvorgang oder wenig
freien Variablenspeicher. Früher hat Windows die Sperren in mehreren kleineren Updates eingetragen;
dieser Starter macht das nach.

Das Skript sammelt alle dbx-Dateien aus dem Ordner `dbx_schrittweise` neben den Skripten (auch aus
Unterordnern) und aus `SecureBootUpdates`. Es

1. sortiert aus, was nicht passt: andere Prozessorarchitekturen (x86, ARM), SVN-Einträge, die
   PCA-2011-Sperre, Dateien mit unsauberem Format und Dateien, deren Hashes schon alle in der dbx
   stehen,
2. zeigt eine Tabelle mit Größe, Datum, Anzahl Hashes und wie viele davon neu wären,
3. schreibt nach einem `JA` eine Datei nach der anderen, die kleinste zuerst, und macht nach einer
   Ablehnung mit der nächsten weiter,
4. wertet am Ende aus: Wird schon die kleinste Datei abgelehnt, liegt es nicht an der Größe. Werden
   kleine Dateien angenommen und große abgelehnt, nennt es die Grenze.

Die zusätzlichen Dateien stellt Microsoft im öffentlichen GitHub-Repository
[microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects) bereit. Geeignet
sind die mit dem KEK 2011 signierten Fassungen für x64:

| Ordner im Repository | Inhalt |
|---|---|
| `PostSignedObjects/SignedByKEK2011/dbx_x64_Legacy` | die vollständige Liste (etwa 17 KB) und zwei Dateien mit je einem einzelnen Hash (etwa 3,4 KB) |
| `PostSignedObjects/DBX/amd64` | `DBXUpdate.bin`, die größte Fassung (etwa 24 KB); laut Microsoft veraltet, wird 2027 entfernt |

Die Dateien herunterladen und in `dbx_schrittweise` legen. Die Endung `.efiauth2` kann bleiben. Die
Einzel-Hash-Dateien sind die wichtigste Probe: Nimmt die Firmware nicht einmal die an, lehnt sie das
Anhängen an die dbx grundsätzlich ab. Der Ordner ist per `.gitignore` vom Repository ausgeschlossen.

## Ergebnis prüfen

Ein PC ist fertig, wenn `1_Pruefen.cmd` Folgendes zeigt:

- **Pflicht:** Die db enthält die Windows UEFI CA 2023, und der Boot-Manager ist mit ihr signiert.
  Damit startet der PC auch mit künftigen Boot-Managern und Installationsmedien.
- **Kür:** Der KEK 2023 ist eingetragen (für künftige Updates von db und dbx), und die dbx hat
  rund 300 Einträge oder mehr.

Ein verbleibendes `AvailableUpdates = 0x4000` ist nur die Bedingung aus der Tabelle oben und kein
Fehler.

Die wichtigsten Ereignisse (Quelle `Microsoft-Windows-TPM-WMI`, Protokoll „System“):

| ID | Bedeutung |
|---|---|
| 1808 | alle Zertifikate erfolgreich aktualisiert |
| 1799 | Boot-Manager mit 2023-Signatur installiert |
| 1800 | Neustart nötig |
| 1801 | Zertifikate aktualisiert, aber noch nicht vollständig angewendet |
| 1797 | Boot-Manager-Tausch abgebrochen, weil die Windows UEFI CA 2023 in der db fehlt |
| 1802 | von Microsoft wegen bekannter Firmwarefehler dieses Modells gesperrt |
| 1803 | keine vom Hersteller signierte KEK-Datei für dieses Modell vorhanden |
| 1795, 1796 | die Firmware hat das Schreiben abgelehnt |

## Notfall und Regeln

> ⚠️ **Nach dem Tausch des Boot-Managers die Secure-Boot-Schlüssel im BIOS nie mehr löschen oder
> auf Werkseinstellung zurücksetzen.** Die Werkseinstellungen der meisten älteren Geräte kennen
> die Windows UEFI CA 2023 nicht. Nach einem Reset startet Windows mit eingeschaltetem Secure Boot
> nicht mehr. Ausnahme: `1_Pruefen.cmd` meldet in Abschnitt 5b, dass die Werkseinstellungen die
> Windows UEFI CA 2023 enthalten.

**Startet ein PC nach einem Schritt nicht** (zum Beispiel mit „invalid signature“ oder einer roten
Secure-Boot-Meldung):

1. Ins Firmware-Setup und Secure Boot ausschalten. Das ist immer gefahrlos. Die Taste zeigt
   `1_Pruefen.cmd` in Abschnitt 1 an (HP: F10, Lenovo: F1, MrChromebox: Esc).
2. Windows starten und `5_Manuell_mit_dbx.cmd` ausführen.
3. Secure Boot wieder einschalten.

Meldet `1_Pruefen.cmd` eine beschädigte Variable, lässt sich mit `7_Sicherung_zurueckspielen.cmd`
auch der Stand vor dem letzten Schreiben zurückholen.

Hat das Zurücksetzen auch den KEK 2023 entfernt, lässt er sich auf Geräten, bei denen
`6_Schluessel_neu_aufbauen.cmd` funktioniert, damit wieder eintragen.

> ⚠️ **Nie einspielen:** `DBXUpdate2024.bin` und `DBXUpdate2024Legacy.bin` sperren die alte
> Windows Production PCA 2011. Danach starten ältere Boot-Manager, Windows-Installationsmedien und
> Rettungssticks nicht mehr. Die Skripte überspringen diese Dateien immer, unabhängig vom Inhalt.

## Ablage der Protokolle und Sicherungen

Alles wird zuerst lokal unter `C:\ProgramData\SecureBootCheck\` gespeichert und danach in denselben
Unterordner neben den Skripten kopiert, also z.B. auf den USB-Stick.

| Ordner | Inhalt |
|---|---|
| `Logs\<PC>\` | Protokoll jedes Laufs |
| `Backups\<PC>\` | Sicherung von PK, KEK, db und dbx vor jedem Schreiben |
| `Rebuild\<PC>\` | Daten für `6_Schluessel_neu_aufbauen` zwischen den beiden Läufen |
| `Uebersicht.csv` | eine Zeile pro Lauf von `1_` und `2_`, über alle Geräte |
| `dbx_schrittweise\` | selbst heruntergeladene dbx-Dateien für `8_` (liegt nur neben den Skripten) |

Protokolldateien heißen nach Datum und Uhrzeit mit Sekunden, und jedes Protokoll nennt die
Skriptversion.

`<PC>` steht für `Hostname_Seriennummer`. So landen auch geklonte PCs mit gleichem Hostnamen in
getrennten Ordnern. Ist keine Seriennummer auslesbar, wird nur der Hostname verwendet.

Diese Ordner enthalten gerätebezogene Daten und sind per `.gitignore` vom Repository ausgeschlossen.

## Erfahrungen mit getesteten Geräten

Stand 17.11.2026, Skriptversion 1.3.

| Gerät | Weg | Ergebnis |
|---|---|---|
| HP ProDesk 400 G5 | Schnellstart, dann `6_` | alles auf 2023 |
| HP EliteBook 840 G3 | Schnellstart, dann `6_` | alles auf 2023 |
| Lenovo ThinkCentre M93 (10A4) | Schnellstart, dann `6_` | alles auf 2023; die dbx ging erst über `6_` |
| Lenovo ThinkCentre M93p (10AA) | Schnellstart, dann `6_` | alles auf 2023 (siehe unten) |
| Chromebox Google Teemo (MrChromebox) | nur `2_` | alles auf 2023; die Firmware bringt die 2023-Zertifikate schon mit, ein Reset ist hier ungefährlich |
| HP Compaq Pro 6300 | Schnellstart | db und Boot-Manager auf 2023; KEK und dbx bisher nicht möglich. Offen: `8_` und die Einstellung „Key Ownership“ |
| 10ZiG Thin Client | | kein Secure Boot, nicht betroffen |

**Fehler in Version 1.1 (behoben in 1.2):** Auf dem M93p mit Windows-Build 19044.7725 lagen die
`DBXUpdate2024`-Dateien in einem älteren Format vor. Version 1.1 erkannte deren Inhalt nicht. Der
zweite Lauf von `6_` schrieb ihn deshalb als unlesbaren Block in die dbx, und der PC startete mit
Secure Boot nur noch mit „invalid signature“. Seit Version 1.2 sind diese Dateien schon per
Dateiname gesperrt, und der zweite Lauf von `6_` bereinigt eine so beschädigte dbx automatisch.
Damit ließ sich der M93p retten.

## Aufruf per PowerShell

Die `.cmd`-Dateien rufen nur die drei Skripte auf. In einer PowerShell mit Administratorrechten im
Skriptordner geht dasselbe so:

```powershell
# 1_Pruefen
powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1
# 2_Update_anstossen
powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1 -Apply -Force
# 3_Manuell_Trockenlauf
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1
# 4_Manuell_einspielen
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute
# 5_Manuell_mit_dbx
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute -IncludeDbx
# 6_Schluessel_neu_aufbauen
powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1
# 7_Sicherung_zurueckspielen
powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1 -Restore
# 8_dbx_schrittweise
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute -DbxStepwise
```

Weitere Parameter:

| Parameter | Skripte | Wirkung |
|---|---|---|
| `-NoPause` | alle | am Ende nicht auf Enter warten |
| `-PayloadDir` | Manual, Rebuild | anderer Ordner mit Update-Dateien statt `SecureBootUpdates` |
| `-StateDir` | Rebuild | Rebuild-Daten von einem anderen Ort lesen, z.B. vom Stick |
| `-StepDir` | Manual mit `-DbxStepwise` | anderer Ordner für die zusätzlichen dbx-Dateien statt `dbx_schrittweise` |

Ohne `-Execute` zeigt `-DbxStepwise` nur die Tabelle und schreibt nichts.

## Selbsttest

Der Ordner `tests` prüft die Skripte, ohne die Firmware anzufassen und ohne Administratorrechte:

| Datei | Wirkung |
|---|---|
| `tests\Tests_ausfuehren.cmd` | prüft Syntax, ASCII und Zeilenenden aller Skripte und testet die Prüf- und Entscheidungsfunktionen mit künstlichen Daten: gültige und beschädigte Signaturlisten, das ältere Dateiformat, eine PCA-2011-Sperre und `DBXUpdate2024` |
| `tests\Testdateien_sammeln.cmd` | kopiert die Update-Dateien und die Variablen dieses PCs nach `tests\fixtures\<PC>_<Build>\` (nur lesen) |

Liegen Testdateien vor, prüft `Tests_ausfuehren.cmd` zusätzlich, dass jede echte Microsoft-Datei
erkannt wird und `DBXUpdate2024` immer abgelehnt wird. Gerade nach einem Windows-Update mit neuen
Dateien in `SecureBootUpdates` lohnt sich das vor dem nächsten Schreiben. Die Testdateien sind
Microsoft-Dateien und gerätebezogene Daten und werden deshalb nicht ins Repository übernommen.

## Haftung

Eingriffe in die Secure-Boot-Variablen können einen PC am Starten hindern. Die Benutzung erfolgt
auf eigene Gefahr. Vor dem ersten Schreiben die Ausgabe von `1_Pruefen.cmd` und
`3_Manuell_Trockenlauf.cmd` lesen und den Notfallweg kennen.
