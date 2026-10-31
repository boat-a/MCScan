# ====================================================================
#  MCScan - Minecraft ScreenShare Scanner (read-only)
#  Looks for common cheat indicators. Does NOT delete, change or
#  upload anything. Saves a report to the Desktop.
#  Results are INDICATORS, not proof - always review manually.
# ====================================================================
$ErrorActionPreference = 'SilentlyContinue'
$Host.UI.RawUI.WindowTitle = 'MCScan - ScreenShare Scanner'
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ---------------------- CONFIG (edit these) -------------------------
$RecentHours = 72   # flag mods modified within this many hours

# Generic cheat module names (high confidence)
$Strong = 'killaura|kill_aura|aimassist|aim_assist|autoclicker|auto_clicker|triggerbot|trigger_bot|antiknockback|anti_knockback|scaffoldwalk|autototem|autocrystal|crystalaura|anchoraura|autoanchor|hitboxes|nofall|wallhack|freecam|reachhack|bhop|flyhack|speedhack|autoarmor|invwalk|cheststealer|nuker|fastplace'

# Known cheat client names
$Clients = 'wurst|meteor-?client|aristois|liquid-?bounce|future-?client|vapev4|vapelite|vape-?client|novoline|astolfo|tenacity|exhibition|dreamclient|slinkyclient|doomsday|zeroday|konas|phobos|salhack|kamiblue|rusherhack|thunderhack|osirisclient|pandaware|augustus|sigmaclient|ravenb|riseclient|impactclient|dripclient|entropyclient|whiteoutclient|lambdaclient|inertiaclient|ghostclient'

# Injectors, macro / autoclicker tools, lag tools
$Tools = 'cheatengine|cheat engine|processhacker|extremeinjector|xenos|dllinject|injector|autohotkey|opautoclicker|gsautoclicker|speedautoclicker|fastclicker|jitbit|tinytask|macrorecorder|clumsy'

# Strings searched inside .class files of jars
$ContentPattern = 'killaura|aimassist|autoclicker|triggerbot|clickgui|modulemanager|crystalaura|anchoraura|autototem|antiknockback|cheststealer|scaffoldwalk'

# Paste SHA256 hashes (UPPERCASE) of known cheat jars here
$KnownBadHashes = @()
# --------------------------------------------------------------------

$script:Findings  = New-Object System.Collections.ArrayList
$script:Inventory = New-Object System.Collections.ArrayList
$script:Seen      = @{}
$script:JarsDone  = @{}

function Add-Finding($Sev, $Cat, $Msg, $Path = '') {
    $key = "$Sev|$Msg|$Path"
    if ($script:Seen.ContainsKey($key)) { return }
    $script:Seen[$key] = 1
    [void]$script:Findings.Add([pscustomobject]@{ Severity = $Sev; Category = $Cat; Message = $Msg; Path = $Path })
    $color = switch ($Sev) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Cyan' } }
    Write-Host ("[{0}] [{1}] {2}" -f $Sev, $Cat, $Msg) -ForegroundColor $color
    if ($Path) { Write-Host "        $Path" -ForegroundColor DarkGray }
}

function Section($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Green }

function Test-Name($n) {
    if (-not $n) { return $null }
    if ($n -match $Strong)  { return 'HIGH' }
    if ($n -match $Clients) { return 'MEDIUM' }
    if ($n -match $Tools)   { return 'MEDIUM' }
    return $null
}

function Scan-Names($root, $depth) {
    if (-not (Test-Path -LiteralPath $root)) { return }
    Get-ChildItem -LiteralPath $root -Recurse -Depth $depth -Force | ForEach-Object {
        if ($_.PSIsContainer -or $_.Extension -match '^\.(jar|exe|dll|zip|rar|7z|bat|cmd|ps1|vbs|lnk)$') {
            $sev = Test-Name $_.Name
            if ($sev) { Add-Finding $sev 'FileName' "Suspicious name: $($_.Name)" $_.FullName }
        }
    }
}

function Scan-Jar($file) {
    if ($script:JarsDone.ContainsKey($file.FullName)) { return }
    $script:JarsDone[$file.FullName] = 1
    $name = $file.Name

    $sev = Test-Name $name
    if ($sev) { Add-Finding $sev 'Mod' "Jar name looks suspicious: $name" $file.FullName }

    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    [void]$script:Inventory.Add(("{0} | {1:N0} KB | modified {2} | {3}" -f $name, ($file.Length / 1KB), $file.LastWriteTime, $hash))
    if ($KnownBadHashes -contains $hash) { Add-Finding 'HIGH' 'Hash' "Known bad hash match: $name" $file.FullName }

    if ($file.LastWriteTime -gt (Get-Date).AddHours(-$RecentHours)) {
        Add-Finding 'LOW' 'Mod' "Modified in last $RecentHours h: $name ($($file.LastWriteTime))" $file.FullName
    }
    if ($file.Length -gt 80MB) { return }

    $zip = $null
    try { $zip = [System.IO.Compression.ZipFile]::OpenRead($file.FullName) }
    catch { Add-Finding 'LOW' 'Mod' "Could not open as zip (corrupt/locked/renamed?): $name" $file.FullName; return }

    $entryHits = New-Object System.Collections.ArrayList
    $contentHits = @{}
    $classCount = 0; $shortCount = 0; $hasMeta = $false
    try {
        foreach ($e in $zip.Entries) {
            $fn = $e.FullName
            if ($fn -match 'fabric\.mod\.json|mods\.toml|mcmod\.info|quilt\.mod\.json') { $hasMeta = $true }
            if (($fn -match $Strong -or $fn -match $Clients) -and $entryHits.Count -lt 5) { [void]$entryHits.Add($fn) }
            if ($fn -like '*.class') {
                $classCount++
                if ([IO.Path]::GetFileNameWithoutExtension($e.Name).Length -le 2) { $shortCount++ }
                if ($e.Length -gt 0 -and $e.Length -lt 1500000 -and $contentHits.Count -lt 6) {
                    try {
                        $s = $e.Open(); $ms = New-Object IO.MemoryStream
                        $s.CopyTo($ms); $s.Dispose()
                        $txt = [Text.Encoding]::GetEncoding(28591).GetString($ms.ToArray())
                        if ($txt -match $ContentPattern) { $contentHits[$Matches[0].ToLower()] = $fn }
                    } catch {}
                }
            }
        }
    } finally { $zip.Dispose() }

    if ($entryHits.Count -gt 0) {
        Add-Finding 'HIGH' 'Mod' "Cheat-like entries inside $name : $($entryHits -join ', ')" $file.FullName
    }
    if ($contentHits.Count -ge 2) {
        Add-Finding 'HIGH' 'Mod' "Cheat strings inside classes of $name : $($contentHits.Keys -join ', ')" $file.FullName
    } elseif ($contentHits.Count -eq 1) {
        Add-Finding 'MEDIUM' 'Mod' "Possible cheat string inside $name : $($contentHits.Keys -join ', ')" $file.FullName
    }
    if ($classCount -gt 20 -and ($shortCount / $classCount) -gt 0.5) {
        Add-Finding 'LOW' 'Mod' "Heavily obfuscated jar (many 1-2 letter class names): $name" $file.FullName
    }
    if (-not $hasMeta -and $classCount -gt 0) {
        Add-Finding 'LOW' 'Mod' "Jar has no Fabric/Forge/Quilt mod metadata: $name" $file.FullName
    }
}

# ------------------------------ START -------------------------------
Clear-Host
Write-Host "  __  __  ____ ____" -ForegroundColor Cyan
Write-Host " |  \/  |/ ___/ ___|  ___ __ _ _ __" -ForegroundColor Cyan
Write-Host " | |\/| | |   \___ \ / __/ _`` | '_ \" -ForegroundColor Cyan
Write-Host " | |  | | |___ ___) | (_| (_| | | | |" -ForegroundColor Cyan
Write-Host " |_|  |_|\____|____/ \___\__,_|_| |_|" -ForegroundColor Cyan
Write-Host "  Minecraft ScreenShare Scanner (read-only)`n" -ForegroundColor Gray

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Not running as Administrator - Prefetch, BAM and Security log checks will be limited." -ForegroundColor Yellow
}
$start = Get-Date

# ---- System info ----
Section 'System'
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host "User: $env:USERNAME | PC: $env:COMPUTERNAME | Last boot: $boot"
if ($boot -gt (Get-Date).AddMinutes(-30)) { Add-Finding 'LOW' 'System' "PC was restarted less than 30 minutes ago ($boot)" }

foreach ($s in 'EventLog', 'DPS', 'PcaSvc', 'SysMain') {
    $svc = Get-Service $s
    if ($svc -and $svc.Status -ne 'Running') {
        $sev = if ($s -in 'EventLog', 'DPS') { 'MEDIUM' } else { 'LOW' }
        Add-Finding $sev 'Service' "Service $s is $($svc.Status) (often stopped to hide traces, but can be a normal tweak)"
    }
}
$c1 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 3
if ($c1) { Add-Finding 'HIGH' 'EventLog' "Security event log was cleared on $($c1[0].TimeCreated)" }
$c2 = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 3
if ($c2) { Add-Finding 'HIGH' 'EventLog' "System event log was cleared on $($c2[0].TimeCreated)" }

# ---- Running processes ----
Section 'Running processes'
Get-Process | ForEach-Object {
    $sev = Test-Name $_.ProcessName
    if (-not $sev -and $_.MainWindowTitle) { $sev = Test-Name $_.MainWindowTitle }
    if ($sev) { Add-Finding $sev 'Process' "Running: $($_.ProcessName) $($_.MainWindowTitle)" $_.Path }
}

Section 'Java / Minecraft process'
$okDll = 'lwjgl|jna|openal|glfw|sqlite|zstd|javafx|jansi|netty|discord|steam|nvidia|amd|intel'
Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^javaw?\.exe$' } | ForEach-Object {
    $cl = $_.CommandLine
    if ($cl -match '-javaagent:[^ ]+') { Add-Finding 'MEDIUM' 'Java' "javaagent in launch args: $($Matches[0])" }
    if ($cl -match '-Xbootclasspath') { Add-Finding 'LOW' 'Java' 'Xbootclasspath used in launch args' }
    if ($cl -match $Strong -or $cl -match $Clients) { Add-Finding 'HIGH' 'Java' 'Cheat name found in Java launch arguments' }
    $p = Get-Process -Id $_.ProcessId
    foreach ($m in $p.Modules) {
        $mp = $m.FileName
        if ($mp -match '\\(Temp|Downloads|Desktop)\\' -or $mp -match '\\AppData\\') {
            if ($mp -notmatch $okDll -and $mp -notmatch '\\(runtime|jre|jdk|java)') {
                $sev = Test-Name $mp
                if (-not $sev) { $sev = 'MEDIUM' }
                Add-Finding $sev 'Injection' "Unusual DLL loaded in Java process: $($m.ModuleName)" $mp
            }
        }
    }
}

# ---- Minecraft folders ----
Section 'Minecraft folders, mods and versions'
$roots = @(
    "$env:APPDATA\.minecraft", "$env:APPDATA\.tlauncher", "$env:APPDATA\PrismLauncher",
    "$env:APPDATA\com.modrinth.theseus", "$env:APPDATA\ATLauncher", "$env:APPDATA\.feather",
    "$env:USERPROFILE\.lunarclient", "$env:USERPROFILE\curseforge"
) | Where-Object { Test-Path -LiteralPath $_ }

if (-not $roots) { Write-Host 'No Minecraft launcher folders found.' -ForegroundColor DarkGray }
foreach ($root in $roots) {
    Write-Host "Scanning $root" -ForegroundColor Gray
    Scan-Names $root 3

    Get-ChildItem -LiteralPath $root -Directory -Recurse -Depth 5 -Filter mods | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -Recurse -Filter *.jar -File | ForEach-Object { Scan-Jar $_ }
    }
    Get-ChildItem -LiteralPath $root -Directory -Recurse -Depth 5 -Filter resourcepacks | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName | ForEach-Object {
            if ($_.Name -match 'x-?ray|fullbright|ore-?finder') {
                Add-Finding 'MEDIUM' 'ResourcePack' "X-ray style resource pack: $($_.Name)" $_.FullName
            }
        }
    }
    $ver = Join-Path $root 'versions'
    if (Test-Path -LiteralPath $ver) {
        Get-ChildItem -LiteralPath $ver -Directory | ForEach-Object {
            $sev = Test-Name $_.Name
            if ($sev) { Add-Finding $sev 'Version' "Suspicious version folder: $($_.Name)" $_.FullName }
            Get-ChildItem -LiteralPath $_.FullName -Filter *.json -File | ForEach-Object {
                if (Select-String -LiteralPath $_.FullName -Pattern $Clients, $Strong -Quiet) {
                    Add-Finding 'MEDIUM' 'Version' "Version json references a cheat client: $($_.Name)" $_.FullName
                }
            }
            Get-ChildItem -LiteralPath $_.FullName -Filter *.jar -File | ForEach-Object { Scan-Jar $_ }
        }
    }
    $prof = Join-Path $root 'launcher_profiles.json'
    if ((Test-Path -LiteralPath $prof) -and (Select-String -LiteralPath $prof -Pattern $Clients -Quiet)) {
        Add-Finding 'MEDIUM' 'Launcher' 'launcher_profiles.json references a cheat client name' $prof
    }
    foreach ($log in 'logs\latest.log', 'logs\debug.log') {
        $lp = Join-Path $root $log
        if (Test-Path -LiteralPath $lp) {
            $hits = Select-String -LiteralPath $lp -Pattern $Strong, $Clients | Select-Object -First 5
            foreach ($h in $hits) {
                Add-Finding 'MEDIUM' 'Log' ("{0}: line {1}: {2}" -f $log, $h.LineNumber, $h.Line.Trim().Substring(0, [Math]::Min(120, $h.Line.Trim().Length))) $lp
            }
        }
    }
}

# ---- Common user folders ----
Section 'Suspicious file names (Downloads, Desktop, Documents, Temp, AppData)'
$desktop = [Environment]::GetFolderPath('Desktop')
Scan-Names "$env:USERPROFILE\Downloads" 3
Scan-Names $desktop 3
Scan-Names "$env:USERPROFILE\Documents" 3
Scan-Names $env:TEMP 2
Scan-Names $env:APPDATA 2
Scan-Names $env:LOCALAPPDATA 2

Section 'Jars outside Minecraft folders'
foreach ($d in "$env:USERPROFILE\Downloads", $desktop) {
    Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -Filter *.jar -File | ForEach-Object { Scan-Jar $_ }
}

# ---- Traces of deleted / previously run files ----
Section 'Recent files (.lnk)'
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter *.lnk | ForEach-Object {
    $sev = Test-Name $_.Name
    if ($sev) { Add-Finding $sev 'Recent' "Recently opened: $($_.BaseName) ($($_.LastWriteTime))" }
}

Section 'Recycle Bin'
try {
    $shell = New-Object -ComObject Shell.Application
    $rb = $shell.Namespace(0xA)
    foreach ($i in $rb.Items()) {
        $n = $rb.GetDetailsOf($i, 0); $orig = $rb.GetDetailsOf($i, 1); $dt = $rb.GetDetailsOf($i, 2)
        $sev = Test-Name "$n $orig"
        if ($sev) { Add-Finding $sev 'RecycleBin' ("Deleted: {0} (from {1}, on {2})" -f $n, $orig, ($dt -replace '[^\x20-\x7E]', '')) }
    }
} catch {}

Section 'Registry execution traces (MuiCache / Compatibility Store / BAM)'
foreach ($r in 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache',
               'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store') {
    $k = Get-Item $r
    if ($k) {
        foreach ($v in $k.GetValueNames()) {
            $sev = Test-Name $v
            if ($sev) { Add-Finding $sev 'Registry' "Previously executed: $v" }
        }
    }
}
$bam = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
Get-ChildItem $bam | ForEach-Object {
    foreach ($v in $_.GetValueNames()) {
        $sev = Test-Name $v
        if ($sev) { Add-Finding $sev 'BAM' "Executed (BAM): $v" }
    }
}

Section 'Prefetch'
$pf = Get-ChildItem 'C:\Windows\Prefetch' -Filter *.pf
if (-not $pf) {
    Add-Finding 'LOW' 'Prefetch' 'Prefetch unreadable or empty (not admin, disabled, or cleared)'
} else {
    if ($pf.Count -lt 30) { Add-Finding 'MEDIUM' 'Prefetch' "Only $($pf.Count) prefetch files - folder may have been cleared" }
    foreach ($f in $pf) {
        $sev = Test-Name $f.Name
        if ($sev) { Add-Finding $sev 'Prefetch' "Program ran: $($f.Name) (last: $($f.LastWriteTime))" }
    }
}

# ------------------------------ REPORT ------------------------------
Section 'Summary'
$high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
$med  = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
$low  = @($script:Findings | Where-Object Severity -eq 'LOW').Count
Write-Host "HIGH: $high   MEDIUM: $med   LOW: $low   Mods/jars inventoried: $($script:Inventory.Count)"
if ($high -gt 0)     { Write-Host 'Verdict: strong cheat indicators found - review the HIGH items.' -ForegroundColor Red }
elseif ($med -gt 0)  { Write-Host 'Verdict: suspicious items found - review manually.' -ForegroundColor Yellow }
else                 { Write-Host 'Verdict: nothing obvious found (this does not guarantee a clean PC).' -ForegroundColor Green }

$report = Join-Path $desktop ("MCScan_Report_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$lines = @("MCScan report - $(Get-Date)", "User: $env:USERNAME  PC: $env:COMPUTERNAME  Admin: $isAdmin",
           "HIGH: $high  MEDIUM: $med  LOW: $low", '', '--- FINDINGS ---')
foreach ($f in ($script:Findings | Sort-Object { switch ($_.Severity) { 'HIGH' { 0 } 'MEDIUM' { 1 } default { 2 } } })) {
    $lines += "[{0}] [{1}] {2}" -f $f.Severity, $f.Category, $f.Message
    if ($f.Path) { $lines += "     $($f.Path)" }
}
$lines += ''; $lines += '--- JAR INVENTORY (name | size | modified | SHA256) ---'
$lines += $script:Inventory
$lines | Out-File -FilePath $report -Encoding UTF8
Write-Host "`nReport saved to: $report" -ForegroundColor Cyan
Write-Host ("Finished in {0:N0} seconds. Indicators are not proof - verify manually." -f ((Get-Date) - $start).TotalSeconds) -ForegroundColor Gray
Read-Host "`nPress Enter to exit"
