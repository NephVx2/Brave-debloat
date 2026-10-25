# =====================================================================================
# BRAVE-DEBLOAT — Controlled deployment of Brave policies (HKLM registry)
# VERSION 3.3.0 — Console UI overhaul (no functional change). Built on v3.2.0:
# interactive menu interface + extended hardening (v3: 20 new
# Telemetry/Bloat/Network/Security/PrivacySandbox/Performance rules, analyzed
# from a full brave://policy/ export on 07/04/2026)
# =====================================================================================
# Applies a set of Brave policies (debloat, telemetry, network, security) via
# HKLM\SOFTWARE\Policies\BraveSoftware\Brave, with automatic backup before any
# change, simulation mode, restore, integrity/conflict verification, and
# CSV/JSON/HTML reports — same architecture as Block-Telemetry.
#
# SAFETY GUARANTEES:
#   [S1] Automatic .reg backup before any change (reg export)
#   [S2] Automatic backup rotation (last 10 kept)
#   [S3] Simulation mode (DryRun) to see the diff without touching anything
#   [S4] Full restore function built in (menu)
#   [S5] "Update" option (cleans up residue + re-applies in one step)
#   [S6] Anti-regression guardrails built into SelfTest (NetworkPredictionOptions,
#        ComponentUpdatesEnabled) — see the original conversation history
#   [S7] Conflict detection (HKCU policies, Recommended subkey, residue)
#   [S8] Integrity check (defined policies vs. actually active values)
#   [S9] DoH and Lockdown remain explicit opt-in (never applied by default)
#
# CATEGORIES: Bloat, Telemetry, Network, Security, PrivacySandbox, Performance,
#             Lockdown (opt-in via -IncludeLockdown)
#
# v3.3.0 — CONSOLE UI OVERHAUL (no functional change):
#   [U1] New console helper layer: Write-Banner, Write-Header, Write-Status,
#        Write-KeyValue, Write-MenuItem, Write-ResultBox, Write-BoxLine/Write-BoxEdge,
#        Write-Rule, Read-Confirm, Wait-ForMenu. Write-Ok / Write-Warn2 / Write-Fail
#        keep their names but now render through Write-Status, so every existing
#        call site picks up the new look.
#   [U2] Framed double-line banners for every screen, "▸ Title ───" section titles,
#        and framed result boxes at the end of Apply, Simulation and Restore.
#   [U3] Unicode status icons (check, cross, triangle, dot, circle, diamond)
#        replace the [OK] / [!] / [x] / [INFO] text tags; diff lines use the same icons.
#   [U4] Main menu regrouped (Policies / Backups & DNS / Reports & diagnostics)
#        with an aligned Status panel (policies applied, last action, integrity).
#   [U5] Backups shown as an aligned table, SelfTest and -DebugDefs rendered with the
#        same status rows, console window title set.
#   [U6] All Y/N prompts go through one Read-Confirm helper (same accepted answers).
#   [U7] Fixed a leftover untranslated label ("Rapport :" -> "HTML report").
#   Policy definitions, registry logic, backups, reports (CSV/JSON/HTML) and
#   SelfTest assertions are unchanged.
# =====================================================================================

[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$DebugDefs,
    [string[]]$Category,
    [switch]$IncludeLockdown,
    [ValidateSet('Off','Standard','Enhanced')]
    [string]$SafeBrowsingLevel = 'Standard',
    [string]$DnsOverHttpsTemplate
)

$ScriptVersion = '3.3.0'

try { $Host.UI.RawUI.WindowTitle = "Brave-Debloat v$ScriptVersion" } catch { }

#region AUTO-ELEVATION

# SelfTest is purely read-only (registry + in-memory comparisons): handled
# before elevation to avoid an unnecessary UAC prompt just for a check.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$script:IsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $SelfTest -and -not $DebugDefs -and -not $script:IsAdmin) {
    $Shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell.exe" }
    $reArgs = @('-ExecutionPolicy','Bypass','-NoProfile','-File',"`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $reArgs += "-$k" } }
        elseif ($v -is [array]) { $reArgs += "-$k"; $reArgs += ($v -join ',') }
        else { $reArgs += "-$k"; $reArgs += "`"$v`"" }
    }
    Start-Process $Shell -Verb RunAs -ArgumentList ($reArgs -join ' ')
    exit
}

#endregion

#region INITIALIZATION

$RegPath          = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
$RegPathWin       = 'HKLM\SOFTWARE\Policies\BraveSoftware\Brave'
$HkcuRegPath      = 'HKCU:\SOFTWARE\Policies\BraveSoftware\Brave'
$RecommendedPath  = Join-Path $RegPath 'Recommended'
$ReportRoot       = Join-Path $env:USERPROFILE 'Desktop\Maintenance_Reports\Brave-Debloat'
$BackupFolder     = Join-Path $env:USERPROFILE 'Desktop\Maintenance_Reports\Brave-Debloat\Registry-Backups'
$LogPath          = Join-Path $env:USERPROFILE 'Desktop\Maintenance_Reports\Brave-Debloat\Brave-Debloat_Log.txt'
$StateFile        = Join-Path $ReportRoot '_last_state.json'
$BackupMaxCount   = 10
$script:Results   = New-Object System.Collections.Generic.List[object]

#endregion

#region DISPLAY / LOG UTILITIES

# =====================================================================================
# CONSOLE UI LAYER [U1] — every visual element of the console goes through here
# =====================================================================================
$script:UiWidth = 66

$script:Box = @{
    TL   = [string][char]0x2554   # top-left
    TR   = [string][char]0x2557   # top-right
    BL   = [string][char]0x255A   # bottom-left
    BR   = [string][char]0x255D   # bottom-right
    H    = [string][char]0x2550   # horizontal (double)
    V    = [string][char]0x2551   # vertical (double)
    ML   = [string][char]0x2560   # middle-left
    MR   = [string][char]0x2563   # middle-right
    Line = [string][char]0x2500   # thin horizontal rule
}

$script:Icon = @{
    OK    = [string][char]0x2714   # check
    FAIL  = [string][char]0x2718   # cross
    WARN  = [string][char]0x25B2   # triangle
    INFO  = [string][char]0x25CF   # filled dot
    SKIP  = [string][char]0x25CB   # empty dot
    SIM   = [string][char]0x25C6   # diamond
    Arrow = [string][char]0x25B8   # small arrow
    Dot   = [string][char]0x00B7   # middle dot
    Ellip = [string][char]0x2026   # ellipsis
}

function Write-Rule {
    param([string]$Color = "DarkGray")
    Write-Host ("  " + ($script:Box.Line * $script:UiWidth)) -ForegroundColor $Color
}

function Write-BoxEdge {
    param(
        [ValidateSet('Top','Middle','Bottom')][string]$Position,
        [string]$Color = "Cyan"
    )
    $b = $script:Box
    if     ($Position -eq 'Top')    { $l = $b.TL; $r = $b.TR }
    elseif ($Position -eq 'Middle') { $l = $b.ML; $r = $b.MR }
    else                            { $l = $b.BL; $r = $b.BR }
    Write-Host ("  " + $l + ($b.H * ($script:UiWidth - 2)) + $r) -ForegroundColor $Color
}

function Write-BoxLine {
    param(
        [string]$Text = "",
        [string]$Color = "White",
        [string]$BorderColor = "Cyan",
        [switch]$Center
    )
    $inner = $script:UiWidth - 2
    if ($Text.Length -gt ($inner - 2)) {
        $Text = $Text.Substring(0, $inner - 3) + $script:Icon.Ellip
    }
    if ($Center) {
        $padL = [int][Math]::Floor(($inner - $Text.Length) / 2)
        $padR = $inner - $Text.Length - $padL
        $content = (" " * $padL) + $Text + (" " * $padR)
    }
    else {
        $content = "  " + $Text.PadRight($inner - 2)
    }
    Write-Host ("  " + $script:Box.V) -NoNewline -ForegroundColor $BorderColor
    Write-Host $content -NoNewline -ForegroundColor $Color
    Write-Host $script:Box.V -ForegroundColor $BorderColor
}

# Framed screen banner. (Title, Color) keep the historical positional order.
function Write-Banner {
    param(
        [string]$Title,
        [string]$Color = "Cyan",
        [string]$Subtitle = "",
        [switch]$Roomy
    )
    Write-Host ""
    Write-BoxEdge Top $Color
    if ($Roomy) { Write-BoxLine "" -BorderColor $Color }
    Write-BoxLine $Title -Color White -BorderColor $Color -Center
    if ($Subtitle) { Write-BoxLine $Subtitle -Color DarkGray -BorderColor $Color -Center }
    if ($Roomy) { Write-BoxLine "" -BorderColor $Color }
    Write-BoxEdge Bottom $Color
}

# Section title: "▸ Title ─────────────"
function Write-Header {
    param([string]$Text, [string]$Color = "Cyan")
    $fill = [Math]::Max(2, $script:UiWidth - $Text.Length - 3)
    Write-Host ""
    Write-Host ("  " + $script:Icon.Arrow + " ") -NoNewline -ForegroundColor $Color
    Write-Host $Text -NoNewline -ForegroundColor White
    Write-Host (" " + ($script:Box.Line * $fill)) -ForegroundColor DarkGray
}

# One result line: icon + message (+ optional dimmed detail)
function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('OK','FAIL','WARN','INFO','SKIP','SIM')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$Detail = "",
        [int]$Indent = 2
    )
    switch ($Level) {
        'OK'   { $Symbol = $script:Icon.OK;   $IconColor = 'Green';      $TextColor = 'White' }
        'FAIL' { $Symbol = $script:Icon.FAIL; $IconColor = 'Red';        $TextColor = 'Red' }
        'WARN' { $Symbol = $script:Icon.WARN; $IconColor = 'Yellow';     $TextColor = 'Yellow' }
        'INFO' { $Symbol = $script:Icon.INFO; $IconColor = 'Cyan';       $TextColor = 'White' }
        'SKIP' { $Symbol = $script:Icon.SKIP; $IconColor = 'DarkGray';   $TextColor = 'DarkGray' }
        'SIM'  { $Symbol = $script:Icon.SIM;  $IconColor = 'DarkYellow'; $TextColor = 'DarkYellow' }
    }
    Write-Host ((" " * $Indent) + $Symbol + "  ") -NoNewline -ForegroundColor $IconColor
    if ($Detail) {
        Write-Host $Message -NoNewline -ForegroundColor $TextColor
        Write-Host ("  " + $Detail) -ForegroundColor DarkGray
    }
    else {
        Write-Host $Message -ForegroundColor $TextColor
    }
}

# Historical names kept so every existing call site gets the new look
function Write-Ok    { param([string]$Text) Write-Status OK   $Text }
function Write-Warn2 { param([string]$Text) Write-Status WARN $Text }
function Write-Fail  { param([string]$Text) Write-Status FAIL $Text }

# Section title kept for compatibility (used by the diff computation screen)
function Write-SectionBox {
    param([string]$Title)
    Write-Header $Title
}

# Aligned "Label      value" row, optional leading icon and dimmed detail
function Write-KeyValue {
    param(
        [string]$Key,
        [string]$Value,
        [string]$ValueColor = "White",
        [int]$KeyWidth = 14,
        [string]$Symbol = "",
        [string]$SymbolColor = "Cyan",
        [string]$Detail = ""
    )
    Write-Host ("  " + $Key.PadRight($KeyWidth)) -NoNewline -ForegroundColor DarkGray
    if ($Symbol) { Write-Host ($Symbol + "  ") -NoNewline -ForegroundColor $SymbolColor }
    if ($Detail) {
        Write-Host $Value -NoNewline -ForegroundColor $ValueColor
        Write-Host ("  " + $Detail) -ForegroundColor DarkGray
    }
    else {
        Write-Host $Value -ForegroundColor $ValueColor
    }
}

# Framed result box (end of Apply / Simulation / Restore)
function Write-ResultBox {
    param(
        [string]$Title,
        [string]$Color = "Green",
        [string]$Symbol = "",
        [string[]]$Rows = @()
    )
    if (-not $Symbol) { $Symbol = $script:Icon.OK }
    Write-Host ""
    Write-BoxEdge Top $Color
    Write-BoxLine ($Symbol + "  " + $Title) -Color $Color -BorderColor $Color
    if ($Rows.Count -gt 0) {
        Write-BoxEdge Middle $Color
        foreach ($Row in $Rows) { Write-BoxLine $Row -Color White -BorderColor $Color }
    }
    Write-BoxEdge Bottom $Color
}

function Write-MenuGroup {
    param([string]$Title)
    Write-Host ""
    Write-Host ("  " + $Title.ToUpper()) -ForegroundColor DarkCyan
}

function Write-MenuItem {
    param(
        [string]$Key,
        [string]$Label,
        [string]$KeyColor = "Cyan",
        [string]$LabelColor = "White",
        [string]$Hint = ""
    )
    Write-Host "   " -NoNewline
    Write-Host (("[" + $Key + "]").PadRight(5)) -NoNewline -ForegroundColor $KeyColor
    if ($Hint) {
        Write-Host $Label -NoNewline -ForegroundColor $LabelColor
        Write-Host ("  (" + $Hint + ")") -ForegroundColor DarkGray
    }
    else {
        Write-Host $Label -ForegroundColor $LabelColor
    }
}

# [U6] Y/N confirmation — same accepted answers as before the UI overhaul
function Read-Confirm {
    param([string]$Question)
    Write-Host ""
    Write-Host ("  " + $script:Icon.WARN + "  ") -NoNewline -ForegroundColor Yellow
    Write-Host ($Question + " ") -NoNewline -ForegroundColor White
    Write-Host "[y/N] " -NoNewline -ForegroundColor DarkGray
    $Answer = Read-Host
    return ($Answer -in @('O','o','oui','OUI','y','Y','yes','YES'))
}

function Wait-ForMenu {
    Write-Host ""
    Write-Host "  Press " -NoNewline -ForegroundColor DarkGray
    Write-Host "Enter" -NoNewline -ForegroundColor White
    Write-Host " to return to the menu " -NoNewline -ForegroundColor DarkGray
    $null = Read-Host
}

function Wait-ForClose {
    Write-Host ""
    Write-Host "  Press " -NoNewline -ForegroundColor DarkGray
    Write-Host "Enter" -NoNewline -ForegroundColor White
    Write-Host " to close " -NoNewline -ForegroundColor DarkGray
    $null = Read-Host
}




# --- Console rendering of diff lines (aligned style: time · icon · category · policy: value) ---
$script:DiffIcons         = @{
    'WillApply' = [string][char]0x25B2   # triangle
    'Unchanged' = [string][char]0x25CB   # empty dot
    'Applied'   = [string][char]0x2714   # check
    'Failed'    = [string][char]0x2718   # cross
}
$script:DiffColors        = @{ 'WillApply' = 'Yellow'; 'Unchanged' = 'DarkGray'; 'Applied' = 'Green'; 'Failed' = 'Red' }
$script:DiffIconWidth     = 2
$script:DiffCategoryWidth = 16

function Write-DiffLine {
    param($Result)
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $icon  = $script:DiffIcons[$Result.Action];  if (-not $icon)  { $icon  = [string][char]0x25CB }
    $color = $script:DiffColors[$Result.Action]; if (-not $color) { $color = 'Gray' }
    $iconCol = $icon.PadRight($script:DiffIconWidth)
    $catCol  = $Result.Category.PadRight($script:DiffCategoryWidth)
    $valueText = if ($Result.Action -eq 'WillApply') {
        "$($Result.OldValue)  ->  $($Result.NewValue)"
    } else {
        "$($Result.NewValue)"
    }

    Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$iconCol " -NoNewline -ForegroundColor $color
    Write-Host "$catCol" -NoNewline -ForegroundColor DarkCyan
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($Result.PolicyName)" -NoNewline -ForegroundColor Gray
    Write-Host " : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$valueText" -ForegroundColor $color
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$((Get-Date).ToString('HH:mm:ss'))] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Test-IsAdmin { return $script:IsAdmin }

# Unambiguous display date (month name instead of numeric dd/MM vs MM/dd) so the
# script's dates read the same regardless of the machine's Windows region.
function Format-ReportDate {
    param([datetime]$Date = (Get-Date))
    return $Date.ToString('dd MMM yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
}

#endregion

#region POLICY DEFINITIONS

function Get-BravePolicyDefinitions {
    $defs = New-Object System.Collections.Generic.List[object]

    function New-Policy {
        param($Name, $Category, $Type, $TargetValue, $Rationale)
        [PSCustomObject]@{
            Name        = $Name
            Category    = $Category
            Type        = $Type
            TargetValue = $TargetValue
            Rationale   = $Rationale
        }
    }

    # --- BLOAT: unused proprietary Brave features -------------
    $defs.Add((New-Policy 'BraveRewardsDisabled'       'Bloat' 'DWord' 1 'Rewards not used'))
    $defs.Add((New-Policy 'BraveWalletDisabled'        'Bloat' 'DWord' 1 'Wallet not used'))
    $defs.Add((New-Policy 'BraveVPNDisabled'           'Bloat' 'DWord' 1 'Brave VPN not used'))
    $defs.Add((New-Policy 'BraveAIChatEnabled'         'Bloat' 'DWord' 0 'Leo AI not used'))
    $defs.Add((New-Policy 'BraveNewsDisabled'          'Bloat' 'DWord' 1 'Brave News not used'))
    $defs.Add((New-Policy 'BraveTalkDisabled'          'Bloat' 'DWord' 1 'Brave Talk not used'))
    $defs.Add((New-Policy 'BraveSpeedreaderEnabled'    'Bloat' 'DWord' 0 'Speedreader not used'))
    $defs.Add((New-Policy 'BraveWaybackMachineEnabled' 'Bloat' 'DWord' 0 'Wayback Machine not used'))
    $defs.Add((New-Policy 'BravePlaylistEnabled'       'Bloat' 'DWord' 0 'Playlist not used'))
    $defs.Add((New-Policy 'SyncDisabled'               'Bloat' 'DWord' 1 'Brave Sync not used'))
    $defs.Add((New-Policy 'TorDisabled'                'Bloat' 'DWord' 1 'Brave Tor window not used'))

    # --- BLOAT v3: UI cleanup + underlying Chromium AI layer ----------
    # Brave doesn't natively use these Google features, but they exist
    # in the underlying Chromium engine — might as well close the door.
    $defs.Add((New-Policy 'PromotionalTabsEnabled'              'Bloat' 'DWord' 0 'Cuts promotional tabs at startup'))
    $defs.Add((New-Policy 'PromotionsEnabled'                   'Bloat' 'DWord' 0 'Cuts internal banners/promos'))
    $defs.Add((New-Policy 'NTPCardsVisible'                     'Bloat' 'DWord' 0 'Removes cards from the new-tab page'))
    $defs.Add((New-Policy 'NTPMiddleSlotAnnouncementVisible'    'Bloat' 'DWord' 0 'Removes the announcement banner from the new-tab page'))
    $defs.Add((New-Policy 'HideWebStoreIcon'                    'Bloat' 'DWord' 1 'Hides the Web Store promo icon (does not prevent installing extensions)'))
    $defs.Add((New-Policy 'BrowserLabsEnabled'                  'Bloat' 'DWord' 0 'Removes the "Labs" (experimental features) button from the toolbar'))
    # Enum 0=Allowed / 1=Not allowed for these two (verified — do not set back to 0)
    $defs.Add((New-Policy 'GeminiSettings'                      'Bloat' 'DWord' 1 'Disables Gemini integration in the Chromium engine (0=allowed, 1=disabled)'))
    $defs.Add((New-Policy 'GeminiActOnWebSettings'               'Bloat' 'DWord' 1 'Disables Gemini auto-browse (AI agent acting on pages) (0=allowed, 1=disabled)'))
    # Enum 0=Allow+improve models / 1=Allow without sharing / 2=Disabled (verified)
    $defs.Add((New-Policy 'HelpMeWriteSettings'                 'Bloat' 'DWord' 2 'Disables the AI "Help me write" feature (0/1=active, 2=disabled)'))
    $defs.Add((New-Policy 'TabCompareSettings'                  'Bloat' 'DWord' 2 'Disables AI-assisted tab comparison (0/1=active, 2=disabled)'))

    # --- TELEMETRY -------------------------------------------------------
    $defs.Add((New-Policy 'BraveP3AEnabled'           'Telemetry' 'DWord' 0 'Cuts P3A (Privacy-Preserving Product Analytics)'))
    $defs.Add((New-Policy 'BraveStatsPingEnabled'     'Telemetry' 'DWord' 0 'Cuts the daily stats ping (laptop-updates.brave.com stays REACHABLE for updates, the policy only cuts the ping)'))
    $defs.Add((New-Policy 'BraveWebDiscoveryEnabled'  'Telemetry' 'DWord' 0 'Cuts the Web Discovery Project (already hardened on the hosts side: patterns.wdp.brave.com / collector.wdp.brave.com)'))
    $defs.Add((New-Policy 'MetricsReportingEnabled'   'Telemetry' 'DWord' 0 'Cuts generic Chromium crash/usage reporting'))
    $defs.Add((New-Policy 'AlternateErrorPagesEnabled' 'Telemetry' 'DWord' 0 'Prevents Brave from contacting Google for navigation error pages'))
    $defs.Add((New-Policy 'PaymentMethodQueryEnabled'  'Telemetry' 'DWord' 0 'Prevents sites from detecting your saved payment methods'))
    $defs.Add((New-Policy 'SearchSuggestEnabled'       'Telemetry' 'DWord' 0 'Cuts sending your keystrokes in real time to the suggestions engine'))
    $defs.Add((New-Policy 'UserFeedbackAllowed'        'Telemetry' 'DWord' 0 'Disables the option to send feedback/reports to Brave'))

    # --- TELEMETRY v3 -------------------------------------------------------
    $defs.Add((New-Policy 'UrlKeyedAnonymizedDataCollectionEnabled' 'Telemetry' 'DWord' 0 'Cuts collection of data tied to browsing history despite the "anonymized" name'))
    $defs.Add((New-Policy 'SafeBrowsingExtendedReportingEnabled'    'Telemetry' 'DWord' 0 'Cuts sending extra data to Google beyond baseline Safe Browsing'))
    $defs.Add((New-Policy 'WebRtcEventLogCollectionAllowed'         'Telemetry' 'DWord' 0 'Prevents sending WebRTC logs to Google'))
    $defs.Add((New-Policy 'FeedbackSurveysEnabled'                  'Telemetry' 'DWord' 0 'Cuts satisfaction surveys (telemetry disguised as UX)'))
    $defs.Add((New-Policy 'CloudReportingEnabled'                   'Telemetry' 'DWord' 0 'No effect on an unenrolled personal machine, but consistent defense in depth'))

    # --- NETWORK -------------------------------------------------------------
    # WARNING known regression: 0 or 1 = prediction ACTIVE. Only 2 actually
    # disables DNS prefetch + preconnect. Never set this back to 0.
    $defs.Add((New-Policy 'NetworkPredictionOptions' 'Network' 'DWord' 2 'Disables DNS prefetch + preconnect (2=never; 0/1=active, do not confuse)'))
    $defs.Add((New-Policy 'BackgroundModeEnabled'    'Network' 'DWord' 0 'Prevents Brave from running in the background after closing'))

    # --- NETWORK v3 -------------------------------------------------------------
    # Verified String value: "default_public_interface_only" prevents WebRTC
    # from revealing the local/private IP even behind a VPN/proxy.
    $defs.Add((New-Policy 'WebRtcIPHandling'      'Network' 'String' 'default_public_interface_only' 'Prevents local IP leakage via WebRTC, even under VPN/proxy'))
    # Forces the OS DNS resolver instead of Chromium's internal resolver,
    # to stay consistent with NextDNS (same logic as an unset DnsOverHttpsMode).
    $defs.Add((New-Policy 'BuiltInDnsClientEnabled' 'Network' 'DWord' 0 'Forces the OS DNS resolver (consistency with NextDNS)'))
    $defs.Add((New-Policy 'WPADQuickCheckEnabled'   'Network' 'DWord' 0 'Cuts automatic WPAD proxy detection on every network connection (reduces WPAD spoofing surface)'))

    # --- SECURITY / UPDATES --------------------------------------------
    # ComponentUpdatesEnabled=1 is deliberate: this isn't just the Brave
    # binary, it also covers Widevine, Safe Browsing lists, and the root
    # certificate store. Never disable.
    $defs.Add((New-Policy 'ComponentUpdatesEnabled' 'Security' 'DWord' 1 'DO NOT DISABLE — security component updates (Widevine, certs, Safe Browsing)'))
    $defs.Add((New-Policy 'HttpsUpgradesEnabled'    'Security' 'DWord' 1 'Forces HTTPS when available'))

    $sbLevel = switch ($SafeBrowsingLevel) { 'Off' {0} 'Standard' {1} 'Enhanced' {2} }
    $sbNote  = switch ($SafeBrowsingLevel) {
        'Off'      { 'Safe Browsing disabled — not recommended' }
        'Standard' { 'Local lists, no real-time sharing with Google' }
        'Enhanced' { 'Better detection, but URLs + page samples sent to Google continuously' }
    }
    $defs.Add((New-Policy 'SafeBrowsingProtectionLevel' 'Security' 'DWord' $sbLevel $sbNote))

    # --- SECURITY v3 -----------------------------------------------------------
    $defs.Add((New-Policy 'RemoteDebuggingAllowed'                   'Security' 'DWord' 0 'Prevents any external tool from attaching to Brave''s remote debugging port'))
    $defs.Add((New-Policy 'BasicAuthOverHttpEnabled'                 'Security' 'DWord' 0 'Blocks HTTP Basic authentication sent in cleartext'))
    $defs.Add((New-Policy 'AmbientAuthenticationInPrivateModesEnabled' 'Security' 'DWord' 0 'Prevents automatic NTLM/Kerberos auth from leaking Windows credentials in private browsing'))
    $defs.Add((New-Policy 'AllowCrossOriginAuthPrompt'               'Security' 'DWord' 0 'Blocks spoofing via cross-origin authentication pop-ups'))
    $defs.Add((New-Policy 'SignedHTTPExchangeEnabled'                'Security' 'DWord' 0 'Disables Signed HTTP Exchanges (can mask a page''s real origin)'))

    # --- PRIVACY SANDBOX -----------------------------------------------------
    $defs.Add((New-Policy 'PrivacySandboxAdTopicsEnabled'       'PrivacySandbox' 'DWord' 0 'Cuts the Topics API (ad profiling) — OBSOLETE on the Chromium side, kept for compat. with older versions'))
    $defs.Add((New-Policy 'PrivacySandboxPromptEnabled'         'PrivacySandbox' 'DWord' 0 'Suppresses the Privacy Sandbox prompt — OBSOLETE on the Chromium side, kept for compat. with older versions'))
    $defs.Add((New-Policy 'PrivacySandboxSiteEnabledAdsEnabled' 'PrivacySandbox' 'DWord' 0 'Cuts per-site ad APIs — OBSOLETE on the Chromium side, kept for compat. with older versions'))
    # Active replacement: the 3 rules above are marked "Deprecated" in
    # brave://policy/ (export from 07/04/2026) — Chromium restructured the
    # Privacy Sandbox API. This is the currently effective rule.
    $defs.Add((New-Policy 'PrivacySandboxAdMeasurementEnabled'  'PrivacySandbox' 'DWord' 0 'Cuts the Attribution Reporting API (cross-site ad measurement) — replaces the 3 deprecated rules above'))

    # --- PERFORMANCE -----------------------------------------------------------
    $defs.Add((New-Policy 'HighEfficiencyModeEnabled' 'Performance' 'DWord' 1 'Memory Saver active'))
    # Level 1 = Balanced (ML estimates the probability of returning to the tab
    # before unloading it). Level 2 = Maximum, ruled out: too many surprise
    # reloads for multi-tab usage with 16 GB of RAM available.
    $defs.Add((New-Policy 'MemorySaverModeSavings' 'Performance' 'DWord' 1 'Strengthens Memory Saver to Balanced mode (0=Moderate, 1=Balanced, 2=Maximum)'))

    # --- LOCKDOWN (opt-in via -IncludeLockdown) ---------------------------
    # These are NOT data leaks: they are feature losses. Only enable if
    # it's a deliberate choice.
    # NOTE: TranslateEnabled and SpellcheckEnabled/SpellcheckServiceEnabled
    # are deliberately ABSENT here (and from the whole script) — page
    # translation and spellcheck (including the online service) are
    # features actually used. The script does not touch them.
    if ($IncludeLockdown) {
        $defs.Add((New-Policy 'PasswordManagerEnabled'    'Lockdown' 'DWord' 0 'Disables the built-in password manager'))
        $defs.Add((New-Policy 'AutofillAddressEnabled'    'Lockdown' 'DWord' 0 'Disables address autofill'))
        $defs.Add((New-Policy 'AutofillCreditCardEnabled' 'Lockdown' 'DWord' 0 'Disables card autofill'))
        $defs.Add((New-Policy 'DeveloperToolsAvailability' 'Lockdown' 'DWord' 0 'Left at 0 (allowed) by default even under Lockdown — a personal machine needs DevTools'))
        $defs.Add((New-Policy 'IncognitoModeAvailability'  'Lockdown' 'DWord' 0 'Left at 0 (allowed) — restricting incognito only makes sense on a shared machine'))
    }

    # --- DNS-over-HTTPS (explicit opt-in only) ------------------------
    if ($DnsOverHttpsTemplate) {
        $defs.Add((New-Policy 'DnsOverHttpsMode'      'Network' 'String' 'secure' 'DoH forced on the Brave side (check that it does not bypass NextDNS)'))
        $defs.Add((New-Policy 'DnsOverHttpsTemplates' 'Network' 'String' $DnsOverHttpsTemplate 'DoH endpoint explicitly provided via -DnsOverHttpsTemplate'))
    }

    return $defs
}

#endregion

#region REGISTRY READ / APPLY

function Get-CurrentPolicyValue {
    param([string]$Name)
    if (-not (Test-Path $RegPath)) { return $null }
    $item = Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function Add-Result {
    param($PolicyName, $Category, $PreviousValue, $TargetValue, $Action, $Note = '')
    $script:Results.Add([PSCustomObject]@{
        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        PolicyName     = $PolicyName
        Category       = $Category
        OldValue       = if ($null -eq $PreviousValue) { '<not set>' } else { $PreviousValue }
        NewValue       = $TargetValue
        Action         = $Action
        Note           = $Note
    })
}

function Set-BravePolicy {
    param($Policy, [bool]$PreviewOnly)

    $current = Get-CurrentPolicyValue -Name $Policy.Name
    $currentStr = if ($null -eq $current) { $null } else { [string]$current }
    $targetStr  = [string]$Policy.TargetValue

    if ($currentStr -eq $targetStr) {
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'Unchanged' $Policy.Rationale
        return
    }

    if ($PreviewOnly) {
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'WillApply' $Policy.Rationale
        return
    }

    try {
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        $regType = if ($Policy.Type -eq 'String') { 'String' } else { 'DWord' }
        New-ItemProperty -Path $RegPath -Name $Policy.Name -Value $Policy.TargetValue -PropertyType $regType -Force | Out-Null
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'Applied' $Policy.Rationale
    }
    catch {
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'Failed' $_.Exception.Message
    }
}

#endregion

#region BACKUP / RESTORE (registry)

function Backup-BravePolicies {
    if (-not (Test-Path $BackupFolder)) { New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $backupPath = Join-Path $BackupFolder "BravePolicies_backup_$stamp.reg"

    try {
        if (Test-Path $RegPath) {
            $null = reg export $RegPathWin $backupPath /y 2>&1
        }
        else {
            # Absence marker: lets Restore know it must delete the whole key
            # rather than import an empty .reg file.
            "; BRAVE-DEBLOAT — no policy was present before applying (key absent)." |
                Out-File -FilePath $backupPath -Encoding UTF8
        }
        Write-Ok "Backup created"
        Write-Host "       $backupPath" -ForegroundColor DarkGray
        Write-Log "Backup created: $backupPath"

        $all = Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' |
            Sort-Object LastWriteTime -Descending
        if ($all.Count -gt $BackupMaxCount) {
            $all | Select-Object -Skip $BackupMaxCount | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        return $backupPath
    }
    catch {
        Write-Fail "Backup failed: $_"
        Write-Log "Backup failed: $_" "ERROR"
        return $null
    }
}

function Restore-BravePolicies {
    Clear-Host
    Write-Banner "RESTORE BRAVE POLICIES" 'Red' -Subtitle "Registry state restored from the latest backup"

    if (-not (Test-Path $BackupFolder) -or (Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' -ErrorAction SilentlyContinue).Count -eq 0) {
        Write-Host ""
        Write-Warn2 "No backup available in $BackupFolder"
        Wait-ForMenu
        return
    }

    $latest = Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    Write-Host ""
    Write-Host "  This action restores the Brave registry state from:" -ForegroundColor White
    Write-Host "  $($latest.FullName)" -ForegroundColor DarkCyan
    Write-Host "  ($(Format-ReportDate $latest.LastWriteTime))" -ForegroundColor DarkGray

    if (-not (Read-Confirm "Confirm the restore?")) {
        Write-Status SKIP "Cancelled."
        Wait-ForMenu
        return
    }

    # Safety backup of the current state before restoring
    Write-Header "Backing up the current state before restoring"
    Backup-BravePolicies | Out-Null

    Write-Header "Restoring"
    try {
        $content = Get-Content -Path $latest.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '^; BRAVE-DEBLOAT') {
            if (Test-Path $RegPath) { Remove-Item -Path $RegPath -Recurse -Force }
            Write-Ok "Brave policy key removed (no policy was present originally)."
        }
        else {
            if (Test-Path $RegPath) { Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue }
            $null = reg import $latest.FullName 2>&1
            Write-Ok "Registry restored from backup."
        }
        Write-Log "Restore performed from $($latest.FullName)"
        Write-StateSnapshot -Action 'Restore'
        Write-ResultBox "RESTORE COMPLETE" 'Green' $script:Icon.OK @("Brave policies restored from the latest backup.")
        Write-Host ""
        Write-Warn2 "Restart Brave to apply."
    }
    catch {
        Write-Fail "Restore failed: $_"
        Write-Log "Restore failed: $_" "ERROR"
    }

    Wait-ForMenu
}

function Show-Backups {
    Clear-Host
    Write-Banner "AVAILABLE BACKUPS" -Subtitle "Registry snapshots taken before every change"

    if (-not (Test-Path $BackupFolder)) {
        Write-Host ""
        Write-Status SKIP "No backup found."
        Write-Host "       Folder not created — no policy has been applied yet." -ForegroundColor DarkGray
    }
    else {
        $backups = @(Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' | Sort-Object LastWriteTime -Descending)
        if ($backups.Count -eq 0) {
            Write-Host ""
            Write-Status SKIP "No backup found in $BackupFolder"
        }
        else {
            Write-Header "$($backups.Count) backup(s)"
            Write-Host ("  {0,-22}{1,-46}{2,8}" -f "Date", "File", "Size") -ForegroundColor DarkGray
            Write-Host ("  " + ($script:Box.Line * 76)) -ForegroundColor DarkGray
            foreach ($b in $backups) {
                $size = [Math]::Round($b.Length / 1KB, 1)
                Write-Host ("  {0,-22}" -f (Format-ReportDate $b.LastWriteTime)) -NoNewline -ForegroundColor White
                Write-Host ("{0,-46}" -f $b.Name) -NoNewline -ForegroundColor Gray
                Write-Host ("{0,8}" -f "$size KB") -ForegroundColor DarkGray
            }
            Write-Host ""
            Write-KeyValue "Folder" $BackupFolder "Gray" -KeyWidth 8
            Write-Host ""
            Write-Host "  Restore (menu) always uses the most recent one." -ForegroundColor DarkCyan
        }
    }

    Wait-ForMenu
}

#endregion

#region STATE / INTEGRITY / CONFLICTS

function Write-StateSnapshot {
    param([string]$Action)
    try {
        if (-not (Test-Path $ReportRoot)) { New-Item -Path $ReportRoot -ItemType Directory -Force | Out-Null }
        $applied = ($script:Results | Where-Object { $_.Action -eq 'Applied' }).Count
        $failed  = ($script:Results | Where-Object { $_.Action -eq 'Failed' }).Count
        [PSCustomObject]@{
            Timestamp = Format-ReportDate
            Action    = $Action
            Applied   = $applied
            Failed    = $failed
        } | ConvertTo-Json | Out-File -FilePath $StateFile -Encoding UTF8 -Force
    }
    catch {
        Write-Log "Failed to write state: $_" "WARN"
    }
}

function Get-LastAppliedInfo {
    if (-not (Test-Path $StateFile)) { return $null }
    try { return (Get-Content -Path $StateFile -Raw | ConvertFrom-Json) }
    catch { return $null }
}

function Get-IntegrityStatus {
    # Read-only comparison, no side effects — reused by the menu (compact
    # indicator) and by Test-Integrity (detailed display).
    $defs = Get-BravePolicyDefinitions
    $missing = @()

    foreach ($p in $defs) {
        $cur = Get-CurrentPolicyValue -Name $p.Name
        $curStr = if ($null -eq $cur) { $null } else { [string]$cur }
        if ($curStr -ne [string]$p.TargetValue) { $missing += $p.Name }
    }

    $extra = @()
    if (Test-Path $RegPath) {
        $props = (Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }
        foreach ($prop in $props) {
            if ($prop.Name -notin $defs.Name) { $extra += $prop.Name }
        }
    }

    $presentCount = $defs.Count - $missing.Count

    return [PSCustomObject]@{
        Active   = ($presentCount -gt 0)
        Expected = $defs.Count
        Present  = $presentCount
        Missing  = @($missing)
        Extra    = @($extra)
    }
}

function Test-Integrity {
    Clear-Host
    Write-Banner "POLICY INTEGRITY CHECK" -Subtitle "Defined policies vs. actually active values"

    $status = Get-IntegrityStatus

    Write-Header "Comparing with the registry"
    Write-KeyValue "Expected" "$($status.Expected) policies" "White" -KeyWidth 10
    Write-KeyValue "Active"   "$($status.Present) policies"  "White" -KeyWidth 10
    Write-Host ""

    if ($status.Missing.Count -eq 0 -and $status.Extra.Count -eq 0) {
        Write-Ok "Perfect integrity — all defined policies are correctly applied."
        Write-Log "Integrity check: OK ($($status.Present) policies)"
    }
    else {
        if ($status.Missing.Count -gt 0) {
            Write-Warn2 "$($status.Missing.Count) policy(ies) out of sync (missing or different value):"
            foreach ($m in $status.Missing | Sort-Object) { Write-Host "       $($script:Icon.Dot) $m" -ForegroundColor DarkYellow }
            Write-Host ""
            Write-Host "  Use option [1] or [2] to (re)apply them." -ForegroundColor DarkGray
            Write-Log "Integrity check: $($status.Missing.Count) policies out of sync" "WARN"
        }
        if ($status.Extra.Count -gt 0) {
            Write-Host ""
            Write-Status INFO "$($status.Extra.Count) value(s) present in the registry but no longer defined by this script:"
            foreach ($e in $status.Extra | Sort-Object) { Write-Host "       $($script:Icon.Dot) $e" -ForegroundColor DarkGray }
            Write-Host ""
            Write-Host "  Likely leftovers from an older version or another tool (e.g. GitHub files)." -ForegroundColor DarkGray
            Write-Host "  Use option [2] Update to clean them up." -ForegroundColor DarkGray
        }
    }

    Wait-ForMenu
}

function Test-Conflicts {
    Clear-Host
    Write-Banner "CONFLICT DETECTION" -Subtitle "User-level policies, Recommended subkey, leftovers"

    $foundAny = $false

    Write-Header "Scope (HKCU)"
    if (Test-Path $HkcuRegPath) {
        $foundAny = $true
        Write-Warn2 "Policies also defined at the user level (HKCU):"
        $hkcuProps = (Get-ItemProperty -Path $HkcuRegPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }
        foreach ($p in $hkcuProps) { Write-Host "       $($script:Icon.Dot) $($p.Name) = $($p.Value)" -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host "  HKLM (machine) generally takes precedence over HKCU, but the redundancy can be confusing." -ForegroundColor DarkGray
    }
    else {
        Write-Ok "No policy defined at the user level (HKCU) — no scope conflict."
    }

    Write-Header "Recommended subkey"
    if (Test-Path $RecommendedPath) {
        $foundAny = $true
        Write-Warn2 "'Recommended' subkey present under $RegPath :"
        $recProps = (Get-ItemProperty -Path $RecommendedPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }
        foreach ($p in $recProps) { Write-Host "       $($script:Icon.Dot) $($p.Name) = $($p.Value)" -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host "  These are default values you can change in Brave (not mandatory) — check they don't mask what you expect." -ForegroundColor DarkGray
    }
    else {
        Write-Ok "No 'Recommended' subkey — no competing non-mandatory policies."
    }

    Write-Header "Leftovers"
    $status = Get-IntegrityStatus
    if ($status.Extra.Count -gt 0) {
        $foundAny = $true
        Write-Warn2 "$($status.Extra.Count) residual value(s) in $RegPath not defined by this script (see [9] integrity for detail)."
    }
    else {
        Write-Ok "No leftovers detected in $RegPath."
    }

    if (-not $foundAny) {
        Write-Host ""
        Write-Ok "No conflicts detected."
    }

    Wait-ForMenu
}

#endregion

#region ACTIONS: APPLY / SIMULATE / UPDATE

function Invoke-BraveAction {
    param([bool]$Simulation, [bool]$ForceUpdate)

    Clear-Host
    if ($Simulation) {
        Write-Banner "SIMULATION (DRYRUN)" 'DarkYellow' -Subtitle "No changes will be made to your system"
    }
    elseif ($ForceUpdate) {
        Write-Banner "UPDATE" 'Yellow' -Subtitle "Clean up leftovers + re-apply all policies"
    }
    else {
        Write-Banner "APPLYING BRAVE POLICIES" 'Yellow' -Subtitle "Diff  $($script:Icon.Dot)  backup  $($script:Icon.Dot)  write  $($script:Icon.Dot)  report"
    }

    $defs = Get-BravePolicyDefinitions
    $defsToApply = if ($Category) { $defs | Where-Object { $_.Category -in $Category } } else { $defs }

    if ($defsToApply.Count -eq 0) {
        Write-Host ""
        Write-Fail "No policy matches the given -Category filter."
        Wait-ForMenu
        return
    }

    $script:Results.Clear()
    Write-SectionBox "Computing diff — current state vs target"
    foreach ($p in $defsToApply) { Set-BravePolicy -Policy $p -PreviewOnly $true }

    $toChange = $script:Results | Where-Object { $_.Action -eq 'WillApply' }
    Write-Host ""
    Write-Host "   $($defsToApply.Count) policies evaluated  $($script:Icon.Dot)  " -NoNewline -ForegroundColor Cyan
    if ($toChange.Count -eq 0) {
        Write-Host "no change needed" -ForegroundColor Green
    } else {
        Write-Host "$($toChange.Count) change(s) needed" -ForegroundColor Yellow
    }
    Write-Host ""
    foreach ($r in $script:Results) { Write-DiffLine $r }

    if ($Simulation) {
        Write-Host ""
        Write-Status SIM "Simulation mode: no change applied."
        $report = Export-BraveReport -Action 'Simulation'
        Write-Ok "HTML report created"
        Write-Host "       $($report.Html)" -ForegroundColor DarkGray
        Write-Log "Simulation run ($($toChange.Count) potential change(s))"
        Write-ResultBox "SIMULATION COMPLETE" 'DarkYellow' $script:Icon.SIM @(
            ("{0,-20}{1}" -f "Policies evaluated", $defsToApply.Count),
            ("{0,-20}{1}" -f "Would change", @($toChange).Count),
            "No changes were made."
        )
        Wait-ForMenu
        return
    }

    if ($toChange.Count -eq 0 -and -not $ForceUpdate) {
        Write-Host ""
        Write-Ok "Nothing to do, all targeted policies are already up to date."
        Export-BraveReport -Action 'NoChange' | Out-Null
        Wait-ForMenu
        return
    }

    if (-not (Read-Confirm "Apply these changes?")) {
        Write-Status SKIP "Cancelled."
        Wait-ForMenu
        return
    }

    Write-Header "Backing up before change"
    Backup-BravePolicies | Out-Null

    if ($ForceUpdate) {
        Write-Header "Cleaning up leftovers (policies not defined by the script's current version)"
        $status = Get-IntegrityStatus
        if ($status.Extra.Count -gt 0) {
            foreach ($name in $status.Extra) {
                try {
                    Remove-ItemProperty -Path $RegPath -Name $name -ErrorAction Stop
                    Write-Ok "Leftover removed: $name"
                    Write-Log "Leftover removed: $name"
                }
                catch {
                    Write-Fail "Could not remove $name : $_"
                }
            }
        }
        else {
            Write-Ok "Nothing to clean up."
        }
    }

    $script:Results.Clear()
    Write-Header "Applying policies"
    foreach ($p in $defsToApply) { Set-BravePolicy -Policy $p -PreviewOnly $false }

    $applied = ($script:Results | Where-Object Action -eq 'Applied').Count
    $failed  = ($script:Results | Where-Object Action -eq 'Failed').Count

    $actionLabel = if ($ForceUpdate) { 'Update' } else { 'Apply' }
    $report = Export-BraveReport -Action $actionLabel
    Write-StateSnapshot -Action $actionLabel
    Write-Log "$actionLabel : $applied applied, $failed failed"

    $rows = @(
        ("{0,-20}{1}" -f "Policies applied", $applied),
        ("{0,-20}{1}" -f "Failures", $failed)
    )
    if ($failed -eq 0) {
        Write-ResultBox "POLICIES APPLIED SUCCESSFULLY" 'Green' $script:Icon.OK $rows
    }
    else {
        Write-ResultBox "APPLIED WITH FAILURES" 'Yellow' $script:Icon.WARN $rows
    }

    Write-Host ""
    Write-KeyValue "CSV report"  $report.Csv  "DarkGray" -KeyWidth 13
    Write-KeyValue "JSON report" $report.Json "DarkGray" -KeyWidth 13
    Write-KeyValue "HTML report" $report.Html "DarkGray" -KeyWidth 13

    Write-Host ""
    Write-Warn2 "Fully restart Brave (close all processes) to apply."
    Write-Warn2 "Then verify on brave://policy"

    Show-Toast -Title "Brave-Debloat" -Message "$applied policy(ies) applied, $failed failure(s)."

    Wait-ForMenu
}

function Flush-DNSCache {
    Clear-Host
    Write-Banner "FLUSH DNS CACHE" -Subtitle "ipconfig /flushdns"
    Write-Host ""
    try {
        ipconfig /flushdns | Out-Null
        Write-Ok "DNS cache flushed"
        Write-Log "DNS cache flushed manually"
    }
    catch {
        Write-Warn2 "Could not flush the DNS cache: $_"
    }
    Wait-ForMenu
}

function Export-ActivePolicies {
    Clear-Host
    Write-Banner "EXPORT ACTIVE LIST" -Subtitle "Plain-text snapshot of the registry vs. target"

    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $exportPath = Join-Path $env:USERPROFILE "Desktop\Maintenance_Reports\Brave-Debloat\Brave-Debloat_Export_$stamp.txt"
    $defs = Get-BravePolicyDefinitions | Sort-Object Category, Name

    $lines = @()
    $lines += "# ====================================================="
    $lines += "# BRAVE-DEBLOAT v$ScriptVersion — Active policies export"
    $lines += "# Generated on $(Format-ReportDate)"
    $lines += "# ====================================================="
    $lines += ""

    $currentCat = ""
    foreach ($p in $defs) {
        if ($p.Category -ne $currentCat) {
            $lines += ""
            $lines += "# --- $($p.Category) ---"
            $currentCat = $p.Category
        }
        $cur = Get-CurrentPolicyValue -Name $p.Name
        $curStr = if ($null -eq $cur) { '<not set>' } else { $cur }
        $status = if ([string]$cur -eq [string]$p.TargetValue) { 'OK' } else { 'OUT_OF_SYNC' }
        $lines += "$($p.Name) = $curStr (target: $($p.TargetValue)) [$status]"
    }

    $status = Get-IntegrityStatus
    if ($status.Extra.Count -gt 0) {
        $lines += ""
        $lines += "# --- Leftovers (not defined by this script) ---"
        foreach ($e in $status.Extra | Sort-Object) {
            $lines += "$e = $(Get-CurrentPolicyValue -Name $e) [LEFTOVER]"
        }
    }

    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($exportPath, $lines, $encoding)
        Write-Host ""
        Write-Ok "Export created"
        Write-Host "       $exportPath" -ForegroundColor DarkGray
        Write-Log "Export created: $exportPath"
    }
    catch {
        Write-Host ""
        Write-Fail "Could not create the export: $_"
    }

    Wait-ForMenu
}

#endregion

#region REPORTS (CSV / JSON / HTML)

function Export-BraveReport {
    param([string]$Action)

    if (-not (Test-Path $ReportRoot)) { New-Item -Path $ReportRoot -Force -ItemType Directory | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $base  = Join-Path $ReportRoot "Brave-Debloat_$stamp"

    $script:Results | Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8

    $byCat = $script:Results | Group-Object Category | ForEach-Object {
        [PSCustomObject]@{
            Category  = $_.Name
            Policies  = $_.Count
            Applied   = ($_.Group | Where-Object { $_.Action -eq 'Applied' -or $_.Action -eq 'WillApply' }).Count
            Unchanged = ($_.Group | Where-Object { $_.Action -eq 'Unchanged' }).Count
            Failed    = ($_.Group | Where-Object { $_.Action -eq 'Failed' }).Count
        }
    }
    $jsonObj = [PSCustomObject]@{
        Timestamp      = Format-ReportDate
        Action         = $Action
        TotalPolicies  = $script:Results.Count
        Applied        = ($script:Results | Where-Object { $_.Action -eq 'Applied' -or $_.Action -eq 'WillApply' }).Count
        Unchanged      = ($script:Results | Where-Object { $_.Action -eq 'Unchanged' }).Count
        Failed         = ($script:Results | Where-Object { $_.Action -eq 'Failed' }).Count
        ByCategory     = $byCat
        Detail         = $script:Results
    }
    $jsonObj | ConvertTo-Json -Depth 6 | Out-File -FilePath "$base.json" -Encoding UTF8

    $totalPolicies = $script:Results.Count
    $appliedCount  = ($script:Results | Where-Object { $_.Action -eq 'Applied' -or $_.Action -eq 'WillApply' }).Count
    $unchangedCount = ($script:Results | Where-Object { $_.Action -eq 'Unchanged' }).Count
    $failedCount    = ($script:Results | Where-Object { $_.Action -eq 'Failed' }).Count

    $rows = $script:Results | ForEach-Object {
        $rowClass = switch ($_.Action) {
            'Applied'     { 'row-ok' }
            'WillApply' { 'row-warn' }
            'Failed'        { 'row-fail' }
            default        { '' }
        }
        $badgeClass = switch ($_.Action) {
            'Applied'     { 'ok' }
            'WillApply' { 'warn' }
            'Unchanged'     { 'info' }
            'Failed'        { 'fail' }
            default        { 'info' }
        }
        $actionLabel = switch ($_.Action) {
            'Applied'     { 'Applied' }
            'WillApply' { 'Will apply' }
            'Unchanged'     { 'Unchanged' }
            'Failed'        { 'Failed' }
            default        { $_.Action }
        }
        "<tr class=`"$rowClass`"><td>$($_.PolicyName)</td><td class=`"cat-cell`">$($_.Category)</td><td class=`"detail`">$($_.OldValue)</td><td class=`"detail`">$($_.NewValue)</td><td><span class=`"badge $badgeClass`">$actionLabel</span></td><td class=`"detail`">$($_.Note)</td></tr>"
    }
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Brave-Debloat v$ScriptVersion — $env:COMPUTERNAME</title>
<style>
  :root {
    --bg: #080b12; --surface: #111827; --surface2: #1a2235;
    --border: #1e2d45; --text: #e2e8f0; --muted: #94a3b8;
    --ok: #a8ce81; --warn: #ffb347; --fail: #ef7066; --info: #7c6af7;
    --accent: #00d4ff; --accent2: #0099cc; --accent3: #005f80;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; }

  header { background: linear-gradient(160deg,#060c1a 0%,#0a1628 50%,#060a14 100%); border-bottom: 2px solid var(--accent3); padding: 32px 40px 24px; position: relative; overflow: hidden; }
  header::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06) 0%,transparent 60%), radial-gradient(ellipse at 80% 20%,rgba(124,106,247,.05) 0%,transparent 50%); pointer-events:none; }
  .titlerow { display:flex; align-items:flex-end; gap:0; position:relative; z-index:1; }
  .title-text h1 { font-family:'Cascadia Code','Consolas','Courier New',monospace; font-size:26px; font-weight:700; color:var(--accent); text-shadow:0 0 20px rgba(0,212,255,.4); letter-spacing:1px; margin:0 0 10px 0; }
  .logo-sub { font-family:'Cascadia Code','Consolas',monospace; font-size:12px; color:var(--muted); letter-spacing:2px; margin-bottom:14px; }
  .logo-sub b { color:var(--accent); }
  .meta-bar { display:flex; flex-wrap:wrap; gap:8px 24px; font-size:11.5px; color:#475569; border-top:1px solid var(--border); padding-top:12px; margin-top:4px; position:relative; z-index:1; }
  .meta-bar span { display:flex; align-items:center; gap:6px; }
  .meta-bar b { color:var(--muted); }
  .meta-dot { width:5px; height:5px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); }

  .container { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
  .stat-card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.ok   .num { color: var(--ok);   }
  .stat-card.warn .num { color: var(--warn);  }
  .stat-card.fail .num { color: var(--fail);  }
  .stat-card.info .num { color: var(--info);  }

  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 32px; }
  thead th { background: var(--surface2); padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); border-bottom: 1px solid var(--border); }
  tbody td { padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  .cat-cell { color: var(--accent); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
  .row-fail { background: rgba(239,112,102,0.05); }
  .row-warn { background: rgba(255,179,71,0.05); }
  .row-ok   { background: rgba(168,206,129,0.03); }
  .detail   { color: var(--muted); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge.ok   { background: rgba(168,206,129,0.15);  color: var(--ok);   border: 1px solid rgba(168,206,129,0.3);  }
  .badge.warn { background: rgba(255,179,71,0.15); color: var(--warn); border: 1px solid rgba(255,179,71,0.3); }
  .badge.fail { background: rgba(239,112,102,0.15);  color: var(--fail); border: 1px solid rgba(239,112,102,0.3);  }
  .badge.info { background: rgba(124,106,247,0.15); color: var(--info); border: 1px solid rgba(124,106,247,0.3); }

  footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 16px; }
</style>
</head>
<body>
<header>
  <div class="titlerow">
    <div class="title-text">
      <h1>Brave-Debloat v$ScriptVersion</h1>
      <div class="logo-sub">by <b>Nephren</b></div>
    </div>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="9.39 8.477 484.197 428.149" style="width:76px;height:76px;margin-left:24px;align-self:flex-end;filter:drop-shadow(0 0 12px rgba(0,212,255,.4));flex-shrink:0"><path d="m347.015 235.334 42.877-112.525 67.515 25.727-42.877 112.524z" fill="#a8ce81"/><path d="m303.267 350.143 42.92-112.634 67.514 25.726-42.919 112.634z" fill="#fddb1d"/><path d="m263.921 207.033 42.879-112.525 67.406 25.685-42.877 112.525z" fill="#ef7066"/><path d="m220.505 320.972 42.588-111.764 67.406 25.685-42.588 111.764z" fill="#6eaed7"/><path d="m415.69 247.559c-12.962-10.418-30.606-21.623-53.002-30.158-1.455-.43-2.827-1.077-4.131-1.574l33.307-87.41c1.755.295 3.277.875 4.893 1.864 22.194 8.083 39.661 19.097 52.64 29.147zm-44.284 116.221a216.14 216.14 0 0 0 -53.045-30.048c-1.496-.321-2.91-.86-4.131-1.574l34.136-89.586c1.673.513 3.236.984 4.893 1.865 22.153 8.192 39.62 19.206 52.392 29.8zm122.181-212.166s-25.485-37.351-81.827-59.07c-56.66-21.216-98.7-15.447-98.482-15.364l-15.038 39.466c-.135-.3 27.632-5.533 68.583 3.971l-33.597 88.172c-41.045-9.913-68.776-3.795-68.693-4.013l-10.29 27.33s27.736-7.111 69.123 2.558l-34.717 91.108c-33.74-8.499-58.772-7.828-67.506-6.798l-14.5 38.052c10.873-1.087 47.89-2.17 95.075 15.809 56.467 21.392 82.284 57.873 82.408 57.547zm-241.467-32.87 14.747-38.705 41.45-2.259-14.748 38.705zm-91.514 240.162 14.748-38.704 41.45-2.259-14.5 38.052zm16.364-42.944 13.38-35.117 41.492-2.367-13.423 35.225zm60.11-157.752 13.382-35.118 41.45-2.259-13.381 35.117zm-30.034 78.821 13.381-35.116 41.45-2.26-13.381 35.117zm-15.038 39.466 13.38-35.117 41.45-2.26-13.38 35.117zm30.035-78.823 13.422-35.225 41.45-2.259-13.423 35.225zm-10.213-90.174 11.476-30.115 40.145-2.756-11.766 30.876zm-110.927-84.974 4.93-12.937 16.36-1.112-4.93 12.937zm76.852 67.881 8.99-23.592 35.117-2.306-9.03 23.7zm-28.691-20.768 6.835-17.94 28.455-1.483-6.836 17.94zm-24.068-24.734 5.469-14.351 23.495-.884-5.179 13.59zm40.932 183.057 11.476-30.115 39.855-1.995-11.475 30.115zm-110.927-84.974 4.93-12.938 16.36-1.111-5.178 13.59zm76.852 67.881 9.031-23.7 35.077-2.198-9.032 23.7zm-28.691-20.769 6.835-17.938 28.455-1.484-6.835 17.939zm-24.067-24.734 5.22-13.698 23.743-1.536-5.179 13.59zm41.222 182.297 11.475-30.115 40.145-2.757-11.475 30.116zm-110.927-84.974 5.178-13.59 16.112-.46-4.93 12.938zm77.1 67.229 8.74-22.94 35.119-2.307-8.783 23.05zm-28.691-20.769 6.587-17.287 28.454-1.483-6.587 17.286zm-24.026-24.843 5.178-13.59 23.495-.883-5.178 13.59z" fill="#000101"/><path d="m114.017 84.174 4.889-12.83 17.411-1.582-4.888 12.829zm88.133 61.472 9.529-25.006 32.364-1.612-9.28 24.353zm-34.836-17.383 7.913-20.766 29.355-1.887-7.913 20.766zm-29.271-19.247 6.049-15.873 22.733-1.173-6.007 15.764zm-50.589-48.909 4.102-10.763 12.995-.776-4.101 10.764zm11.525 63.532 4.93-12.938 17.411-1.583-4.93 12.938zm88.133 61.472 9.57-25.114 32.612-2.265-9.528 25.006zm-34.588-18.035 7.664-20.113 29.397-1.996-7.954 20.874zm-29.478-18.703 6.007-15.764 22.734-1.174-5.758 15.112zm-50.63-48.8 4.392-11.525 12.995-.775-4.392 11.524z" fill="#ef7066"/><path d="m68.115 204.635 4.93-12.937 17.122-.822-4.93 12.938zm87.844 62.234 9.57-25.114 32.653-2.374-9.57 25.114zm-34.547-18.144 7.913-20.766 29.107-1.235-7.664 20.113zm-29.229-19.355 5.717-15.004 22.733-1.173-5.717 15.003zm-50.92-48.04 4.391-11.524 12.995-.776-4.35 11.416zm11.814 62.77 4.93-12.937 17.122-.822-4.93 12.938zm88.133 61.473 9.28-24.353 32.654-2.374-9.57 25.115zm-34.836-17.383 7.913-20.765 29.397-1.996-7.955 20.874zm-29.229-19.355 5.717-15.004 23.023-1.934-6.007 15.764zm-50.631-48.801 4.102-10.763 12.995-.775-4.101 10.763z" fill="#6eaed7"/></svg>
  </div>
  <div class="meta-bar">
    <span><span class="meta-dot"></span>Machine: <b>$env:COMPUTERNAME</b></span>
    <span>Date: <b>$(Format-ReportDate)</b></span>
    <span>Action: <b>$Action</b></span>
  </div>
</header>
<div class="container">

  <div class="summary-grid">
    <div class="stat-card info"><div class="num">$totalPolicies</div><div class="lbl">Total policies</div></div>
    <div class="stat-card ok"><div class="num">$appliedCount</div><div class="lbl">Applied</div></div>
    <div class="stat-card info"><div class="num">$unchangedCount</div><div class="lbl">Unchanged</div></div>
    <div class="stat-card fail"><div class="num">$failedCount</div><div class="lbl">Failed</div></div>
  </div>

  <table>
    <thead><tr><th>Policy</th><th>Category</th><th>Old value</th><th>New value</th><th>Action</th><th>Note</th></tr></thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table>

</div>
<footer>Brave-Debloat v$ScriptVersion — Report generated on $(Format-ReportDate)</footer>
</body>
</html>
"@
    $html | Out-File -FilePath "$base.html" -Encoding UTF8

    return @{ Csv = "$base.csv"; Json = "$base.json"; Html = "$base.html" }
}

function Show-GeneratedReport {
    Clear-Host
    Write-Banner "GENERATE HTML REPORT" -Subtitle "Current state vs target — CSV, JSON and HTML"

    $defs = Get-BravePolicyDefinitions
    $script:Results.Clear()
    foreach ($p in $defs) { Set-BravePolicy -Policy $p -PreviewOnly $true }

    $report = Export-BraveReport -Action 'ManualReport'
    Write-Host ""
    Write-Ok "Reports created"
    Write-KeyValue "CSV report"  $report.Csv  "DarkGray" -KeyWidth 13
    Write-KeyValue "JSON report" $report.Json "DarkGray" -KeyWidth 13
    Write-KeyValue "HTML report" $report.Html "DarkGray" -KeyWidth 13
    Write-Log "HTML report generated manually"

    try {
        Write-Host ""
        Write-Status INFO "Opening in your default browser..."
        Start-Process $report.Html -ErrorAction Stop
    }
    catch {
        Write-Warn2 "Could not open the report automatically: $_"
    }

    Wait-ForMenu
}

function Show-Toast {
    param([string]$Title, [string]$Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $icon = New-Object System.Windows.Forms.NotifyIcon
        $icon.Icon = [System.Drawing.SystemIcons]::Information
        $icon.Visible = $true
        $icon.ShowBalloonTip(4000, $Title, $Message, [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 4
        $icon.Dispose()
    } catch { }
}

#endregion

#region MAIN MENU

function Show-Menu {
    Clear-Host

    Write-Host ""
    Write-BoxEdge Top Cyan
    Write-BoxLine "" -BorderColor Cyan
    Write-BoxLine "BRAVE-DEBLOAT" -Color White -BorderColor Cyan -Center
    Write-BoxLine "Browser policies  $($script:Icon.Dot)  HKLM registry  $($script:Icon.Dot)  v$ScriptVersion" -Color DarkGray -BorderColor Cyan -Center
    Write-BoxLine "" -BorderColor Cyan
    Write-BoxEdge Bottom Cyan

    $status   = Get-IntegrityStatus
    $lastInfo = Get-LastAppliedInfo

    Write-Header "Status"

    if ($status.Present -gt 0) {
        Write-KeyValue "Policies" "ACTIVE" "Green" -Symbol $script:Icon.INFO -SymbolColor Green -Detail "$($status.Present)/$($status.Expected) applied"
    }
    else {
        Write-KeyValue "Policies" "No policy applied" "Gray" -Symbol $script:Icon.SKIP -SymbolColor DarkGray
    }

    if ($lastInfo) {
        Write-KeyValue "Last action" "$($lastInfo.Action) on $($lastInfo.Timestamp)" "Gray"
    }
    else {
        Write-KeyValue "Last action" "never run" "DarkGray"
    }

    if ($status.Present -eq 0) {
        Write-KeyValue "Integrity" "N/A (nothing applied)" "Gray" -Symbol $script:Icon.SKIP -SymbolColor DarkGray
    }
    elseif ($status.Missing.Count -eq 0 -and $status.Extra.Count -eq 0) {
        Write-KeyValue "Integrity" "Synced with the current definition" "Green" -Symbol $script:Icon.OK -SymbolColor Green
    }
    else {
        Write-KeyValue "Integrity" "$($status.Missing.Count) out of sync, $($status.Extra.Count) leftover(s)" "Yellow" -Symbol $script:Icon.WARN -SymbolColor Yellow -Detail "see [9]"
    }

    Write-MenuGroup "Policies"
    Write-MenuItem "1" "Apply changes" -KeyColor Yellow
    Write-MenuItem "2" "Update" -KeyColor Yellow -Hint "clean up leftovers + re-apply"
    Write-MenuItem "3" "Simulate without changing" -KeyColor DarkYellow -Hint "DryRun"
    Write-MenuItem "4" "RESTORE original settings" -KeyColor Red

    Write-MenuGroup "Backups & DNS"
    Write-MenuItem "5" "View available backups"
    Write-MenuItem "6" "Flush DNS cache manually"

    Write-MenuGroup "Reports & diagnostics"
    Write-MenuItem "7" "Generate an HTML report"
    Write-MenuItem "8" "Check for conflicts"
    Write-MenuItem "9" "Check policy integrity"
    Write-MenuItem "10" "Export the active list" -Hint ".txt"

    Write-Host ""
    Write-Rule
    Write-MenuItem "Q" "Quit" -KeyColor DarkGray -LabelColor Gray
    Write-Host ""
    Write-Host ("  " + $script:Icon.Arrow + " ") -NoNewline -ForegroundColor Cyan
    Write-Host "Choice: " -NoNewline -ForegroundColor White

    return (Read-Host)
}

#endregion

#region SELFTEST

function Invoke-SelfTest {
    Write-Banner "SELFTEST" -Subtitle "Brave-Debloat v$ScriptVersion  $($script:Icon.Dot)  read-only logic checks"
    Write-Host ""
    $tests = New-Object System.Collections.Generic.List[object]

    function T { param($Name, $Condition) $tests.Add([PSCustomObject]@{ Name = $Name; Pass = [bool]$Condition }) }

    $defs = Get-BravePolicyDefinitions

    T "At least one policy defined"                            ($defs.Count -gt 0)
    T "No duplicate policy name"                                (($defs.Name | Group-Object | Where-Object Count -gt 1).Count -eq 0)
    T "Every DWord policy has an integer TargetValue"           ((($defs | Where-Object Type -eq 'DWord') | ForEach-Object { $_.TargetValue -is [int] }) -notcontains $false)
    T "Every String policy has a string TargetValue"            ((($defs | Where-Object Type -eq 'String') | ForEach-Object { $_.TargetValue -is [string] }) -notcontains $false)

    $npo = $defs | Where-Object Name -eq 'NetworkPredictionOptions'
    T "NetworkPredictionOptions target = 2 (not 0/1)"           ($npo.TargetValue -eq 2)
    $cue = $defs | Where-Object Name -eq 'ComponentUpdatesEnabled'
    T "ComponentUpdatesEnabled target = 1 (never disabled)"     ($cue.TargetValue -eq 1)

    $dohNotRequested = ($null -eq $DnsOverHttpsTemplate -or $DnsOverHttpsTemplate -eq '')
    $dohAbsentFromDefs = (($defs | Where-Object Name -like 'DnsOverHttps*').Count -eq 0)
    T "DoH absent from policies when -DnsOverHttpsTemplate is not given" (
        (-not $dohNotRequested) -or $dohAbsentFromDefs
    )
    T "Lockdown category absent by default (-IncludeLockdown not given)" (
        $IncludeLockdown -or (($defs | Where-Object Category -eq 'Lockdown').Count -eq 0)
    )
    T "DevTools stays allowed even with -IncludeLockdown"       (
        -not $IncludeLockdown -or ((($defs | Where-Object Name -eq 'DeveloperToolsAvailability').TargetValue) -eq 0)
    )
    T "TranslateEnabled and SpellcheckEnabled absent from the script" (
        (($defs | Where-Object Name -in @('TranslateEnabled','SpellcheckEnabled','SpellcheckServiceEnabled')).Count -eq 0)
    )

    T "Get-CurrentPolicyValue returns `$null on a non-existent path" (
        (Get-CurrentPolicyValue -Name 'KeyThatDoesNotExistAtAll123') -eq $null
    )

    T "Add-Result correctly adds an entry" ({
        $before = $script:Results.Count
        Add-Result 'TestPolicy' 'TestCategory' 'old' 'new' 'Test' 'note'
        $ok = ($script:Results.Count -eq $before + 1)
        $script:Results.RemoveAt($script:Results.Count - 1)
        $ok
    }.Invoke())

    T "Test-IsAdmin returns a boolean"                          ((Test-IsAdmin) -is [bool])

    T "CSV export does not throw (temp file)" ({
        try {
            $tmp = [IO.Path]::GetTempFileName()
            [PSCustomObject]@{ A = 1; B = 2 } | Export-Csv -Path $tmp -NoTypeInformation
            Remove-Item $tmp -Force
            $true
        } catch { $false }
    }.Invoke())

    T "Valid JSON round-trip" ({
        try {
            $obj = [PSCustomObject]@{ A = 1; B = 'x' }
            $json = $obj | ConvertTo-Json
            $back = $json | ConvertFrom-Json
            ($back.A -eq 1 -and $back.B -eq 'x')
        } catch { $false }
    }.Invoke())

    T "SafeBrowsingProtectionLevel correctly maps Off/Standard/Enhanced" (
        (($defs | Where-Object Name -eq 'SafeBrowsingProtectionLevel').TargetValue) -in 0,1,2
    )

    T "-Category filter returns a consistent subset" ({
        $sub = $defs | Where-Object { $_.Category -in @('Telemetry') }
        ($sub.Count -gt 0 -and ($sub.Category | Select-Object -Unique) -eq 'Telemetry')
    }.Invoke())

    T "Report folder can be resolved without error" ({
        try { [IO.Path]::GetFullPath($ReportRoot) | Out-Null; $true } catch { $false }
    }.Invoke())

    T "Backup folder can be resolved without error" ({
        try { [IO.Path]::GetFullPath($BackupFolder) | Out-Null; $true } catch { $false }
    }.Invoke())

    T "Get-IntegrityStatus runs without error (read-only)" ({
        try { $null = Get-IntegrityStatus; $true } catch { $false }
    }.Invoke())

    T "Get-LastAppliedInfo does not throw when there is no state" ({
        try { $null = Get-LastAppliedInfo; $true } catch { $false }
    }.Invoke())

    $passed = ($tests | Where-Object Pass).Count
    $total  = $tests.Count
    foreach ($t in $tests) {
        if ($t.Pass) { Write-Ok $t.Name } else { Write-Fail $t.Name }
    }
    Write-Host ""
    Write-Rule
    Write-Host "  Result  " -NoNewline -ForegroundColor DarkGray
    if ($passed -eq $total) { Write-Host "$passed / $total tests passed" -ForegroundColor Green }
    else { Write-Host "$passed / $total tests passed — FAILURES DETECTED" -ForegroundColor Red }
    Write-Host ""
    return ($passed -eq $total)
}

#endregion

#region MAIN

if ($DebugDefs) {
    $d = Get-BravePolicyDefinitions
    Write-Banner "DEBUG — POLICY DEFINITIONS" -Subtitle "Output of Get-BravePolicyDefinitions"
    Write-Host ""
    Write-KeyValue "Total objects" "$($d.Count)" "White" -KeyWidth 15
    Write-Host ""
    $i = 0
    foreach ($p in $d) {
        $i++
        Write-Host ("  {0,3}  " -f $i) -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-38}" -f $p.Name) -NoNewline -ForegroundColor White
        Write-Host $p.Category -ForegroundColor DarkCyan
    }
    Write-Host ""
    Write-Rule
    foreach ($n in @('PaymentMethodQueryEnabled','SearchSuggestEnabled')) {
        if ($d.Name -contains $n) { Write-Status OK "$n present in the generated list" }
        else { Write-Status FAIL "$n MISSING from the generated list" }
    }
    Wait-ForClose
    exit
}

if ($SelfTest) {
    $ok = Invoke-SelfTest
    Wait-ForClose
    exit ([int](-not $ok))
}

Write-Log "Script started (v$ScriptVersion)"

do {
    $choice = Show-Menu

    switch ($choice.ToUpper()) {
        "1"  { Invoke-BraveAction -Simulation $false -ForceUpdate $false }
        "2"  { Invoke-BraveAction -Simulation $false -ForceUpdate $true }
        "3"  { Invoke-BraveAction -Simulation $true  -ForceUpdate $false }
        "4"  { Restore-BravePolicies }
        "5"  { Show-Backups }
        "6"  { Flush-DNSCache }
        "7"  { Show-GeneratedReport }
        "8"  { Test-Conflicts }
        "9"  { Test-Integrity }
        "10" { Export-ActivePolicies }
        "Q"  {
            Write-Log "Script ended"
            Clear-Host
            Write-Host ""
            Write-Status OK "Session closed." -Detail "Log: $LogPath"
            Write-Host ""
        }
        default {
            Write-Host ""
            Write-Status WARN "Invalid choice. Pick an option from the menu."
            Start-Sleep -Seconds 1
        }
    }
} while ($choice.ToUpper() -ne "Q")

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBA+7Jr47z25203
# 9HiIopVVbovZRuSDxNmJhLlz+DG366CCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEII2xsj6L57HlMAHqtlmJ+EJF7wFikN0XQufIphM5
# IJm1MA0GCSqGSIb3DQEBAQUABIIBAFsSKFqC5w5ttrHF0mCFFIqh6/ndfgPQWepZ
# LmH4m21qZ4rVyg25slvBsDv6xTo99YdfER1fvQcebzmAAbAeyBer/wnti9RVMK8k
# 09eolXyg+NhLKD8hYp/xnHnucSnw/xXOcRLzE6/eEa4mUubcItXoPq/JrzMU1MV1
# jK6wiNogeHaXEaJ1+liShPlnrY6ExbDmfvhAQTC17mImrplZnr9D8j/xvpZxadPl
# sj1NoXwCLp0DtTrLu0x8Uk8DKkYIOsr9v2Vv13TymcIT3ddSYV2Jb6nhGfsn3XVd
# /PpTxcScK2kPtnZGrl9CzsVTKqStYZrE3VVmny5t6/fGsQs8ROo=
# SIG # End signature block
