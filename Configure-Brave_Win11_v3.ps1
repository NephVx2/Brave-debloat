# =====================================================================================
# CONFIGURE-BRAVE_WIN11 — Déploiement contrôlé des policies Brave (registre HKLM)
# VERSION 3.0 — Interface menu interactif + durcissement étendu (v3 : 20 nouvelles
# règles Telemetrie/Bloat/Reseau/Securite/PrivacySandbox/Performance, analysées
# depuis un export complet brave://policy/ le 04/07/2026)
# =====================================================================================
# Applique un jeu de policies Brave (debloat, télémétrie, réseau, sécurité) via
# HKLM\SOFTWARE\Policies\BraveSoftware\Brave, avec sauvegarde automatique avant
# toute modification, mode simulation, restauration, vérification d'intégrité et
# de conflits, et rapports CSV/JSON/HTML — même architecture que Block-Telemetry.
#
# GARANTIES DE SÉCURITÉ :
#   [S1] Sauvegarde .reg automatique avant toute modification (reg export)
#   [S2] Rotation automatique des sauvegardes (conservation des 10 dernières)
#   [S3] Mode simulation (DryRun) pour voir le diff sans rien toucher
#   [S4] Fonction de restauration complète intégrée (menu)
#   [S5] Option "Mettre à jour" (nettoie les résidus + ré-applique en une étape)
#   [S6] Garde-fous anti-régression intégrés au SelfTest (NetworkPredictionOptions,
#        ComponentUpdatesEnabled) — cf. historique de la conversation d'origine
#   [S7] Détection de conflits (policies HKCU, sous-clé Recommended, résidus)
#   [S8] Vérification d'intégrité (policies définies vs valeurs réellement actives)
#   [S9] DoH et Lockdown restent opt-in explicite (jamais appliqués par défaut)
#
# CATÉGORIES : Bloat, Telemetrie, Reseau, Securite, PrivacySandbox, Performance,
#              Lockdown (opt-in via -IncludeLockdown)
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

$ScriptVersion = '3.0'

#region AUTO-ELEVATION

# Le SelfTest est purement en lecture (registre + comparaisons en mémoire) : traité
# avant l'élévation pour éviter une demande UAC inutile juste pour un contrôle.
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

#region INITIALISATION

$RegPath          = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
$RegPathWin       = 'HKLM\SOFTWARE\Policies\BraveSoftware\Brave'
$HkcuRegPath      = 'HKCU:\SOFTWARE\Policies\BraveSoftware\Brave'
$RecommendedPath  = Join-Path $RegPath 'Recommended'
$ReportRoot       = Join-Path $env:USERPROFILE 'Desktop\Rapports_Maintenance\ConfigBrave'
$BackupFolder     = Join-Path $env:USERPROFILE 'Desktop\Registry_Backups\ConfigBrave'
$LogPath          = Join-Path $env:USERPROFILE 'Desktop\Configure-Brave_Log.txt'
$StateFile        = Join-Path $ReportRoot '_dernier_etat.json'
$BackupMaxCount   = 10
$script:Results   = New-Object System.Collections.Generic.List[object]

#endregion

#region UTILITAIRES D'AFFICHAGE / LOG

function Write-Banner {
    param([string]$Title, [string]$Color = 'Cyan')
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor $Color
    Write-Host "   $Title" -ForegroundColor $Color
    Write-Host "  ============================================================" -ForegroundColor $Color
    Write-Host ""
}

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "  $('-' * $Text.Length)" -ForegroundColor DarkCyan
}

function Write-Ok    { param([string]$Text) Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "  [!]  $Text" -ForegroundColor Yellow }
function Write-Fail  { param([string]$Text) Write-Host "  [x]  $Text" -ForegroundColor Red }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$((Get-Date).ToString('HH:mm:ss'))] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Test-IsAdmin { return $script:IsAdmin }

#endregion

#region DÉFINITION DES POLICIES

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

    # --- BLOAT : features Brave propriétaires non utilisées -------------
    $defs.Add((New-Policy 'BraveRewardsDisabled'       'Bloat' 'DWord' 1 'Rewards non utilisé'))
    $defs.Add((New-Policy 'BraveWalletDisabled'        'Bloat' 'DWord' 1 'Wallet non utilisé'))
    $defs.Add((New-Policy 'BraveVPNDisabled'           'Bloat' 'DWord' 1 'Brave VPN non utilisé'))
    $defs.Add((New-Policy 'BraveAIChatEnabled'         'Bloat' 'DWord' 0 'Leo AI non utilisé'))
    $defs.Add((New-Policy 'BraveNewsDisabled'          'Bloat' 'DWord' 1 'Brave News non utilisé'))
    $defs.Add((New-Policy 'BraveTalkDisabled'          'Bloat' 'DWord' 1 'Brave Talk non utilisé'))
    $defs.Add((New-Policy 'BraveSpeedreaderEnabled'    'Bloat' 'DWord' 0 'Speedreader non utilisé'))
    $defs.Add((New-Policy 'BraveWaybackMachineEnabled' 'Bloat' 'DWord' 0 'Wayback Machine non utilisé'))
    $defs.Add((New-Policy 'BravePlaylistEnabled'       'Bloat' 'DWord' 0 'Playlist non utilisé'))
    $defs.Add((New-Policy 'SyncDisabled'               'Bloat' 'DWord' 1 'Brave Sync non utilisé'))
    $defs.Add((New-Policy 'TorDisabled'                'Bloat' 'DWord' 1 'Fenêtre Tor de Brave non utilisée'))

    # --- BLOAT v3 : nettoyage UI + couche IA Chromium sous-jacente ----------
    # Brave n'utilise pas ces fonctionnalités Google nativement, mais elles
    # existent dans le moteur Chromium sous-jacent — autant fermer la porte.
    $defs.Add((New-Policy 'PromotionalTabsEnabled'              'Bloat' 'DWord' 0 'Coupe les onglets promotionnels au démarrage'))
    $defs.Add((New-Policy 'PromotionsEnabled'                   'Bloat' 'DWord' 0 'Coupe les bannières/promos internes'))
    $defs.Add((New-Policy 'NTPCardsVisible'                     'Bloat' 'DWord' 0 'Retire les cartes de la page nouvel onglet'))
    $defs.Add((New-Policy 'NTPMiddleSlotAnnouncementVisible'    'Bloat' 'DWord' 0 'Retire le bandeau d''annonce de la page nouvel onglet'))
    $defs.Add((New-Policy 'HideWebStoreIcon'                    'Bloat' 'DWord' 1 'Masque l''icône promo du Web Store (n''empêche pas d''installer des extensions)'))
    $defs.Add((New-Policy 'BrowserLabsEnabled'                  'Bloat' 'DWord' 0 'Retire le bouton "Labs" (fonctionnalités expérimentales) de la barre d''outils'))
    # Enum 0=Autorisé / 1=Non autorisé pour ces deux-là (vérifié — ne pas remettre à 0)
    $defs.Add((New-Policy 'GeminiSettings'                      'Bloat' 'DWord' 1 'Désactive l''intégration Gemini dans le moteur Chromium (0=autorisé, 1=désactivé)'))
    $defs.Add((New-Policy 'GeminiActOnWebSettings'               'Bloat' 'DWord' 1 'Désactive l''auto-browse Gemini (agent IA agissant sur les pages) (0=autorisé, 1=désactivé)'))
    # Enum 0=Autoriser+améliorer modèles / 1=Autoriser sans partage / 2=Désactivé (vérifié)
    $defs.Add((New-Policy 'HelpMeWriteSettings'                 'Bloat' 'DWord' 2 'Désactive la fonctionnalité "Aide à l''écriture" IA (0/1=actif, 2=désactivé)'))
    $defs.Add((New-Policy 'TabCompareSettings'                  'Bloat' 'DWord' 2 'Désactive la comparaison d''onglets assistée par IA (0/1=actif, 2=désactivé)'))

    # --- TELEMETRIE -------------------------------------------------------
    $defs.Add((New-Policy 'BraveP3AEnabled'           'Telemetrie' 'DWord' 0 'Coupe P3A (Privacy-Preserving Product Analytics)'))
    $defs.Add((New-Policy 'BraveStatsPingEnabled'     'Telemetrie' 'DWord' 0 'Coupe le ping stats quotidien (laptop-updates.brave.com reste JOIGNABLE pour les mises à jour, la policy coupe uniquement le ping)'))
    $defs.Add((New-Policy 'BraveWebDiscoveryEnabled'  'Telemetrie' 'DWord' 0 'Coupe Web Discovery Project (déjà renforcé côté hosts : patterns.wdp.brave.com / collector.wdp.brave.com)'))
    $defs.Add((New-Policy 'MetricsReportingEnabled'   'Telemetrie' 'DWord' 0 'Coupe le reporting de crash/usage Chromium générique'))
    $defs.Add((New-Policy 'AlternateErrorPagesEnabled' 'Telemetrie' 'DWord' 0 'Empêche Brave de contacter Google pour les pages d''erreur de navigation'))
    $defs.Add((New-Policy 'PaymentMethodQueryEnabled'  'Telemetrie' 'DWord' 0 'Empêche les sites de détecter tes moyens de paiement enregistrés'))
    $defs.Add((New-Policy 'SearchSuggestEnabled'       'Telemetrie' 'DWord' 0 'Coupe l''envoi de ta frappe en temps réel au moteur de suggestions'))
    $defs.Add((New-Policy 'UserFeedbackAllowed'        'Telemetrie' 'DWord' 0 'Désactive l''option d''envoi de feedback/rapport à Brave'))

    # --- TELEMETRIE v3 -------------------------------------------------------
    $defs.Add((New-Policy 'UrlKeyedAnonymizedDataCollectionEnabled' 'Telemetrie' 'DWord' 0 'Coupe la collecte de données liées à l''historique de navigation malgré le nom "anonymisé"'))
    $defs.Add((New-Policy 'SafeBrowsingExtendedReportingEnabled'    'Telemetrie' 'DWord' 0 'Coupe l''envoi de données supplémentaires à Google au-delà du Safe Browsing de base'))
    $defs.Add((New-Policy 'WebRtcEventLogCollectionAllowed'         'Telemetrie' 'DWord' 0 'Empêche l''envoi de logs WebRTC à Google'))
    $defs.Add((New-Policy 'FeedbackSurveysEnabled'                  'Telemetrie' 'DWord' 0 'Coupe les sondages de satisfaction (télémétrie déguisée en UX)'))
    $defs.Add((New-Policy 'CloudReportingEnabled'                   'Telemetrie' 'DWord' 0 'Sans effet sur poste perso non enrôlé, mais défense en profondeur cohérente'))

    # --- RESEAU -------------------------------------------------------------
    # ATTENTION régression connue : 0 ou 1 = prédiction ACTIVE. Seul 2 désactive
    # réellement le DNS prefetch + preconnect. Ne jamais remettre 0 ici.
    $defs.Add((New-Policy 'NetworkPredictionOptions' 'Reseau' 'DWord' 2 'Désactive DNS prefetch + preconnect (2=never ; 0/1=actif, ne pas confondre)'))
    $defs.Add((New-Policy 'BackgroundModeEnabled'    'Reseau' 'DWord' 0 'Empêche Brave de tourner en arrière-plan après fermeture'))

    # --- RESEAU v3 -------------------------------------------------------------
    # Valeur String vérifiée : "default_public_interface_only" empêche WebRTC
    # de révéler l'IP locale/privée même derrière un VPN/proxy.
    $defs.Add((New-Policy 'WebRtcIPHandling'      'Reseau' 'String' 'default_public_interface_only' 'Empêche la fuite d''IP locale via WebRTC, même sous VPN/proxy'))
    # Force le résolveur DNS de l'OS plutôt que le résolveur interne Chromium,
    # pour rester cohérent avec NextDNS (même logique que DnsOverHttpsMode non défini).
    $defs.Add((New-Policy 'BuiltInDnsClientEnabled' 'Reseau' 'DWord' 0 'Force le résolveur DNS de l''OS (cohérence avec NextDNS)'))
    $defs.Add((New-Policy 'WPADQuickCheckEnabled'   'Reseau' 'DWord' 0 'Coupe la détection auto de proxy WPAD à chaque connexion réseau (réduit la surface de spoofing WPAD)'))

    # --- SECURITE / MISES A JOUR --------------------------------------------
    # ComponentUpdatesEnabled=1 est volontaire : ce n'est pas juste le binaire
    # Brave, ça couvre aussi Widevine, listes Safe Browsing, magasin de
    # certificats racine. Ne jamais désactiver.
    $defs.Add((New-Policy 'ComponentUpdatesEnabled' 'Securite' 'DWord' 1 'NE PAS DÉSACTIVER — mises à jour composants sécurité (Widevine, certs, Safe Browsing)'))
    $defs.Add((New-Policy 'HttpsUpgradesEnabled'    'Securite' 'DWord' 1 'Force HTTPS quand disponible'))

    $sbLevel = switch ($SafeBrowsingLevel) { 'Off' {0} 'Standard' {1} 'Enhanced' {2} }
    $sbNote  = switch ($SafeBrowsingLevel) {
        'Off'      { 'Safe Browsing désactivé — déconseillé' }
        'Standard' { 'Listes locales, pas de partage temps réel avec Google' }
        'Enhanced' { 'Meilleure détection, mais URL + échantillons de page envoyés à Google en continu' }
    }
    $defs.Add((New-Policy 'SafeBrowsingProtectionLevel' 'Securite' 'DWord' $sbLevel $sbNote))

    # --- SECURITE v3 -----------------------------------------------------------
    $defs.Add((New-Policy 'RemoteDebuggingAllowed'                   'Securite' 'DWord' 0 'Empêche tout outil externe de s''attacher au port de débogage distant de Brave'))
    $defs.Add((New-Policy 'BasicAuthOverHttpEnabled'                 'Securite' 'DWord' 0 'Bloque l''authentification HTTP Basic transmise en clair'))
    $defs.Add((New-Policy 'AmbientAuthenticationInPrivateModesEnabled' 'Securite' 'DWord' 0 'Empêche l''auth NTLM/Kerberos automatique de fuiter des identifiants Windows en navigation privée'))
    $defs.Add((New-Policy 'AllowCrossOriginAuthPrompt'               'Securite' 'DWord' 0 'Bloque le spoofing par pop-up d''authentification cross-origin'))
    $defs.Add((New-Policy 'SignedHTTPExchangeEnabled'                'Securite' 'DWord' 0 'Désactive les Signed HTTP Exchanges (peuvent masquer l''origine réelle d''une page)'))

    # --- PRIVACY SANDBOX -----------------------------------------------------
    $defs.Add((New-Policy 'PrivacySandboxAdTopicsEnabled'       'PrivacySandbox' 'DWord' 0 'Coupe Topics API (profilage publicitaire) — OBSOLETE côté Chromium, conservé pour compat. anciennes versions'))
    $defs.Add((New-Policy 'PrivacySandboxPromptEnabled'         'PrivacySandbox' 'DWord' 0 'Supprime le prompt Privacy Sandbox — OBSOLETE côté Chromium, conservé pour compat. anciennes versions'))
    $defs.Add((New-Policy 'PrivacySandboxSiteEnabledAdsEnabled' 'PrivacySandbox' 'DWord' 0 'Coupe les API publicitaires par site — OBSOLETE côté Chromium, conservé pour compat. anciennes versions'))
    # Remplacement actif : les 3 règles ci-dessus sont marquées "Obsolète" dans
    # brave://policy/ (export du 04/07/2026) — Chromium a restructuré l'API
    # Privacy Sandbox. Celle-ci est la règle actuellement effective.
    $defs.Add((New-Policy 'PrivacySandboxAdMeasurementEnabled'  'PrivacySandbox' 'DWord' 0 'Coupe l''API Attribution Reporting (mesure publicitaire cross-site) — remplace les 3 règles obsolètes ci-dessus'))

    # --- PERFORMANCE -----------------------------------------------------------
    $defs.Add((New-Policy 'HighEfficiencyModeEnabled' 'Performance' 'DWord' 1 'Memory Saver actif'))
    # Niveau 1 = Équilibré (ML estime la probabilité de retour sur l'onglet avant
    # déchargement). Niveau 2 = Maximum, écarté : trop de rechargements surprise
    # sur un usage multi-onglets avec 16 Go de RAM disponibles.
    $defs.Add((New-Policy 'MemorySaverModeSavings' 'Performance' 'DWord' 1 'Renforce Memory Saver en mode Équilibré (0=Modéré, 1=Équilibré, 2=Maximum)'))

    # --- LOCKDOWN (opt-in via -IncludeLockdown) ---------------------------
    # Ce ne sont PAS des fuites de données : ce sont des pertes de
    # fonctionnalité. À n'activer que si c'est un choix délibéré.
    # NOTE : TranslateEnabled et SpellcheckEnabled/SpellcheckServiceEnabled
    # sont volontairement ABSENTS d'ici (et de tout le script) — traduction
    # de pages et correcteur orthographique (y compris le service en ligne)
    # sont des fonctionnalités utilisées. Le script ne les touche pas.
    if ($IncludeLockdown) {
        $defs.Add((New-Policy 'PasswordManagerEnabled'    'Lockdown' 'DWord' 0 'Désactive le gestionnaire de mots de passe intégré'))
        $defs.Add((New-Policy 'AutofillAddressEnabled'    'Lockdown' 'DWord' 0 'Désactive autofill adresses'))
        $defs.Add((New-Policy 'AutofillCreditCardEnabled' 'Lockdown' 'DWord' 0 'Désactive autofill CB'))
        $defs.Add((New-Policy 'DeveloperToolsAvailability' 'Lockdown' 'DWord' 0 'Laissé à 0 (autorisé) par défaut même en Lockdown — un poste perso a besoin des DevTools'))
        $defs.Add((New-Policy 'IncognitoModeAvailability'  'Lockdown' 'DWord' 0 'Laissé à 0 (autorisé) — restreindre l''incognito n''a de sens que sur poste partagé'))
    }

    # --- DNS-over-HTTPS (opt-in explicite uniquement) ------------------------
    if ($DnsOverHttpsTemplate) {
        $defs.Add((New-Policy 'DnsOverHttpsMode'      'Reseau' 'String' 'secure' 'DoH forcé côté Brave (vérifie que ça ne contourne pas NextDNS)'))
        $defs.Add((New-Policy 'DnsOverHttpsTemplates' 'Reseau' 'String' $DnsOverHttpsTemplate 'Endpoint DoH fourni explicitement par -DnsOverHttpsTemplate'))
    }

    return $defs
}

#endregion

#region LECTURE / APPLICATION REGISTRE

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
        Categorie      = $Category
        AncienneValeur = if ($null -eq $PreviousValue) { '<absent>' } else { $PreviousValue }
        NouvelleValeur = $TargetValue
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
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'Inchange' $Policy.Rationale
        return
    }

    if ($PreviewOnly) {
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'SeraApplique' $Policy.Rationale
        return
    }

    try {
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        $regType = if ($Policy.Type -eq 'String') { 'String' } else { 'DWord' }
        New-ItemProperty -Path $RegPath -Name $Policy.Name -Value $Policy.TargetValue -PropertyType $regType -Force | Out-Null
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'Applique' $Policy.Rationale
    }
    catch {
        Add-Result $Policy.Name $Policy.Category $current $Policy.TargetValue 'Echec' $_.Exception.Message
    }
}

#endregion

#region SAUVEGARDE / RESTAURATION (registre)

function Backup-BravePolicies {
    if (-not (Test-Path $BackupFolder)) { New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $backupPath = Join-Path $BackupFolder "BravePolicies_backup_$stamp.reg"

    try {
        if (Test-Path $RegPath) {
            $null = reg export $RegPathWin $backupPath /y 2>&1
        }
        else {
            # Marqueur d'absence : permet à Restore de savoir qu'il faut supprimer
            # toute la clé plutôt que d'importer un .reg vide.
            "; CONFIGURE-BRAVE — aucune policy presente avant application (cle absente)." |
                Out-File -FilePath $backupPath -Encoding UTF8
        }
        Write-Ok "Sauvegarde : $backupPath"
        Write-Log "Sauvegarde créée : $backupPath"

        $all = Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' |
            Sort-Object LastWriteTime -Descending
        if ($all.Count -gt $BackupMaxCount) {
            $all | Select-Object -Skip $BackupMaxCount | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        return $backupPath
    }
    catch {
        Write-Fail "Sauvegarde échouée : $_"
        Write-Log "Échec sauvegarde : $_" "ERREUR"
        return $null
    }
}

function Restore-BravePolicies {
    Clear-Host
    Write-Banner "RESTAURATION DES POLICIES BRAVE" 'Red'

    if (-not (Test-Path $BackupFolder) -or (Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' -ErrorAction SilentlyContinue).Count -eq 0) {
        Write-Warn2 "Aucune sauvegarde disponible dans $BackupFolder"
        Write-Host ""
        Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
        return
    }

    $latest = Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    Write-Host "  Cette action restaure l'état du registre Brave à partir de :" -ForegroundColor White
    Write-Host "  $($latest.FullName)" -ForegroundColor White
    Write-Host "  ($($latest.LastWriteTime.ToString('dd/MM/yyyy HH:mm:ss')))" -ForegroundColor DarkGray
    Write-Host ""
    $confirm = Read-Host "  Confirmer la restauration ? (O/N)"
    if ($confirm -notin @('O','o','oui','OUI','y','Y','yes','YES')) {
        Write-Warn2 "Annulé."
        Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
        return
    }

    # Sauvegarde de sécurité de l'état courant avant de restaurer
    Write-Header "Sauvegarde de l'état actuel avant restauration"
    Backup-BravePolicies | Out-Null

    Write-Header "Restauration en cours"
    try {
        $content = Get-Content -Path $latest.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '^; CONFIGURE-BRAVE') {
            if (Test-Path $RegPath) { Remove-Item -Path $RegPath -Recurse -Force }
            Write-Ok "Clé de policies Brave supprimée (aucune policy n'était présente à l'origine)."
        }
        else {
            if (Test-Path $RegPath) { Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue }
            $null = reg import $latest.FullName 2>&1
            Write-Ok "Registre restauré depuis la sauvegarde."
        }
        Write-Log "Restauration effectuée depuis $($latest.FullName)"
        Write-StateSnapshot -Action 'Restauration'
        Write-Host ""
        Write-Banner "RESTAURATION TERMINÉE" 'Green'
        Write-Warn2 "Redémarre Brave pour appliquer."
    }
    catch {
        Write-Fail "Restauration échouée : $_"
        Write-Log "Échec restauration : $_" "ERREUR"
    }

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

function Show-Backups {
    Clear-Host
    Write-Banner "SAUVEGARDES DISPONIBLES"

    if (-not (Test-Path $BackupFolder)) {
        Write-Host "  Aucune sauvegarde trouvée." -ForegroundColor Gray
        Write-Host "  (Dossier non créé — aucune policy n'a encore été appliquée)" -ForegroundColor DarkGray
    }
    else {
        $backups = Get-ChildItem -Path $BackupFolder -Filter 'BravePolicies_backup_*' | Sort-Object LastWriteTime -Descending
        if ($backups.Count -eq 0) {
            Write-Host "  Aucune sauvegarde trouvée dans $BackupFolder" -ForegroundColor Gray
        }
        else {
            foreach ($b in $backups) {
                $size = [Math]::Round($b.Length / 1KB, 1)
                Write-Host "  $($b.LastWriteTime.ToString('dd/MM/yyyy HH:mm:ss'))  |  $($b.Name)  |  $size KB" -ForegroundColor White
            }
            Write-Host ""
            Write-Host "  Dossier : $BackupFolder" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  La restauration (menu) utilise toujours la plus récente." -ForegroundColor DarkCyan
        }
    }

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

#endregion

#region ETAT / INTEGRITE / CONFLITS

function Write-StateSnapshot {
    param([string]$Action)
    try {
        if (-not (Test-Path $ReportRoot)) { New-Item -Path $ReportRoot -ItemType Directory -Force | Out-Null }
        $applied = ($script:Results | Where-Object { $_.Action -eq 'Applique' }).Count
        $failed  = ($script:Results | Where-Object { $_.Action -eq 'Echec' }).Count
        [PSCustomObject]@{
            Timestamp = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
            Action    = $Action
            Appliques = $applied
            Echecs    = $failed
        } | ConvertTo-Json | Out-File -FilePath $StateFile -Encoding UTF8 -Force
    }
    catch {
        Write-Log "Échec écriture état : $_" "AVERT"
    }
}

function Get-LastAppliedInfo {
    if (-not (Test-Path $StateFile)) { return $null }
    try { return (Get-Content -Path $StateFile -Raw | ConvertFrom-Json) }
    catch { return $null }
}

function Get-IntegrityStatus {
    # Comparaison lecture seule, aucun effet de bord — réutilisée par le menu
    # (indicateur compact) et par Test-Integrity (affichage détaillé).
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
    Write-Banner "VÉRIFICATION D'INTÉGRITÉ DES POLICIES"

    $status = Get-IntegrityStatus

    Write-Host "  Policies attendues : $($status.Expected)" -ForegroundColor White
    Write-Host "  Policies actives   : $($status.Present)"  -ForegroundColor White
    Write-Host ""

    if ($status.Missing.Count -eq 0 -and $status.Extra.Count -eq 0) {
        Write-Ok "Intégrité parfaite — toutes les policies définies sont correctement appliquées."
        Write-Log "Vérification intégrité : OK ($($status.Present) policies)"
    }
    else {
        if ($status.Missing.Count -gt 0) {
            Write-Warn2 "$($status.Missing.Count) policy(ies) désynchronisée(s) (absente(s) ou valeur différente) :"
            foreach ($m in $status.Missing | Sort-Object) { Write-Host "     - $m" -ForegroundColor DarkYellow }
            Write-Host ""
            Write-Host "  Utilisez l'option [1] ou [2] pour les (ré)appliquer." -ForegroundColor DarkGray
            Write-Log "Vérification intégrité : $($status.Missing.Count) policies désynchronisées" "AVERT"
        }
        if ($status.Extra.Count -gt 0) {
            Write-Host ""
            Write-Host "  [INFO] $($status.Extra.Count) valeur(s) présente(s) dans le registre mais plus définie(s) par ce script :" -ForegroundColor Cyan
            foreach ($e in $status.Extra | Sort-Object) { Write-Host "     - $e" -ForegroundColor DarkGray }
            Write-Host ""
            Write-Host "  Résidus probables d'une ancienne version ou d'un autre outil (ex : fichiers GitHub)." -ForegroundColor DarkGray
            Write-Host "  Utilisez l'option [2] Mettre à jour pour les nettoyer." -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

function Test-Conflicts {
    Clear-Host
    Write-Banner "DÉTECTION DE CONFLITS"

    $foundAny = $false

    if (Test-Path $HkcuRegPath) {
        $foundAny = $true
        Write-Warn2 "Policies également définies au niveau utilisateur (HKCU) :"
        $hkcuProps = (Get-ItemProperty -Path $HkcuRegPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }
        foreach ($p in $hkcuProps) { Write-Host "     - $($p.Name) = $($p.Value)" -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host "  En général HKLM (machine) prévaut sur HKCU, mais la redondance peut prêter à confusion." -ForegroundColor DarkGray
    }
    else {
        Write-Ok "Aucune policy définie au niveau utilisateur (HKCU) — pas de conflit de portée."
    }

    Write-Host ""
    if (Test-Path $RecommendedPath) {
        $foundAny = $true
        Write-Warn2 "Sous-clé 'Recommended' présente sous $RegPath :"
        $recProps = (Get-ItemProperty -Path $RecommendedPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }
        foreach ($p in $recProps) { Write-Host "     - $($p.Name) = $($p.Value)" -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host "  Ce sont des valeurs par défaut modifiables par toi dans Brave (pas obligatoires) — vérifie qu'elles ne masquent pas ce que tu attends." -ForegroundColor DarkGray
    }
    else {
        Write-Ok "Aucune sous-clé 'Recommended' — pas de policies non-obligatoires en concurrence."
    }

    Write-Host ""
    $status = Get-IntegrityStatus
    if ($status.Extra.Count -gt 0) {
        $foundAny = $true
        Write-Warn2 "$($status.Extra.Count) valeur(s) résiduelle(s) dans $RegPath non définie(s) par ce script (voir [9] intégrité pour le détail)."
    }
    else {
        Write-Ok "Aucun résidu détecté dans $RegPath."
    }

    Write-Host ""
    if (-not $foundAny) {
        Write-Ok "Aucun conflit détecté."
    }

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

#endregion

#region ACTIONS : APPLIQUER / SIMULER / METTRE A JOUR

function Invoke-BraveAction {
    param([bool]$Simulation, [bool]$ForceUpdate)

    Clear-Host
    $title = if ($Simulation) { "SIMULATION (DRYRUN) — AUCUNE MODIFICATION" }
             elseif ($ForceUpdate) { "MISE A JOUR (NETTOYAGE + RE-APPLICATION)" }
             else { "APPLICATION DES POLICIES BRAVE" }
    Write-Banner $title

    $defs = Get-BravePolicyDefinitions
    $defsToApply = if ($Category) { $defs | Where-Object { $_.Category -in $Category } } else { $defs }

    if ($defsToApply.Count -eq 0) {
        Write-Fail "Aucune policy ne correspond au filtre -Category fourni."
        Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
        return
    }

    $script:Results.Clear()
    Write-Header "Calcul du diff (état actuel vs cible)"
    foreach ($p in $defsToApply) { Set-BravePolicy -Policy $p -PreviewOnly $true }

    $toChange = $script:Results | Where-Object { $_.Action -eq 'SeraApplique' }
    Write-Host ""
    Write-Host "  $($defsToApply.Count) policies évaluées — $($toChange.Count) modification(s) nécessaire(s)" -ForegroundColor Cyan
    Write-Host ""
    $script:Results | Format-Table PolicyName, Categorie, AncienneValeur, NouvelleValeur, Action -AutoSize

    if ($Simulation) {
        Write-Host ""
        Write-Warn2 "Mode simulation : aucune modification appliquée."
        $report = Export-BraveReport -Action 'Simulation'
        Write-Ok "Rapport : $($report.Html)"
        Write-Log "Simulation exécutée ($($toChange.Count) modification(s) potentielle(s))"
        Write-Host ""
        Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
        return
    }

    if ($toChange.Count -eq 0 -and -not $ForceUpdate) {
        Write-Host ""
        Write-Ok "Rien à faire, toutes les policies ciblées sont déjà à jour."
        Export-BraveReport -Action 'AucunChangement' | Out-Null
        Write-Host ""
        Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
        return
    }

    Write-Host ""
    $confirm = Read-Host "  Appliquer ces changements ? (O/N)"
    if ($confirm -notin @('O','o','oui','OUI','y','Y','yes','YES')) {
        Write-Warn2 "Annulé."
        Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
        return
    }

    Write-Header "Sauvegarde avant modification"
    Backup-BravePolicies | Out-Null

    if ($ForceUpdate) {
        Write-Header "Nettoyage des résidus (policies non définies par la version actuelle du script)"
        $status = Get-IntegrityStatus
        if ($status.Extra.Count -gt 0) {
            foreach ($name in $status.Extra) {
                try {
                    Remove-ItemProperty -Path $RegPath -Name $name -ErrorAction Stop
                    Write-Ok "Résidu supprimé : $name"
                    Write-Log "Résidu supprimé : $name"
                }
                catch {
                    Write-Fail "Impossible de supprimer $name : $_"
                }
            }
        }
        else {
            Write-Ok "Aucun résidu à nettoyer."
        }
    }

    $script:Results.Clear()
    Write-Header "Application des policies"
    foreach ($p in $defsToApply) { Set-BravePolicy -Policy $p -PreviewOnly $false }

    $applied = ($script:Results | Where-Object Action -eq 'Applique').Count
    $failed  = ($script:Results | Where-Object Action -eq 'Echec').Count

    Write-Host ""
    if ($failed -eq 0) { Write-Ok "$applied policy(ies) appliquée(s), 0 échec." }
    else { Write-Fail "$applied policy(ies) appliquée(s), $failed échec(s)." }

    $actionLabel = if ($ForceUpdate) { 'MiseAJour' } else { 'Application' }
    $report = Export-BraveReport -Action $actionLabel
    Write-StateSnapshot -Action $actionLabel
    Write-Log "$actionLabel : $applied appliquée(s), $failed échec(s)"

    Write-Host ""
    Write-Ok "Rapport CSV  : $($report.Csv)"
    Write-Ok "Rapport JSON : $($report.Json)"
    Write-Ok "Rapport HTML : $($report.Html)"

    Write-Host ""
    Write-Warn2 "Redémarre complètement Brave (fermer tous les processus) pour appliquer."
    Write-Warn2 "Vérifie ensuite sur brave://policy"

    Show-Toast -Title "Configure-Brave" -Message "$applied policy(ies) appliquée(s), $failed échec(s)."

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

function Flush-DNSCache {
    Clear-Host
    Write-Banner "VIDAGE DU CACHE DNS"
    try {
        ipconfig /flushdns | Out-Null
        Write-Ok "Cache DNS vidé"
        Write-Log "Cache DNS vidé manuellement"
    }
    catch {
        Write-Warn2 "Impossible de vider le cache DNS : $_"
    }
    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

function Export-ActivePolicies {
    Clear-Host
    Write-Banner "EXPORT DE LA LISTE ACTIVE"

    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $exportPath = Join-Path $env:USERPROFILE "Desktop\Configure-Brave_Export_$stamp.txt"
    $defs = Get-BravePolicyDefinitions | Sort-Object Category, Name

    $lines = @()
    $lines += "# ====================================================="
    $lines += "# CONFIGURE-BRAVE_WIN11 v$ScriptVersion — Export policies actives"
    $lines += "# Généré le $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
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
        $curStr = if ($null -eq $cur) { '<absent>' } else { $cur }
        $status = if ([string]$cur -eq [string]$p.TargetValue) { 'OK' } else { 'DESYNC' }
        $lines += "$($p.Name) = $curStr (cible: $($p.TargetValue)) [$status]"
    }

    $status = Get-IntegrityStatus
    if ($status.Extra.Count -gt 0) {
        $lines += ""
        $lines += "# --- Residus (non definis par ce script) ---"
        foreach ($e in $status.Extra | Sort-Object) {
            $lines += "$e = $(Get-CurrentPolicyValue -Name $e) [RESIDU]"
        }
    }

    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($exportPath, $lines, $encoding)
        Write-Ok "Export créé : $exportPath"
        Write-Log "Export créé : $exportPath"
    }
    catch {
        Write-Fail "Impossible de créer l'export : $_"
    }

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
}

#endregion

#region RAPPORTS (CSV / JSON / HTML)

function Export-BraveReport {
    param([string]$Action)

    if (-not (Test-Path $ReportRoot)) { New-Item -Path $ReportRoot -Force -ItemType Directory | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $base  = Join-Path $ReportRoot "Configure-Brave_$stamp"

    $script:Results | Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8

    $byCat = $script:Results | Group-Object Categorie | ForEach-Object {
        [PSCustomObject]@{
            Categorie = $_.Name
            Policies  = $_.Count
            Appliques = ($_.Group | Where-Object { $_.Action -eq 'Applique' -or $_.Action -eq 'SeraApplique' }).Count
            Inchanges = ($_.Group | Where-Object { $_.Action -eq 'Inchange' }).Count
            Echecs    = ($_.Group | Where-Object { $_.Action -eq 'Echec' }).Count
        }
    }
    $jsonObj = [PSCustomObject]@{
        Timestamp      = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
        Action         = $Action
        TotalPolicies  = $script:Results.Count
        Appliques      = ($script:Results | Where-Object { $_.Action -eq 'Applique' -or $_.Action -eq 'SeraApplique' }).Count
        Inchanges      = ($script:Results | Where-Object { $_.Action -eq 'Inchange' }).Count
        Echecs         = ($script:Results | Where-Object { $_.Action -eq 'Echec' }).Count
        ParCategorie   = $byCat
        Detail         = $script:Results
    }
    $jsonObj | ConvertTo-Json -Depth 6 | Out-File -FilePath "$base.json" -Encoding UTF8

    $rows = $script:Results | ForEach-Object {
        $color = switch ($_.Action) {
            'Applique'     { '#4ade80' }
            'SeraApplique' { '#facc15' }
            'Inchange'     { '#94a3b8' }
            'Echec'        { '#f87171' }
            default        { '#e2e8f0' }
        }
        "<tr><td>$($_.PolicyName)</td><td>$($_.Categorie)</td><td>$($_.AncienneValeur)</td><td>$($_.NouvelleValeur)</td><td style='color:$color;font-weight:600'>$($_.Action)</td><td>$($_.Note)</td></tr>"
    }
    $html = @"
<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<title>Configure-Brave — Rapport</title>
<style>
body{background:#0f172a;color:#e2e8f0;font-family:Segoe UI,Arial,sans-serif;padding:24px}
h1{color:#38bdf8}
table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{padding:8px 12px;border-bottom:1px solid #334155;text-align:left;font-size:14px}
th{background:#1e293b;color:#93c5fd}
tr:hover{background:#1e293b}
.summary{background:#1e293b;padding:16px;border-radius:8px;margin-top:12px}
</style></head><body>
<h1>Configure-Brave_Win11 v$ScriptVersion — Rapport</h1>
<div class="summary">
<b>Action :</b> $Action &nbsp;|&nbsp; <b>Généré le :</b> $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')<br>
<b>Total policies :</b> $($script:Results.Count) &nbsp;|&nbsp;
<b>Appliqués :</b> $(($script:Results | Where-Object { $_.Action -eq 'Applique' -or $_.Action -eq 'SeraApplique' }).Count) &nbsp;|&nbsp;
<b>Inchangés :</b> $(($script:Results | Where-Object { $_.Action -eq 'Inchange' }).Count) &nbsp;|&nbsp;
<b>Échecs :</b> $(($script:Results | Where-Object { $_.Action -eq 'Echec' }).Count)
</div>
<table>
<tr><th>Policy</th><th>Catégorie</th><th>Ancienne valeur</th><th>Nouvelle valeur</th><th>Action</th><th>Note</th></tr>
$($rows -join "`n")
</table>
</body></html>
"@
    $html | Out-File -FilePath "$base.html" -Encoding UTF8

    return @{ Csv = "$base.csv"; Json = "$base.json"; Html = "$base.html" }
}

function Show-GeneratedReport {
    Clear-Host
    Write-Banner "GÉNÉRATION D'UN RAPPORT HTML (ÉTAT ACTUEL)"

    $defs = Get-BravePolicyDefinitions
    $script:Results.Clear()
    foreach ($p in $defs) { Set-BravePolicy -Policy $p -PreviewOnly $true }

    $report = Export-BraveReport -Action 'RapportManuel'
    Write-Ok "Rapport CSV  : $($report.Csv)"
    Write-Ok "Rapport JSON : $($report.Json)"
    Write-Ok "Rapport HTML : $($report.Html)"
    Write-Log "Rapport HTML généré manuellement"

    Write-Host ""
    Read-Host "  Appuyez sur Entrée pour revenir au menu" | Out-Null
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

#region MENU PRINCIPAL

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   CONFIGURE-BRAVE_WIN11  v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""

    $status   = Get-IntegrityStatus
    $lastInfo = Get-LastAppliedInfo

    if ($status.Present -gt 0) {
        Write-Host "  Statut : " -NoNewline
        Write-Host "ACTIF" -ForegroundColor Green -NoNewline
        Write-Host "  ($($status.Present)/$($status.Expected) policies appliquées)" -ForegroundColor DarkGreen
    }
    else {
        Write-Host "  Statut : " -NoNewline
        Write-Host "Aucune policy appliquée" -ForegroundColor Gray
    }

    if ($lastInfo) {
        Write-Host "  Dernière action : $($lastInfo.Action) le $($lastInfo.Timestamp)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Dernière action : jamais exécutée" -ForegroundColor DarkGray
    }

    if ($status.Present -eq 0) {
        Write-Host "  Intégrité : " -NoNewline
        Write-Host "N/A (rien d'appliqué)" -ForegroundColor Gray
    }
    elseif ($status.Missing.Count -eq 0 -and $status.Extra.Count -eq 0) {
        Write-Host "  Intégrité : " -NoNewline
        Write-Host "OK — synchronisé avec la définition actuelle" -ForegroundColor DarkGreen
    }
    else {
        Write-Host "  Intégrité : " -NoNewline
        Write-Host "$($status.Missing.Count) désynchronisée(s), $($status.Extra.Count) résidu(s) — voir [9]" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  [1]  Appliquer les modifications" -ForegroundColor Yellow
    Write-Host "  [2]  Mettre à jour (nettoyer résidus + ré-appliquer)" -ForegroundColor Yellow
    Write-Host "  [3]  Simuler sans modifier (DryRun)" -ForegroundColor DarkYellow
    Write-Host "  [4]  RESTAURER les paramètres d'origine" -ForegroundColor Red
    Write-Host "  [5]  Voir les sauvegardes disponibles" -ForegroundColor Gray
    Write-Host "  [6]  Vider le cache DNS manuellement" -ForegroundColor Gray
    Write-Host "  [7]  Générer un rapport HTML" -ForegroundColor Cyan
    Write-Host "  [8]  Vérifier les conflits" -ForegroundColor Cyan
    Write-Host "  [9]  Vérifier l'intégrité des policies" -ForegroundColor Cyan
    Write-Host "  [10] Exporter la liste active (.txt)" -ForegroundColor DarkGray
    Write-Host "  [Q]  Quitter" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Choix : " -NoNewline

    return (Read-Host)
}

#endregion

#region SELFTEST

function Invoke-SelfTest {
    Write-Banner "CONFIGURE-BRAVE — SELFTEST v$ScriptVersion"
    $tests = New-Object System.Collections.Generic.List[object]

    function T { param($Name, $Condition) $tests.Add([PSCustomObject]@{ Name = $Name; Pass = [bool]$Condition }) }

    $defs = Get-BravePolicyDefinitions

    T "Au moins une policy definie"                          ($defs.Count -gt 0)
    T "Pas de doublon de nom de policy"                       (($defs.Name | Group-Object | Where-Object Count -gt 1).Count -eq 0)
    T "Toutes les policies DWord ont une TargetValue entiere" ((($defs | Where-Object Type -eq 'DWord') | ForEach-Object { $_.TargetValue -is [int] }) -notcontains $false)
    T "Toutes les policies String ont une TargetValue string" ((($defs | Where-Object Type -eq 'String') | ForEach-Object { $_.TargetValue -is [string] }) -notcontains $false)

    $npo = $defs | Where-Object Name -eq 'NetworkPredictionOptions'
    T "NetworkPredictionOptions cible = 2 (pas 0/1)"          ($npo.TargetValue -eq 2)
    $cue = $defs | Where-Object Name -eq 'ComponentUpdatesEnabled'
    T "ComponentUpdatesEnabled cible = 1 (jamais desactive)"  ($cue.TargetValue -eq 1)

    $dohNotRequested = ($null -eq $DnsOverHttpsTemplate -or $DnsOverHttpsTemplate -eq '')
    $dohAbsentFromDefs = (($defs | Where-Object Name -like 'DnsOverHttps*').Count -eq 0)
    T "DoH absent des policies si -DnsOverHttpsTemplate non fourni" (
        (-not $dohNotRequested) -or $dohAbsentFromDefs
    )
    T "Categorie Lockdown absente par defaut (-IncludeLockdown non fourni)" (
        $IncludeLockdown -or (($defs | Where-Object Category -eq 'Lockdown').Count -eq 0)
    )
    T "DevTools reste autorise meme si -IncludeLockdown"      (
        -not $IncludeLockdown -or ((($defs | Where-Object Name -eq 'DeveloperToolsAvailability').TargetValue) -eq 0)
    )
    T "TranslateEnabled et SpellcheckEnabled absents du script" (
        (($defs | Where-Object Name -in @('TranslateEnabled','SpellcheckEnabled','SpellcheckServiceEnabled')).Count -eq 0)
    )

    T "Get-CurrentPolicyValue retourne `$null sur chemin inexistant" (
        (Get-CurrentPolicyValue -Name 'CleQuiNexistePasDuTout123') -eq $null
    )

    T "Add-Result ajoute correctement un enregistrement" ({
        $before = $script:Results.Count
        Add-Result 'TestPolicy' 'TestCategorie' 'ancien' 'nouveau' 'Test' 'note'
        $ok = ($script:Results.Count -eq $before + 1)
        $script:Results.RemoveAt($script:Results.Count - 1)
        $ok
    }.Invoke())

    T "Test-IsAdmin retourne un booleen"                      ((Test-IsAdmin) -is [bool])

    T "Export CSV ne leve pas d'exception (fichier temp)" ({
        try {
            $tmp = [IO.Path]::GetTempFileName()
            [PSCustomObject]@{ A = 1; B = 2 } | Export-Csv -Path $tmp -NoTypeInformation
            Remove-Item $tmp -Force
            $true
        } catch { $false }
    }.Invoke())

    T "Round-trip JSON valide" ({
        try {
            $obj = [PSCustomObject]@{ A = 1; B = 'x' }
            $json = $obj | ConvertTo-Json
            $back = $json | ConvertFrom-Json
            ($back.A -eq 1 -and $back.B -eq 'x')
        } catch { $false }
    }.Invoke())

    T "SafeBrowsingProtectionLevel mappe correctement Off/Standard/Enhanced" (
        (($defs | Where-Object Name -eq 'SafeBrowsingProtectionLevel').TargetValue) -in 0,1,2
    )

    T "Categorie filter -Category retourne un sous-ensemble coherent" ({
        $sub = $defs | Where-Object { $_.Category -in @('Telemetrie') }
        ($sub.Count -gt 0 -and ($sub.Category | Select-Object -Unique) -eq 'Telemetrie')
    }.Invoke())

    T "Dossier de rapport peut etre resolu sans erreur" ({
        try { [IO.Path]::GetFullPath($ReportRoot) | Out-Null; $true } catch { $false }
    }.Invoke())

    T "Dossier de sauvegarde peut etre resolu sans erreur" ({
        try { [IO.Path]::GetFullPath($BackupFolder) | Out-Null; $true } catch { $false }
    }.Invoke())

    T "Get-IntegrityStatus s'execute sans erreur (lecture seule)" ({
        try { $null = Get-IntegrityStatus; $true } catch { $false }
    }.Invoke())

    T "Get-LastAppliedInfo ne leve pas d'exception si aucun etat" ({
        try { $null = Get-LastAppliedInfo; $true } catch { $false }
    }.Invoke())

    $passed = ($tests | Where-Object Pass).Count
    $total  = $tests.Count
    foreach ($t in $tests) {
        if ($t.Pass) { Write-Ok $t.Name } else { Write-Fail $t.Name }
    }
    Write-Host ""
    if ($passed -eq $total) { Write-Host "  SelfTest : $passed/$total — TOUT PASSE" -ForegroundColor Green }
    else { Write-Host "  SelfTest : $passed/$total — ECHECS DETECTES" -ForegroundColor Red }
    Write-Host ""
    return ($passed -eq $total)
}

#endregion

#region MAIN

if ($DebugDefs) {
    $d = Get-BravePolicyDefinitions
    Write-Host ""
    Write-Host "  Total objets retournes par Get-BravePolicyDefinitions : $($d.Count)" -ForegroundColor Cyan
    Write-Host ""
    $i = 0
    foreach ($p in $d) {
        $i++
        Write-Host ("  {0,2}. {1,-35} [{2}]" -f $i, $p.Name, $p.Category)
    }
    Write-Host ""
    foreach ($n in @('PaymentMethodQueryEnabled','SearchSuggestEnabled')) {
        if ($d.Name -contains $n) { Write-Host "  [OK] $n present dans la liste generee" -ForegroundColor Green }
        else { Write-Host "  [x]  $n ABSENT de la liste generee" -ForegroundColor Red }
    }
    Write-Host ""
    Read-Host "Appuyez sur Entree pour fermer" | Out-Null
    exit
}

if ($SelfTest) {
    $ok = Invoke-SelfTest
    Read-Host "Appuyez sur Entrée pour fermer" | Out-Null
    exit ([int](-not $ok))
}

Write-Log "Script démarré (v$ScriptVersion)"

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
            Write-Log "Script terminé"
            Clear-Host
            Write-Host ""
            Write-Host "  Au revoir." -ForegroundColor Gray
            Write-Host ""
        }
        default {
            Write-Host "  Choix invalide." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice.ToUpper() -ne "Q")

#endregion

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDMePxyKH6x2Oi0
# CUzbAat60jpz2oHkPcMT0kQ0xBkMKaCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
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
# ARUwLwYJKoZIhvcNAQkEMSIEIKdJit8VXvyeEsd1tVmRYcyAYIBVFl2Ga1S57k/r
# Z9zrMA0GCSqGSIb3DQEBAQUABIIBAKVL7JQL+dbmzD9x8STVfqSjpImL/BON87al
# khxUlp91LyNtVQrogo3cUT/ufh9VZ+1p4frznmAfYl/gBcz/O23hz6OXXFokKmEE
# cgX2Gydz+gu+52fQdliDyl+Fo5bThKshWlGNvhhErT4pBIAKNPW8GepblplVCFG7
# mcLU6Yur5JAlT89C+f8GrGYY1rbFUlb2jRF6whvS+T1QJwZIclBDIcYUZ0Paqn9k
# zDYQPWYxENLWw0FE/ztncxMZEv4fFyi4WdHvd75NB0zJOlpO4PB48KDqcLn5SFxI
# xVe+bC4KgBKsz3lpPCQ+L+qpEAsG63C4pT17nh5k9SmHprQJPkI=
# SIG # End signature block
