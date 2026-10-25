# Brave-Debloat

🇬🇧 [English version](README.md)

Menu PowerShell interactif qui applique un jeu de policies Brave soigneusement choisies via le registre Windows (`HKLM\SOFTWARE\Policies\BraveSoftware\Brave`) — debloating, télémétrie, réseau et durcissement de sécurité — avec sauvegardes `.reg` automatiques, prévisualisation en mode simulation, restauration en un clic, et vérificateur d'intégrité. Même architecture que [Block-Telemetry](https://github.com/NephVx2/Block-Telemetry).

> Chaque valeur est justifiée. Chaque policy porte une justification en langage clair directement dans le script, deux pièges de régression Chromium connus sont verrouillés par le self-test (`NetworkPredictionOptions`, `ComponentUpdatesEnabled`), et rien de marqué "opt-in" n'est jamais appliqué sans que vous ne le demandiez explicitement.

---

## Captures d'écran

<p align="center">
  <img src="https://raw.githubusercontent.com/NephVx2/Brave-Debloat/main/screenshots/01-menu-preview.png?v=3.3.0" width="49%" />
  <img src="https://raw.githubusercontent.com/NephVx2/Brave-Debloat/main/screenshots/05-html-preview.png?v=3.3.0" width="49%" />
</p>

D'autres captures (diff en mode simulation, vérification d'intégrité, rapport HTML complet) sont dans le dossier [`screenshots/`](https://github.com/NephVx2/Brave-Debloat/tree/main/screenshots).

> **Note :** l'interface (console + rapport HTML) est entièrement en anglais depuis la v3.2.0. Ce README reste en français pour les explications, mais les captures et le texte cite ci-dessous montrent l'écran réel tel qu'il s'affiche.

---

## Sommaire

- [Captures d'écran](#captures-décran)
- [Présentation](#présentation)
- [Fonctionnement](#fonctionnement)
- [Rapports et affichage console](#rapports-et-affichage-console)
- [Ce qui est configuré](#ce-qui-est-configuré)
- [Opt-in uniquement : Lockdown et DNS-over-HTTPS](#opt-in-uniquement--lockdown-et-dns-over-https)
- [Garanties de sécurité](#garanties-de-sécurité)
- [Prérequis](#prérequis)
- [Premier lancement](#premier-lancement-pas-à-pas)
- [Référence du menu](#référence-du-menu)
- [Paramètres en ligne de commande](#paramètres-en-ligne-de-commande)
- [Fichiers écrits par le script](#fichiers-écrits-par-le-script)
- [Déploiement multi-machines](#déploiement-multi-machines)
- [Dépannage](#dépannage)

---

## Présentation

`Brave-Debloat.ps1` écrit des policies Brave à l'échelle machine dans le registre — le même mécanisme que les services informatiques d'entreprise utilisent pour gérer Brave via Group Policy, appliqué ici à une seule machine via un script contrôle et réversible plutôt qu'un contrôleur de domaine.

Il touche **une seule clé de registre et son arborescence** : `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Il ne modifie pas directement les paramètres du profil utilisateur Brave, ne touche à aucun autre navigateur, et n'installe ni ne désinstalle rien.

Comme `Block-Telemetry`, c'est un outil **piloté par menu** — appliquer, mettre à jour et restaurer des policies sont des modifications de configuration durables, pas des tâches de maintenance ponctuelles, donc le script garde un humain dans la boucle plutôt que d'exposer un simple paramètre CLI "fais-le et c'est tout."

---

## Fonctionnement

1. Chaque policy gérée par ce script est définie une seule fois, à un seul endroit (`Get-BravePolicyDefinitions`), chacune avec une `Category`, un `Type` (DWord ou String), une `TargetValue`, et une **justification** expliquant pourquoi cette valeur précise a été choisie — pas juste "désactiver ceci."

2. Avant **toute** écriture dans le registre, un export `.reg` complet de la clé de policies actuelle est effectué (voir [Fichiers écrits par le script](#fichiers-écrits-par-le-script)).

3. L'application compare la valeur registre actuelle de chaque policy à sa cible : les valeurs déjà correctes sont laissées telles quelles, les manquantes ou incorrectes sont écrites, et le résultat est tracé par policy (`Add-Result`) pour les rapports CSV/JSON/HTML.

4. La restauration re-importe la dernière sauvegarde, ramenant la clé de registre exactement à son état avant que ce script n'y touche.

5. Une **vérification d'intégrité** (option de menu `[9]`) relit chaque policy que ce script est censé gérer et signale toute dérive par rapport à sa cible — utile après une mise à jour de Brave, qui réinitialise ou ignore occasionnellement certaines policies.

   ![Vérification d'intégrité des policies](https://raw.githubusercontent.com/NephVx2/Brave-Debloat/main/screenshots/03-policy-integrity.png?v=3.3.0)

---

## Rapports et affichage console

- L'**interface console** utilise un langage visuel homogène : bandeaux encadrés, titres de section `▸`, et icônes de statut — `✔` succès, `✘` erreur, `▲` avertissement ou changement en attente, `●` info, `○` ignoré ou inchangé, `◆` simulation. Apply, la simulation et Restore se terminent chacun par une boîte de résultat encadrée. Pour le meilleur rendu, utiliser **Windows Terminal** (voir [Prérequis](#prérequis)).

- Le **rapport HTML** (option de menu `[7]`, et généré automatiquement après chaque application/mise à jour/simulation) reprend le même style visuel sombre que le reste de la suite : bandeau d'en-tête à dégradé, logo Windows, et une palette de couleurs partagée pour les badges de statut (appliqué / inchangé / échec). Il s'**ouvre automatiquement** dans le navigateur par défaut juste après sa génération, en plus d'être écrit sur le disque.

  ![Génération du rapport HTML](https://raw.githubusercontent.com/NephVx2/Brave-Debloat/main/screenshots/04-html-report.png?v=3.3.0)

- Le **diff en mode simulation** (option de menu `[3]`) est affiche ligne par ligne, horodaté et coloré — icône, catégorie, nom de la policy, ancienne → nouvelle valeur — plutôt que dans un tableau à largeur fixe. Ainsi, une seule valeur longue (par ex. `default_public_interface_only` pour `WebRtcIPHandling`) ne déforme plus jamais l'alignement des autres lignes.

  ![Aperçu du diff en mode simulation](https://raw.githubusercontent.com/NephVx2/Brave-Debloat/main/screenshots/02-dryrun-preview.png?v=3.3.0)

---

## Ce qui est configuré

**53 policies appliquées par défaut**, réparties en 6 catégories :

<details>
<summary><strong>Bloat</strong> — 21 policies</summary>

Désactive les fonctionnalités propres à Brave non utilisées dans cette configuration : Rewards, Wallet, VPN, News, Talk, Speedreader, Wayback Machine, Playlist, Sync, la fenêtre Tor intégrée, Leo AI. Ferme aussi la surface UI/IA Chromium sous-jacente que Brave n'utilise pas nativement mais exposé quand même : onglets et bannières promotionnels, cartes et bandeau d'annonce de la page nouvel onglet, l'icône promo du Web Store (n'empêche pas d'installer des extensions), le bouton "Labs" (fonctionnalités expérimentales), et l'intégration Gemini, "Aide à l'écriture" et comparaison d'onglets IA de Chromium.
</details>

<details>
<summary><strong>Telemetry</strong> — 13 policies</summary>

Le P3A propre à Brave (Privacy-Preserving Product Analytics), le ping de stats quotidien (ceci ne bloque **pas** `laptop-updates.brave.com`, qui reste joignable pour les mises à jour binaires — seul le ping lui-même est coupé), Web Discovery Project, le reporting générique de crash/usage Chromium, le contact avec Google sur les pages d'erreur, la détection de moyens de paiement par les sites, l'envoi en temps réel de la frappe au moteur de suggestions, les sondages de feedback, la collecte de données "anonymisées" liées à l'URL, le rapport étendu Safe Browsing, la collecte de logs WebRTC vers Google, et le cloud reporting (sans effet sur un poste perso non enrôlé, conservé par cohérence de défense en profondeur).
</details>

<details>
<summary><strong>Network</strong> — 5 policies (7 avec DNS-over-HTTPS activé)</summary>

`NetworkPredictionOptions` réglé sur **2** — c'est le seul réglage de tout le catalogue avec un piège de régression documenté : 0 ou 1 signifient tous les deux que la prédiction est *active*, seul 2 désactive réellement le DNS prefetch/preconnect. Également : empêche Brave de tourner en arrière-plan après la fermeture de la fenêtre, empêche WebRTC de révéler une IP locale/privée même derrière un VPN ou un proxy, force le résolveur DNS de l'OS plutôt que le résolveur interne de Chromium (cohérent avec un filtre DNS système comme NextDNS), et désactive la détection automatique de proxy WPAD à chaque changement de réseau.
</details>

<details>
<summary><strong>Security</strong> — 8 policies</summary>

`ComponentUpdatesEnabled` est explicitement laisse **actif** — ce n'est pas seulement le binaire Brave, cela couvre aussi Widevine, les listes Safe Browsing, et le magasin de certificats racine, donc cette policy n'est jamais touchée. Également : force les mises à niveau HTTPS quand disponibles, niveau Safe Browsing configurable (voir ci-dessous), bloque les outils externes de s'attacher au port de débogage distant de Brave, bloque l'authentification HTTP Basic transmise en clair, empêche l'authentification NTLM/Kerberos automatique de fuiter des identifiants Windows en navigation privée, bloque le spoofing par prompt d'authentification cross-origin, et désactive les Signed HTTP Exchanges (qui peuvent masquer l'origine réelle d'une page).
</details>

<details>
<summary><strong>PrivacySandbox</strong> — 4 policies</summary>

Bloque les API de profilage publicitaire de Chromium (Topics, le prompt Privacy Sandbox, les API publicitaires par site — les trois premières sont marquées "Obsolète" dans `brave://policy/` actuel mais conservées pour compatibilité avec d'anciennes versions de Brave) et le remplacement actuellement actif, Attribution Reporting (mesure publicitaire cross-site).
</details>

<details>
<summary><strong>Performance</strong> — 2 policies</summary>

Active Memory Saver (High Efficiency Mode) et règle son agressivité sur **Équilibré** plutôt que Maximum — Maximum a été volontairement écarté car causant trop de rechargements d'onglets surprise sur un usage multi-onglets avec 16 Go de RAM disponibles. (0 = Modéré, 1 = Équilibré, 2 = Maximum.)
</details>

**Explicitement laisses intacts :** la traduction de pages et le correcteur orthographique (y compris le service de correction en ligne) sont des fonctionnalités utilisées et sont volontairement absents de toute la liste de policies du script, de sa catégorisation, et de son self-test — pas un oubli.

---

## Opt-in uniquement : Lockdown et DNS-over-HTTPS

Deux catégories supplémentaires existent dans le script mais ne sont **jamais appliquées sans demande explicite** :

<details>
<summary><strong>Lockdown</strong> — 5 policies, nécessite <code>-IncludeLockdown</code></summary>

Ce ne sont pas des fuites de confidentialité — ce sont des restrictions de fonctionnalités, destinées uniquement à un choix de durcissement délibéré (ex : une machine partagée ou exposée au public) : désactive le gestionnaire de mots de passe intégré, l'autofill d'adresses, et l'autofill de cartes bancaires. **L'accès aux DevTools est volontairement laissé actif** même sous `-IncludeLockdown` (un poste personnel à besoin des DevTools), et il en va de même pour le mode Incognito (le restreindre n'a de sens que sur une machine partagée) — les deux sont verrouillés par des assertions dédiées du self-test plutôt que laisses au hasard.
</details>

<details>
<summary><strong>DNS-over-HTTPS</strong> — 2 policies, nécessite <code>-DnsOverHttpsTemplate &lt;url&gt;</code></summary>

Force le résolveur DoH propre à Brave vers un endpoint que vous fournissez. Absent par défaut spécifiquement pour qu'il ne puisse pas contourner silencieusement un filtre DNS système comme NextDNS — une assertion dédiée du self-test confirme que ces deux policies sont totalement absentes de la liste de définitions tant que le paramètre n'est pas fourni.
</details>

---

## Garanties de sécurité

| # | Garantie |
|---|---|
| S1 | Sauvegarde `.reg` automatique avant toute modification (`reg export`) |
| S2 | Rotation automatique des sauvegardes (conservation des 10 dernières) |
| S3 | Mode simulation pour prévisualiser le diff sans rien changer |
| S4 | Fonction de restauration complète intégrée (un seul choix au menu) |
| S5 | Option "Mettre à jour" intégrée (nettoie les résidus + re-applique en une étape) |
| S6 | Garde-fous anti-régression intégrés au self-test (`NetworkPredictionOptions`, `ComponentUpdatesEnabled`) |
| S7 | Détection de conflits (policies HKCU, sous-clé `Recommended`, résidus) |
| S8 | Vérification d'intégrité (policies définies vs ce qui est réellement actif dans le registre) |
| S9 | DoH et Lockdown restent opt-in explicite — jamais appliqués par défaut |

---

## Prérequis

- Windows 10 ou 11 avec Brave Browser installé.
- PowerShell 5.1 (intégré à Windows) ou PowerShell 7+.
- Recommandé : **Windows Terminal** (par défaut sur Windows 11) pour le meilleur rendu de l'interface console (caractères de cadre et icônes de statut). La fenêtre console classique fonctionne aussi, mais certaines icônes dépendent de la police choisie.
- Droits administrateur — nécessaires car la cible est `HKLM` (à l'échelle machine), pas `HKCU`. Le script s'auto-élève au démarrage, sauf pour `-SelfTest` et `-DebugDefs`, qui fonctionnent en lecture seule et **ne nécessitent pas** d'élévation.
- Si le script est signé numériquement (recommandé en environnement `-ExecutionPolicy AllSigned`/`RemoteSigned`) : le certificat de signature doit être approuvé sur la machine cible.

---

## Premier lancement (pas à pas)

1. Copier `Brave-Debloat.ps1` sur la machine cible.

2. Ouvrir un terminal PowerShell (pas besoin de le lancer en admin à la main — le script s'auto-élève, sauf pour les vérifications en lecture seule ci-dessous).

   Puis se placer dans le dossier qui contient le script (adapter le chemin ; garder les guillemets s'il contient des espaces) :

   ```powershell
   cd "$HOME\Downloads"
   ```

3. **Débloquer le script** s'il a été téléchargé depuis Internet. Windows marque les fichiers téléchargés, et la politique d'exécution de PowerShell (`RemoteSigned`, par exemple) refuse de lancer un script marqué. Depuis le dossier du script :

   ```powershell
   Unblock-File .\Brave-Debloat.ps1
   ```

   Si PowerShell indique plutôt que l'exécution de scripts est désactivée sur ce système (la politique par défaut de Windows est `Restricted`), autoriser d'abord les scripts pour le compte courant (la modification ne s'applique qu'à ce compte, pas à toute la machine) :

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

   Toujours bloqué ? Voir le [guide pas à pas](https://github.com/NephVx2/Script-blocked-Look-at-this/blob/main/README_POWERSHELL_FRENCH.md).

4. Lancer d'abord le self-test — lecture seule, aucun droit admin requis :

   ```powershell
   .\Brave-Debloat.ps1 -SelfTest
   ```

   Exécute 21 assertions : intégrité de la liste de policies (pas de doublons, types de valeurs corrects), les deux garde-fous de régression (`NetworkPredictionOptions` = 2, `ComponentUpdatesEnabled` = 1), Lockdown/DoH restent absents sans demande explicite, les DevTools restent actifs même sous Lockdown, traduction/correcteur orthographique confirmés absents de tout le script, et plusieurs fonctions internes s'exécutent sans lever d'exception. Code de sortie `0` = tout passe, `1` = au moins un échec.

5. *(Optionnel)* Inspecter la liste complète des policies sans toucher au registre :

   ```powershell
   .\Brave-Debloat.ps1 -DebugDefs
   ```

6. Lancer le script normalement (accepter le prompt UAC) :

   ```powershell
   .\Brave-Debloat.ps1
   ```

7. Depuis le menu, prévisualiser ce qui changerait **sans rien écrire** :

   ```
   [3] Simulate without changing (DryRun)
   ```

8. Appliquer les policies pour de vrai :

   ```
   [1] Apply changes
   ```

   Sauvegarde l'état actuel du registre, écrit les valeurs cibles, et enregistre le résultat pour les rapports.

9. Redémarrer Brave pour que les nouvelles policies prennent effet (les navigateurs basés sur Chromium lisent la plupart des policies au démarrage). Confirmer dans le navigateur via `brave://policy/`.

10. Vérifier l'intégrité à tout moment ensuite avec l'option `[9]` — utile après une mise à jour de Brave, qui réinitialise occasionnellement certaines policies à leurs valeurs par défaut.

11. Pour tout annuler, utiliser l'option `[4]` (Restaurer) — re-importe la sauvegarde prise avant la dernière modification.

---

## Référence du menu

| Option | Action |
|---|---|
| `[1]` | Appliquer les policies pour de vrai (sauvegarde → comparaison → écriture → enregistrement des résultats) |
| `[2]` | Mettre à jour — nettoie les résidus, puis re-applique depuis zéro en une étape |
| `[3]` | Simulation : prévisualise le diff sans rien écrire |
| `[4]` | **Restaurer** les paramètres d'origine depuis la dernière sauvegarde |
| `[5]` | Lister les sauvegardes disponibles |
| `[6]` | Vider le cache DNS manuellement |
| `[7]` | Générer un rapport HTML (s'ouvre automatiquement dans le navigateur par défaut) |
| `[8]` | Vérifier les conflits (policies HKCU surchargeant HKLM, sous-clé `Recommended` présente, résidus d'une version précédente) |
| `[9]` | Vérifier l'intégrité — policies définies vs ce qui est réellement actif dans le registre en ce moment |
| `[10]` | Exporter la liste de policies actuellement active vers un fichier `.txt` |
| `[Q]` | Quitter |

Le menu est organisé en trois groupes — **Policies** (`[1]`–`[4]`), **Backups & DNS** (`[5]`–`[6]`) et **Reports & diagnostics** (`[7]`–`[10]`) — sous un panneau **Status** qui affiche en un coup d'œil le nombre de policies appliquées (ex : `42/53`), la dernière action et sa date, et un indicateur d'intégrité compact (la même vérification que l'option `[9]`).

---

## Paramètres en ligne de commande

| Paramètre | Description |
|---|---|
| `-SelfTest` | Exécute la batterie de tests internes à 21 assertions puis quitte. Aucun droit admin requis, registre jamais touché. |
| `-DebugDefs` | Affiche la liste numérotée complète des policies (nom + catégorie) telle que définie actuellement, plus deux vérifications de présence de policies nommées, puis quitte. Aucun droit admin requis, registre jamais touché. |
| `-Category <nom(s)>` | Restreint une action à une ou plusieurs catégories (ex : `-Category Telemetry,Network`) au lieu de l'ensemble complet. |
| `-IncludeLockdown` | Ajoute les 5 policies Lockdown opt-in à l'action lancée (appliquer/mettre à jour/simuler). Voir [Opt-in uniquement](#opt-in-uniquement--lockdown-et-dns-over-https). |
| `-SafeBrowsingLevel <Off\|Standard\|Enhanced>` | Règle le niveau Safe Browsing de Brave. Par défaut `Standard` (listes locales, pas de partage temps réel avec Google). `Enhanced` offre une meilleure détection mais envoie en continu des URL et échantillons de page à Google. `Off` est disponible mais déconseillé. |
| `-DnsOverHttpsTemplate <url>` | Fournir ce paramètre active les 2 policies DoH opt-in, pointées vers votre URL. Voir [Opt-in uniquement](#opt-in-uniquement--lockdown-et-dns-over-https). |

**Exemples :**

```powershell
.\Brave-Debloat.ps1 -SelfTest
.\Brave-Debloat.ps1 -Category Telemetry,Network
.\Brave-Debloat.ps1 -IncludeLockdown
.\Brave-Debloat.ps1 -SafeBrowsingLevel Enhanced
.\Brave-Debloat.ps1 -DnsOverHttpsTemplate "https://dns.nextdns.io/xxxxxx"
```

---

## Fichiers écrits par le script

| Fichier / dossier | Contenu |
|---|---|
| `%USERPROFILE%\Desktop\Maintenance_Reports\Brave-Debloat\Registry-Backups\*.reg` | Export `reg export` complet de la clé de policies, pris avant chaque écriture réelle (rotation automatique, 10 dernières conservées) |
| `%USERPROFILE%\Desktop\Maintenance_Reports\Brave-Debloat\Brave-Debloat_Log.txt` | Journal d'actions en texte brut (ajout uniquement) |
| `%USERPROFILE%\Desktop\Maintenance_Reports\Brave-Debloat\_last_state.json` | Instantané du dernier état appliqué, utilise par la vérification d'intégrité |
| `%USERPROFILE%\Desktop\Maintenance_Reports\Brave-Debloat\*.csv` / `*.json` / `*.html` | Rapports générés après chaque application / mise à jour / simulation, et via l'option de menu `[7]` |
| `%USERPROFILE%\Desktop\Maintenance_Reports\Brave-Debloat\Brave-Debloat_Export_<horodatage>.txt` *(à la demande, option de menu `[10]`)* | Liste texte des policies actuellement actives |

`-SelfTest` et `-DebugDefs` n'écrivent **aucun** fichier et ne touchent **aucune** clé de registre.

---

## Déploiement multi-machines

1. **Distribuer** le fichier `.ps1` vers chaque machine cible.

2. **Approuver le certificat de signature** si une politique d'exécution stricte est en place (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Exécuter `-SelfTest` en premier** sur chaque machine — aucun droit admin nécessaire, registre non touché, sans risque à lancer avant de décider de la suite.

4. Comme il s'agit d'une **modification de configuration durable pilotée par menu** (pas d'une tâche de nettoyage ponctuelle), ce n'est pas un candidat direct pour une tâche planifiée silencieuse. Pour un déploiement multi-machines non supervisé, l'option la plus propre est d'appeler `Invoke-BraveAction` directement depuis votre propre script d'encapsulation avec les paramètres nécessaires (`-Category`, `-IncludeLockdown`, etc.) plutôt que de piloter le menu interactif.

5. Les sauvegardes, logs et rapports sont écrits dans le profil de l'utilisateur qui exécute le script — propres à chaque machine, non centralisés automatiquement.

6. Si votre parc utilise Group Policy ou une solution MDM qui gère déjà Brave de manière centralisée, vérifier les conflits (option de menu `[8]`) avant de lancer ce script sur une machine gérée par domaine — les policies HKLM définies ici pourraient entrer en concurrence avec celles poussées par ce système.

---

## Dépannage

<details>
<summary><strong>Une policy apparaît active dans le registre mais Brave ne semble pas la respecter</strong></summary>

Redémarrer Brave — les navigateurs basés sur Chromium lisent la plupart des policies au démarrage, pas en temps réel. Confirmer via `brave://policy/`, qui montre chaque policy que Brave voit actuellement, sa source, et sa valeur réellement appliquée.
</details>

<details>
<summary><strong>La vérification d'intégrité (option [9]) signale une dérive après une mise à jour de Brave</strong></summary>

Certaines mises à jour de Brave réinitialisent ou réintroduisent des valeurs par défaut pour certaines policies. Relancer l'option `[2]` (Mettre à jour) pour nettoyer et re-appliquer depuis les définitions actuelles du script.
</details>

<details>
<summary><strong>La vérification de conflits (option [8]) signale une policy HKCU ou une sous-clé Recommended</strong></summary>

Une policy au niveau HKCU pour le même paramètre, ou une sous-clé `Recommended` sous le chemin de policy géré, peut surcharger ou masquer ce que ce script définit au niveau `HKLM`. Investiguer ce qui l'a créée (un autre outil, un résidu de test manuel, ou une gestion réelle par domaine/MDM) avant de la supprimer.
</details>

<details>
<summary><strong>Certaines icônes ou caractères de cadre s'affichent en carrés ou semblent décalés</strong></summary>

L'interface console utilise des caractères Unicode (lignes de cadre et icônes de statut comme `✔ ✘ ▲ ● ○ ◆`). **Windows Terminal** les affiche correctement sans configuration. Dans la fenêtre console classique, la police choisie peut ne pas contenir certains glyphes — passer à une police comme **Cascadia Mono** ou **Consolas**, ou lancer le script depuis Windows Terminal. C'est purement cosmétique et n'affecte jamais ce que fait le script.
</details>

<details>
<summary><strong>-SelfTest signale un FAIL</strong></summary>

Les 21 assertions sont des vérifications de cohérence interne sur les définitions de policies et les fonctions auxiliaires — un FAIL pointe vers un invariant précis casse (ex : `NetworkPredictionOptions` ne ciblant plus 2, un nom de policy dupliqué, des policies Lockdown présentes sans `-IncludeLockdown`). Lire le nom de l'assertion en échec pour identifier le problème précis.
</details>

<details>
<summary><strong>Je veux changer la valeur cible d'une policy spécifique</strong></summary>

Éditer directement sa ligne `New-Policy` dans `Get-BravePolicyDefinitions`, puis relancer `-SelfTest` avant d'appliquer — plusieurs policies ont un piège de régression documenté dans le commentaire qui les entoure (`NetworkPredictionOptions`, `ComponentUpdatesEnabled` en particulier), donc lire le commentaire au-dessus de la ligne avant de changer sa valeur.
</details>

---

<sub>Brave-Debloat — basé sur le registre (policies HKLM uniquement), sauvegarde automatique avant chaque modification, rien d'opt-in appliqué sans flag explicite.</sub>
