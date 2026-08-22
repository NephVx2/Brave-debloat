# Configure-Brave_Win11

🇬🇧 [English version](README.md)

Menu PowerShell interactif qui applique un jeu de policies Brave soigneusement choisies via le registre Windows (`HKLM\SOFTWARE\Policies\BraveSoftware\Brave`) — debloating, telemetrie, reseau et durcissement de securite — avec sauvegardes `.reg` automatiques, previsualisation en mode simulation, restauration en un clic, et verificateur d'integrite. Meme architecture que [Block-Telemetry](../Block-Telemetry).

> Chaque valeur est justifiee. Chaque policy porte une justification en langage clair directement dans le script, deux pieges de regression Chromium connus sont verrouilles par le self-test (`NetworkPredictionOptions`, `ComponentUpdatesEnabled`), et rien de marque "opt-in" n'est jamais applique sans que vous ne le demandiez explicitement.

---

## Sommaire

- [Presentation](#presentation)
- [Fonctionnement](#fonctionnement)
- [Ce qui est configure](#ce-qui-est-configure)
- [Opt-in uniquement : Lockdown et DNS-over-HTTPS](#opt-in-uniquement--lockdown-et-dns-over-https)
- [Garanties de securite](#garanties-de-securite)
- [Prerequis](#prerequis)
- [Premier lancement](#premier-lancement-pas-a-pas)
- [Reference du menu](#reference-du-menu)
- [Parametres en ligne de commande](#parametres-en-ligne-de-commande)
- [Fichiers ecrits par le script](#fichiers-ecrits-par-le-script)
- [Deploiement multi-machines](#deploiement-multi-machines)
- [Depannage](#depannage)

---

## Presentation

`Configure-Brave_Win11_v3.ps1` ecrit des policies Brave a l'echelle machine dans le registre — le meme mecanisme que les services informatiques d'entreprise utilisent pour gerer Brave via Group Policy, applique ici a une seule machine via un script controle et reversible plutot qu'un controleur de domaine.

Il touche **une seule cle de registre et son arborescence** : `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Il ne modifie pas directement les parametres du profil utilisateur Brave, ne touche a aucun autre navigateur, et n'installe ni ne desinstalle rien.

Comme `Block-Telemetry`, c'est un outil **pilote par menu** — appliquer, mettre a jour et restaurer des policies sont des modifications de configuration durables, pas des taches de maintenance ponctuelles, donc le script garde un humain dans la boucle plutot que d'exposer un simple parametre CLI "fais-le et c'est tout."

---

## Fonctionnement

1. Chaque policy geree par ce script est definie une seule fois, a un seul endroit (`Get-BravePolicyDefinitions`), chacune avec une `Category`, un `Type` (DWord ou String), une `TargetValue`, et une **justification** expliquant pourquoi cette valeur precise a ete choisie — pas juste "desactiver ceci."

2. Avant **toute** ecriture dans le registre, un export `.reg` complet de la cle de policies actuelle est effectue (voir [Fichiers ecrits par le script](#fichiers-ecrits-par-le-script)).

3. L'application compare la valeur registre actuelle de chaque policy a sa cible : les valeurs deja correctes sont laissees telles quelles, les manquantes ou incorrectes sont ecrites, et le resultat est trace par policy (`Add-Result`) pour les rapports CSV/JSON/HTML.

4. La restauration re-importe la derniere sauvegarde, ramenant la cle de registre exactement a son etat avant que ce script n'y touche.

5. Une **verification d'integrite** (option de menu `[9]`) relit chaque policy que ce script est cense gerer et signale toute derive par rapport a sa cible — utile apres une mise a jour de Brave, qui reinitialise ou ignore occasionnellement certaines policies.

---

## Ce qui est configure

**53 policies appliquees par defaut**, reparties en 6 categories :

<details>
<summary><strong>Bloat</strong> — 21 policies</summary>

Desactive les fonctionnalites propres a Brave non utilisees dans cette configuration : Rewards, Wallet, VPN, News, Talk, Speedreader, Wayback Machine, Playlist, Sync, la fenetre Tor integree, Leo AI. Ferme aussi la surface UI/IA Chromium sous-jacente que Brave n'utilise pas nativement mais expose quand meme : onglets et bannieres promotionnels, cartes et bandeau d'annonce de la page nouvel onglet, l'icone promo du Web Store (n'empeche pas d'installer des extensions), le bouton "Labs" (fonctionnalites experimentales), et l'integration Gemini, "Aide a l'ecriture" et comparaison d'onglets IA de Chromium.
</details>

<details>
<summary><strong>Telemetrie</strong> — 13 policies</summary>

Le P3A propre a Brave (Privacy-Preserving Product Analytics), le ping de stats quotidien (ceci ne bloque **pas** `laptop-updates.brave.com`, qui reste joignable pour les mises a jour binaires — seul le ping lui-meme est coupe), Web Discovery Project, le reporting generique de crash/usage Chromium, le contact avec Google sur les pages d'erreur, la detection de moyens de paiement par les sites, l'envoi en temps reel de la frappe au moteur de suggestions, les sondages de feedback, la collecte de donnees "anonymisees" liees a l'URL, le rapport etendu Safe Browsing, la collecte de logs WebRTC vers Google, et le cloud reporting (sans effet sur un poste perso non enrole, conserve par coherence de defense en profondeur).
</details>

<details>
<summary><strong>Reseau</strong> — 5 policies (7 avec DNS-over-HTTPS active)</summary>

`NetworkPredictionOptions` regle sur **2** — c'est le seul reglage de tout le catalogue avec un piege de regression documente : 0 ou 1 signifient tous les deux que la prediction est *active*, seul 2 desactive reellement le DNS prefetch/preconnect. Egalement : empeche Brave de tourner en arriere-plan apres la fermeture de la fenetre, empeche WebRTC de reveler une IP locale/privee meme derriere un VPN ou un proxy, force le resolveur DNS de l'OS plutot que le resolveur interne de Chromium (coherent avec un filtre DNS systeme comme NextDNS), et desactive la detection automatique de proxy WPAD a chaque changement de reseau.
</details>

<details>
<summary><strong>Securite</strong> — 8 policies</summary>

`ComponentUpdatesEnabled` est explicitement laisse **actif** — ce n'est pas seulement le binaire Brave, cela couvre aussi Widevine, les listes Safe Browsing, et le magasin de certificats racine, donc cette policy n'est jamais touchee. Egalement : force les mises a niveau HTTPS quand disponibles, niveau Safe Browsing configurable (voir ci-dessous), bloque les outils externes de s'attacher au port de debogage distant de Brave, bloque l'authentification HTTP Basic transmise en clair, empeche l'authentification NTLM/Kerberos automatique de fuiter des identifiants Windows en navigation privee, bloque le spoofing par prompt d'authentification cross-origin, et desactive les Signed HTTP Exchanges (qui peuvent masquer l'origine reelle d'une page).
</details>

<details>
<summary><strong>PrivacySandbox</strong> — 4 policies</summary>

Bloque les API de profilage publicitaire de Chromium (Topics, le prompt Privacy Sandbox, les API publicitaires par site — les trois premieres sont marquees "Obsolete" dans `brave://policy/` actuel mais conservees pour compatibilite avec d'anciennes versions de Brave) et le remplacement actuellement actif, Attribution Reporting (mesure publicitaire cross-site).
</details>

<details>
<summary><strong>Performance</strong> — 2 policies</summary>

Active Memory Saver (High Efficiency Mode) et regle son agressivite sur **Equilibre** plutot que Maximum — Maximum a ete volontairement ecarte car causant trop de rechargements d'onglets surprise sur un usage multi-onglets avec 16 Go de RAM disponibles. (0 = Modere, 1 = Equilibre, 2 = Maximum.)
</details>

**Explicitement laisses intacts :** la traduction de pages et le correcteur orthographique (y compris le service de correction en ligne) sont des fonctionnalites utilisees et sont volontairement absents de toute la liste de policies du script, de sa categorisation, et de son self-test — pas un oubli.

---

## Opt-in uniquement : Lockdown et DNS-over-HTTPS

Deux categories supplementaires existent dans le script mais ne sont **jamais appliquees sans demande explicite** :

<details>
<summary><strong>Lockdown</strong> — 5 policies, necessite <code>-IncludeLockdown</code></summary>

Ce ne sont pas des fuites de confidentialite — ce sont des restrictions de fonctionnalites, destinees uniquement a un choix de durcissement delibere (ex : une machine partagee ou exposee au public) : desactive le gestionnaire de mots de passe integre, l'autofill d'adresses, et l'autofill de cartes bancaires. **L'acces aux DevTools est volontairement laisse actif** meme sous `-IncludeLockdown` (un poste personnel a besoin des DevTools), et il en va de meme pour le mode Incognito (le restreindre n'a de sens que sur une machine partagee) — les deux sont verrouilles par des assertions dediees du self-test plutot que laisses au hasard.
</details>

<details>
<summary><strong>DNS-over-HTTPS</strong> — 2 policies, necessite <code>-DnsOverHttpsTemplate &lt;url&gt;</code></summary>

Force le resolveur DoH propre a Brave vers un endpoint que vous fournissez. Absent par defaut specifiquement pour qu'il ne puisse pas contourner silencieusement un filtre DNS systeme comme NextDNS — une assertion dediee du self-test confirme que ces deux policies sont totalement absentes de la liste de definitions tant que le parametre n'est pas fourni.
</details>

---

## Garanties de securite

| # | Garantie |
|---|---|
| S1 | Sauvegarde `.reg` automatique avant toute modification (`reg export`) |
| S2 | Rotation automatique des sauvegardes (conservation des 10 dernieres) |
| S3 | Mode simulation pour previsualiser le diff sans rien changer |
| S4 | Fonction de restauration complete integree (un seul choix au menu) |
| S5 | Option "Mettre a jour" integree (nettoie les residus + re-applique en une etape) |
| S6 | Garde-fous anti-regression integres au self-test (`NetworkPredictionOptions`, `ComponentUpdatesEnabled`) |
| S7 | Detection de conflits (policies HKCU, sous-cle `Recommended`, residus) |
| S8 | Verification d'integrite (policies definies vs ce qui est reellement actif dans le registre) |
| S9 | DoH et Lockdown restent opt-in explicite — jamais appliques par defaut |

---

## Prerequis

- Windows 10 ou 11 avec Brave Browser installe.
- PowerShell 5.1 (integre a Windows) ou PowerShell 7+.
- Droits administrateur — necessaires car la cible est `HKLM` (a l'echelle machine), pas `HKCU`. Le script s'auto-eleve au demarrage, sauf pour `-SelfTest` et `-DebugDefs`, qui fonctionnent en lecture seule et **ne necessitent pas** d'elevation.
- Si le script est signe numeriquement (recommande en environnement `-ExecutionPolicy AllSigned`/`RemoteSigned`) : le certificat de signature doit etre approuve sur la machine cible.

---

## Premier lancement (pas a pas)

1. Copier `Configure-Brave_Win11_v3.ps1` sur la machine cible.

2. Ouvrir un terminal PowerShell (pas besoin de le lancer en admin a la main — le script s'auto-eleve, sauf pour les verifications en lecture seule ci-dessous).

3. Lancer d'abord le self-test — lecture seule, aucun droit admin requis :

   ```powershell
   .\Configure-Brave_Win11_v3.ps1 -SelfTest
   ```

   Execute 19 assertions : integrite de la liste de policies (pas de doublons, types de valeurs corrects), les deux garde-fous de regression (`NetworkPredictionOptions` = 2, `ComponentUpdatesEnabled` = 1), Lockdown/DoH restent absents sans demande explicite, les DevTools restent actifs meme sous Lockdown, traduction/correcteur orthographique confirmes absents de tout le script, et plusieurs fonctions internes s'executent sans lever d'exception. Code de sortie `0` = tout passe, `1` = au moins un echec.

4. *(Optionnel)* Inspecter la liste complete des policies sans toucher au registre :

   ```powershell
   .\Configure-Brave_Win11_v3.ps1 -DebugDefs
   ```

5. Lancer le script normalement (accepter le prompt UAC) :

   ```powershell
   .\Configure-Brave_Win11_v3.ps1
   ```

6. Depuis le menu, previsualiser ce qui changerait **sans rien ecrire** :

   ```
   [3] Simuler sans modifier (DryRun)
   ```

7. Appliquer les policies pour de vrai :

   ```
   [1] Appliquer les modifications
   ```

   Sauvegarde l'etat actuel du registre, ecrit les valeurs cibles, et enregistre le resultat pour les rapports.

8. Redemarrer Brave pour que les nouvelles policies prennent effet (les navigateurs bases sur Chromium lisent la plupart des policies au demarrage). Confirmer dans le navigateur via `brave://policy/`.

9. Verifier l'integrite a tout moment ensuite avec l'option `[9]` — utile apres une mise a jour de Brave, qui reinitialise occasionnellement certaines policies a leurs valeurs par defaut.

10. Pour tout annuler, utiliser l'option `[4]` (Restaurer) — re-importe la sauvegarde prise avant la derniere modification.

---

## Reference du menu

| Option | Action |
|---|---|
| `[1]` | Appliquer les policies pour de vrai (sauvegarde → comparaison → ecriture → enregistrement des resultats) |
| `[2]` | Mettre a jour — nettoie les residus, puis re-applique depuis zero en une etape |
| `[3]` | Simulation : previsualise le diff sans rien ecrire |
| `[4]` | **Restaurer** les parametres d'origine depuis la derniere sauvegarde |
| `[5]` | Lister les sauvegardes disponibles |
| `[6]` | Vider le cache DNS manuellement |
| `[7]` | Generer un rapport HTML |
| `[8]` | Verifier les conflits (policies HKCU surchargeant HKLM, sous-cle `Recommended` presente, residus d'une version precedente) |
| `[9]` | Verifier l'integrite — policies definies vs ce qui est reellement actif dans le registre en ce moment |
| `[10]` | Exporter la liste de policies actuellement active vers un fichier `.txt` |
| `[Q]` | Quitter |

---

## Parametres en ligne de commande

| Parametre | Description |
|---|---|
| `-SelfTest` | Execute la batterie de tests internes a 19 assertions puis quitte. Aucun droit admin requis, registre jamais touche. |
| `-DebugDefs` | Affiche la liste numerotee complete des policies (nom + categorie) telle que definie actuellement, plus deux verifications de presence de policies nommees, puis quitte. Aucun droit admin requis, registre jamais touche. |
| `-Category <nom(s)>` | Restreint une action a une ou plusieurs categories (ex : `-Category Telemetrie,Reseau`) au lieu de l'ensemble complet. |
| `-IncludeLockdown` | Ajoute les 5 policies Lockdown opt-in a l'action lancee (appliquer/mettre a jour/simuler). Voir [Opt-in uniquement](#opt-in-uniquement--lockdown-et-dns-over-https). |
| `-SafeBrowsingLevel <Off\|Standard\|Enhanced>` | Regle le niveau Safe Browsing de Brave. Par defaut `Standard` (listes locales, pas de partage temps reel avec Google). `Enhanced` offre une meilleure detection mais envoie en continu des URL et echantillons de page a Google. `Off` est disponible mais deconseille. |
| `-DnsOverHttpsTemplate <url>` | Fournir ce parametre active les 2 policies DoH opt-in, pointees vers votre URL. Voir [Opt-in uniquement](#opt-in-uniquement--lockdown-et-dns-over-https). |

**Exemples :**

```powershell
.\Configure-Brave_Win11_v3.ps1 -SelfTest
.\Configure-Brave_Win11_v3.ps1 -Category Telemetrie,Reseau
.\Configure-Brave_Win11_v3.ps1 -IncludeLockdown
.\Configure-Brave_Win11_v3.ps1 -SafeBrowsingLevel Enhanced
.\Configure-Brave_Win11_v3.ps1 -DnsOverHttpsTemplate "https://dns.nextdns.io/xxxxxx"
```

---

## Fichiers ecrits par le script

| Fichier / dossier | Contenu |
|---|---|
| `%USERPROFILE%\Desktop\Registry_Backups\ConfigBrave\*.reg` | Export `reg export` complet de la cle de policies, pris avant chaque ecriture reelle (rotation automatique, 10 dernieres conservees) |
| `%USERPROFILE%\Desktop\Configure-Brave_Log.txt` | Journal d'actions en texte brut (ajout uniquement) |
| `%USERPROFILE%\Desktop\Rapports_Maintenance\ConfigBrave\_dernier_etat.json` | Instantane du dernier etat applique, utilise par la verification d'integrite |
| `%USERPROFILE%\Desktop\Rapports_Maintenance\ConfigBrave\*.csv` / `*.json` / `*.html` | Rapports generes via l'option de menu `[7]` |
| Fichier d'export *(a la demande, option de menu `[10]`)* | Liste texte des policies actuellement actives |

`-SelfTest` et `-DebugDefs` n'ecrivent **aucun** fichier et ne touchent **aucune** cle de registre.

---

## Deploiement multi-machines

1. **Distribuer** le fichier `.ps1` vers chaque machine cible.

2. **Approuver le certificat de signature** si une politique d'execution stricte est en place (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Executer `-SelfTest` en premier** sur chaque machine — aucun droit admin necessaire, registre non touche, sans risque a lancer avant de decider de la suite.

4. Comme il s'agit d'une **modification de configuration durable pilotee par menu** (pas d'une tache de nettoyage ponctuelle), ce n'est pas un candidat direct pour une tache planifiee silencieuse. Pour un deploiement multi-machines non supervise, l'option la plus propre est d'appeler `Invoke-BraveAction` directement depuis votre propre script d'encapsulation avec les parametres necessaires (`-Category`, `-IncludeLockdown`, etc.) plutot que de piloter le menu interactif.

5. Les sauvegardes, logs et rapports sont ecrits dans le profil de l'utilisateur qui execute le script — propres a chaque machine, non centralises automatiquement.

6. Si votre parc utilise Group Policy ou une solution MDM qui gere deja Brave de maniere centralisee, verifier les conflits (option de menu `[8]`) avant de lancer ce script sur une machine geree par domaine — les policies HKLM definies ici pourraient entrer en concurrence avec celles poussees par ce systeme.

---

## Depannage

<details>
<summary><strong>Une policy apparait active dans le registre mais Brave ne semble pas la respecter</strong></summary>

Redemarrer Brave — les navigateurs bases sur Chromium lisent la plupart des policies au demarrage, pas en temps reel. Confirmer via `brave://policy/`, qui montre chaque policy que Brave voit actuellement, sa source, et sa valeur reellement appliquee.
</details>

<details>
<summary><strong>La verification d'integrite (option [9]) signale une derive apres une mise a jour de Brave</strong></summary>

Certaines mises a jour de Brave reinitialisent ou reintroduisent des valeurs par defaut pour certaines policies. Relancer l'option `[2]` (Mettre a jour) pour nettoyer et re-appliquer depuis les definitions actuelles du script.
</details>

<details>
<summary><strong>La verification de conflits (option [8]) signale une policy HKCU ou une sous-cle Recommended</strong></summary>

Une policy au niveau HKCU pour le meme parametre, ou une sous-cle `Recommended` sous le chemin de policy gere, peut surcharger ou masquer ce que ce script definit au niveau `HKLM`. Investiguer ce qui l'a creee (un autre outil, un residu de test manuel, ou une gestion reelle par domaine/MDM) avant de la supprimer.
</details>

<details>
<summary><strong>-SelfTest signale un FAIL</strong></summary>

Les 19 assertions sont des verifications de coherence interne sur les definitions de policies et les fonctions auxiliaires — un FAIL pointe vers un invariant precis casse (ex : `NetworkPredictionOptions` ne ciblant plus 2, un nom de policy duplique, des policies Lockdown presentes sans `-IncludeLockdown`). Lire le nom de l'assertion en echec pour identifier le probleme precis.
</details>

<details>
<summary><strong>Je veux changer la valeur cible d'une policy specifique</strong></summary>

Editer directement sa ligne `New-Policy` dans `Get-BravePolicyDefinitions`, puis relancer `-SelfTest` avant d'appliquer — plusieurs policies ont un piege de regression documente dans le commentaire qui les entoure (`NetworkPredictionOptions`, `ComponentUpdatesEnabled` en particulier), donc lire le commentaire au-dessus de la ligne avant de changer sa valeur.
</details>

---

<sub>Configure-Brave_Win11 — base sur le registre (policies HKLM uniquement), sauvegarde automatique avant chaque modification, rien d'opt-in applique sans flag explicite.</sub>
