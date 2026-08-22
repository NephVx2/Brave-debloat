# Configure-Brave_Win11

🇫🇷 [Version française](README_FRENCH.md)

Interactive PowerShell menu that applies a curated set of Brave browser policies via the Windows registry (`HKLM\SOFTWARE\Policies\BraveSoftware\Brave`) — debloating, telemetry, network, and security hardening — with automatic `.reg` backups, a dry-run preview, one-click restore, and an integrity checker. Same architecture as [Block-Telemetry](../Block-Telemetry).

> Every value is justified. Each policy carries a plain-language rationale in the script itself, two known Chromium regression traps are locked in by the self-test (`NetworkPredictionOptions`, `ComponentUpdatesEnabled`), and nothing marked "opt-in" is ever applied unless you explicitly ask for it.

---

## Table of contents

- [Overview](#overview)
- [How it works](#how-it-works)
- [What gets configured](#what-gets-configured)
- [Opt-in only: Lockdown and DNS-over-HTTPS](#opt-in-only-lockdown-and-dns-over-https)
- [Safety guarantees](#safety-guarantees)
- [Prerequisites](#prerequisites)
- [First run](#first-run-step-by-step)
- [Menu reference](#menu-reference)
- [Command-line parameters](#command-line-parameters)
- [Files written by the script](#files-written-by-the-script)
- [Multi-machine deployment](#multi-machine-deployment)
- [Troubleshooting](#troubleshooting)

---

## Overview

`Configure-Brave_Win11_v3.ps1` writes machine-wide Brave policies to the registry — the same mechanism enterprise IT departments use to manage Brave via Group Policy, applied here to a single machine through a controlled, reversible script instead of a domain controller.

It touches **one registry key and its subtree**: `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. It does not modify Brave's user profile settings directly, does not touch any other browser, and does not install or remove anything.

Like `Block-Telemetry`, this is a **menu-driven** tool — applying, updating, and restoring policies are standing configuration changes, not one-off maintenance tasks, so the script keeps a human in the loop rather than exposing a single "just do it" CLI flag.

---

## How it works

1. Every policy this script manages is defined once, in one place (`Get-BravePolicyDefinitions`), each with a `Category`, a `Type` (DWord or String), a `TargetValue`, and a **rationale** explaining why that specific value was chosen — not just "disable this."

2. Before **any** write to the registry, a full `.reg` export of the current policy key is taken (see [Files written by the script](#files-written-by-the-script)).

3. Applying compares each policy's current registry value against its target: already-correct values are left alone, missing or wrong ones are written, and the result is tracked per policy (`Add-Result`) for the CSV/JSON/HTML reports.

4. Restoring re-imports the last backup, returning the registry key to exactly what it was before this script ever touched it.

5. An **integrity check** (menu option `[9]`) re-reads every policy this script is supposed to manage and flags any that drifted from its target — useful after a Brave update, which occasionally resets or ignores specific policies.

---

## What gets configured

**53 policies applied by default**, across 6 categories:

<details>
<summary><strong>Bloat</strong> — 21 policies</summary>

Disables Brave-proprietary features not used in this configuration: Rewards, Wallet, VPN, News, Talk, Speedreader, Wayback Machine, Playlist, Sync, the built-in Tor window, Leo AI. Also closes off underlying Chromium UI/AI surface that Brave doesn't use natively but still ships: promotional tabs and banners, New Tab Page cards and announcement banner, the Web Store promo icon (doesn't block installing extensions), the "Labs" experimental-features button, and Chromium's Gemini integration, "Help me write," and AI tab comparison features.
</details>

<details>
<summary><strong>Telemetrie</strong> — 13 policies</summary>

Brave's own P3A (Privacy-Preserving Product Analytics), the daily stats ping (this does **not** block `laptop-updates.brave.com`, which stays reachable for binary updates — only the ping itself is cut), Web Discovery Project, generic Chromium crash/usage metrics reporting, error-page phone-home to Google, payment-method detection by sites, real-time search-suggestion keystroke sending, feedback/survey prompts, URL-keyed "anonymized" data collection, Safe Browsing extended reporting, WebRTC event log collection to Google, and cloud reporting (a no-op on a non-enrolled personal machine, kept for defense-in-depth consistency).
</details>

<details>
<summary><strong>Reseau</strong> (Network) — 5 policies (7 with DNS-over-HTTPS opted in)</summary>

`NetworkPredictionOptions` set to **2** — this is the one setting in the whole catalog with a documented regression trap: 0 or 1 both mean prediction is *active*, only 2 truly disables DNS prefetch/preconnect. Also: prevents Brave from running in the background after the window is closed, blocks WebRTC from leaking a local/private IP even behind a VPN or proxy, forces the OS DNS resolver instead of Chromium's internal one (kept consistent with a system-wide DNS filter like NextDNS), and disables WPAD proxy auto-detection on every network change.
</details>

<details>
<summary><strong>Securite</strong> (Security) — 8 policies</summary>

`ComponentUpdatesEnabled` is explicitly kept **enabled** — this isn't just the Brave binary, it also covers Widevine, Safe Browsing lists, and the root certificate store, so this policy is never touched. Also: forces HTTPS upgrades when available, configurable Safe Browsing level (see below), blocks external tools from attaching to Brave's remote debugging port, blocks HTTP Basic Auth sent in the clear, prevents automatic NTLM/Kerberos authentication from leaking Windows credentials in private browsing, blocks cross-origin authentication-prompt spoofing, and disables Signed HTTP Exchanges (which can mask a page's real origin).
</details>

<details>
<summary><strong>PrivacySandbox</strong> — 4 policies</summary>

Blocks Chromium's ad-profiling APIs (Topics, the Privacy Sandbox prompt, per-site ad APIs — the first three are marked "Obsolete" in current `brave://policy/` but kept for compatibility with older Brave versions) and the currently-active replacement, Attribution Reporting (cross-site ad measurement).
</details>

<details>
<summary><strong>Performance</strong> — 2 policies</summary>

Enables Memory Saver (High Efficiency Mode) and sets its aggressiveness to **Balanced** rather than Maximum — Maximum was deliberately ruled out as causing too many unexpected tab reloads on a multi-tab workflow with 16GB of RAM available. (0 = Conservative, 1 = Balanced, 2 = Maximum.)
</details>

**Explicitly left untouched:** page translation and spell-check (including the online spell-check service) are used features and are deliberately absent from this script's entire policy list, category, and self-test — not an oversight.

---

## Opt-in only: Lockdown and DNS-over-HTTPS

Two additional categories exist in the script but are **never applied unless you explicitly ask**:

<details>
<summary><strong>Lockdown</strong> — 5 policies, requires <code>-IncludeLockdown</code></summary>

These aren't privacy leaks — they're feature restrictions, meant only for a deliberate hardening choice (e.g. a shared or public-facing machine): disables the built-in password manager, address autofill, and credit card autofill. **Developer Tools access is deliberately left enabled** even under `-IncludeLockdown` (a personal machine needs DevTools), and so is Incognito mode (restricting it only makes sense on a shared machine) — both are enforced by dedicated self-test assertions rather than left to chance.
</details>

<details>
<summary><strong>DNS-over-HTTPS</strong> — 2 policies, requires <code>-DnsOverHttpsTemplate &lt;url&gt;</code></summary>

Forces Brave's own DoH resolver to a specific endpoint you provide. Absent by default specifically so it can't silently bypass a system-wide DNS filter like NextDNS — a dedicated self-test assertion confirms these two policies are entirely absent from the definition list unless the parameter is supplied.
</details>

---

## Safety guarantees

| # | Guarantee |
|---|---|
| S1 | Automatic `.reg` backup before any modification (`reg export`) |
| S2 | Automatic backup rotation (last 10 kept) |
| S3 | Dry-run mode to preview the diff without changing anything |
| S4 | Full built-in restore (single menu choice) |
| S5 | Built-in "Update" option (cleans up residue + re-applies in one step) |
| S6 | Anti-regression guards baked into the self-test (`NetworkPredictionOptions`, `ComponentUpdatesEnabled`) |
| S7 | Conflict detection (HKCU policies, `Recommended` subkey, leftover residue) |
| S8 | Integrity check (defined policies vs. what's actually active in the registry) |
| S9 | DoH and Lockdown stay explicit opt-in — never applied by default |

---

## Prerequisites

- Windows 10 or 11 with Brave Browser installed.
- PowerShell 5.1 (built into Windows) or PowerShell 7+.
- Administrator rights — required because the target is `HKLM` (machine-wide), not `HKCU`. The script self-elevates on launch, except for `-SelfTest` and `-DebugDefs`, which run read-only and do **not** require elevation.
- If the script is digitally signed (recommended in environments using `-ExecutionPolicy AllSigned`/`RemoteSigned`): the signing certificate must be trusted on the target machine.

---

## First run (step by step)

1. Copy `Configure-Brave_Win11_v3.ps1` to the target machine.

2. Open a PowerShell terminal (no need to run it as admin manually — the script self-elevates, except for the read-only checks below).

3. Run the self-test first — read-only, no admin rights required:

   ```powershell
   .\Configure-Brave_Win11_v3.ps1 -SelfTest
   ```

   Runs 19 assertions: policy list integrity (no duplicates, correct value types), the two regression guards (`NetworkPredictionOptions` = 2, `ComponentUpdatesEnabled` = 1), Lockdown/DoH stay absent unless explicitly requested, DevTools stays enabled even under Lockdown, translation/spell-check are confirmed absent from the script entirely, and several internal functions run without throwing. Exit code `0` = all passed, `1` = at least one failure.

4. *(Optional)* Inspect the full policy list without touching the registry:

   ```powershell
   .\Configure-Brave_Win11_v3.ps1 -DebugDefs
   ```

5. Launch the script normally (accept the UAC prompt):

   ```powershell
   .\Configure-Brave_Win11_v3.ps1
   ```

6. From the menu, preview what would change **without writing anything**:

   ```
   [3] Simuler sans modifier (DryRun)
   ```

7. Apply the policies for real:

   ```
   [1] Appliquer les modifications
   ```

   This backs up the current registry state, writes the target values, and records the result for the reports.

8. Restart Brave for the new policies to take effect (Chromium-based browsers read most policies at startup). Confirm in the browser via `brave://policy/`.

9. Check integrity any time afterward with option `[9]` — useful after a Brave update, which occasionally resets specific policies back to their defaults.

10. To undo everything, use option `[4]` (Restore) — re-imports the backup taken before the last change.

---

## Menu reference

| Option | Action |
|---|---|
| `[1]` | Apply the policies for real (backup → compare → write → record results) |
| `[2]` | Update — cleans up residue, then re-applies from scratch in one step |
| `[3]` | Dry-run: preview the diff without writing anything |
| `[4]` | **Restore** the original settings from the last backup |
| `[5]` | List available backups |
| `[6]` | Flush the DNS cache manually |
| `[7]` | Generate an HTML report |
| `[8]` | Check for conflicts (HKCU-level policies overriding HKLM, a `Recommended` subkey present, leftover residue from a previous version) |
| `[9]` | Check integrity — defined policies vs. what's actually active in the registry right now |
| `[10]` | Export the currently active policy list to a `.txt` file |
| `[Q]` | Quit |

---

## Command-line parameters

| Parameter | Description |
|---|---|
| `-SelfTest` | Runs the 19-assertion internal test suite and exits. No admin rights required, registry never touched. |
| `-DebugDefs` | Prints the full numbered policy list (name + category) as currently defined, plus two named-policy presence checks, and exits. No admin rights required, registry never touched. |
| `-Category <name(s)>` | Restrict an action to one or more categories (e.g. `-Category Telemetrie,Reseau`) instead of the full set. |
| `-IncludeLockdown` | Adds the 5 opt-in Lockdown policies to whatever action you run (apply/update/dry-run). See [Opt-in only](#opt-in-only-lockdown-and-dns-over-https). |
| `-SafeBrowsingLevel <Off\|Standard\|Enhanced>` | Sets Brave's Safe Browsing level. Default `Standard` (local lists, no real-time sharing with Google). `Enhanced` gives better detection but sends URLs and page samples to Google continuously. `Off` is available but not recommended. |
| `-DnsOverHttpsTemplate <url>` | Supplying this enables the 2 opt-in DoH policies, pointed at your URL. See [Opt-in only](#opt-in-only-lockdown-and-dns-over-https). |

**Examples:**

```powershell
.\Configure-Brave_Win11_v3.ps1 -SelfTest
.\Configure-Brave_Win11_v3.ps1 -Category Telemetrie,Reseau
.\Configure-Brave_Win11_v3.ps1 -IncludeLockdown
.\Configure-Brave_Win11_v3.ps1 -SafeBrowsingLevel Enhanced
.\Configure-Brave_Win11_v3.ps1 -DnsOverHttpsTemplate "https://dns.nextdns.io/xxxxxx"
```

---

## Files written by the script

| File / folder | Content |
|---|---|
| `%USERPROFILE%\Desktop\Registry_Backups\ConfigBrave\*.reg` | Full `reg export` of the policy key, taken before every real write (rotated automatically, last 10 kept) |
| `%USERPROFILE%\Desktop\Configure-Brave_Log.txt` | Plain-text action log (append-only) |
| `%USERPROFILE%\Desktop\Rapports_Maintenance\ConfigBrave\_dernier_etat.json` | Snapshot of the last applied state, used by the integrity check |
| `%USERPROFILE%\Desktop\Rapports_Maintenance\ConfigBrave\*.csv` / `*.json` / `*.html` | Reports generated via menu option `[7]` |
| Export file *(on demand, menu option `[10]`)* | Plain-text list of the currently active policies |

`-SelfTest` and `-DebugDefs` write **no** files and touch **no** registry keys.

---

## Multi-machine deployment

1. **Distribute** the `.ps1` file to each target machine.

2. **Trust the signing certificate** if a strict execution policy is enforced (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Run `-SelfTest` first** on each machine — no admin rights needed, registry untouched, safe to run before deciding to proceed.

4. Because this is a **menu-driven, standing configuration change** (not a one-off cleanup task), it isn't a drop-in candidate for a silent scheduled task. For unattended multi-machine rollout, the cleanest option is to call `Invoke-BraveAction` directly from your own wrapper script with the parameters you need (`-Category`, `-IncludeLockdown`, etc.) rather than driving the interactive menu.

5. Backups, logs, and reports are written to the profile of the user running the script — local to each machine, not centralized automatically.

6. If your fleet uses Group Policy or an MDM solution that already manages Brave centrally, check for conflicts (menu option `[8]`) before running this script on a domain-managed machine — HKLM policies set here could compete with policies pushed by that system.

---

## Troubleshooting

<details>
<summary><strong>A policy shows as active in the registry but Brave doesn't seem to respect it</strong></summary>

Restart Brave — Chromium-based browsers read most policies at startup, not live. Confirm at `brave://policy/`, which shows every policy Brave currently sees, its source, and its actual applied value.
</details>

<details>
<summary><strong>Integrity check (option [9]) reports drift after a Brave update</strong></summary>

Some Brave updates reset or reintroduce default values for specific policies. Re-run option `[2]` (Update) to clean up and re-apply from the current script's definitions.
</details>

<details>
<summary><strong>Conflict check (option [8]) flags an HKCU policy or a Recommended subkey</strong></summary>

An HKCU-level policy for the same setting, or a `Recommended` subkey under the managed policy path, can override or shadow what this script sets at `HKLM`. Investigate what created it (another tool, a leftover from manual testing, or actual domain/MDM management) before removing it.
</details>

<details>
<summary><strong>-SelfTest reports a FAIL</strong></summary>

All 19 assertions are internal consistency checks on the policy definitions and helper functions — a FAIL points to a specific broken invariant (e.g. `NetworkPredictionOptions` no longer targeting 2, a duplicate policy name, Lockdown policies present without `-IncludeLockdown`). Read the failing assertion's name for the specific issue.
</details>

<details>
<summary><strong>I want to change the target value for one specific policy</strong></summary>

Edit its `New-Policy` line inside `Get-BravePolicyDefinitions` directly, then re-run `-SelfTest` before applying — several policies have a documented regression trap in their surrounding comment (`NetworkPredictionOptions`, `ComponentUpdatesEnabled` in particular), so read the comment above the line before changing its value.
</details>

---

<sub>Configure-Brave_Win11 — registry-based (HKLM policies only), automatic backup before every change, nothing opt-in applied without an explicit flag.</sub>
