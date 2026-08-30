# KrbEtypeInsight

Predicts which accounts, services and clients a Kerberos encryption type hardening change
will break, before the change is made. Published to the PowerShell Gallery.

## Where the conventions live

General PowerShell conventions — module structure, comment-based help, Pester, PlatyPS,
error handling — come from
[Powershell-Copilot-Standards](https://github.com/fadwen/Powershell-Copilot-Standards) and
are mirrored into this repository by `.github/workflows/sync-copilot-standards.yml`:

- `.github/copilot-instructions.md`
- `.github/instructions/`
- `.github/prompts/`

**Those three paths are mirrored with `rm -rf` + `cp`.** A local edit there is silently
reverted on the next sync. Changes belong upstream in the standards repository.

This file is outside the mirror, so it is the right place for anything specific to this
module. What follows is *not* general convention — it is the set of local invariants that
look wrong or arbitrary until you know why, and that are cheap to break by accident.

## Invariants

### Enums must not appear in `param()` type constraints

`Classes/KrbEtypeEnum.ps1` defines `[KrbTicketEtype]` and `[KrbEtypeFlag]`. Function bodies
reference them freely — a cast like `[KrbEtypeFlag]($effective -band $mask)` is fine — but a
type literal in a parameter attribute is resolved when the file is *parsed*, and a
dot-sourced file cannot see a class defined by a sibling file at that moment.

Keeping the enums out of parameter blocks is the only reason the simple dot-source loader in
the `.psm1` works. Adding `[KrbTicketEtype]$Etype` to a `param()` block breaks module import
for every command, not just that one.

### Load order is deliberate and not alphabetical

`Classes` → `Private` → `Public`. The loader fails the whole import on any error, because a
partially loaded module is worse than no module: functions resolve, calls succeed, and
results are silently wrong because a catalog the decoder depends on was never defined.

### The MAML filename carries a capital H

`en-US/KrbEtypeInsight-Help.xml`, matching every `.EXTERNALHELP KrbEtypeInsight-Help.xml`
keyword in `Public/`. `Export-MamlCommandHelp` produces that name while most documentation
writes `-help.xml`. On Windows the mismatch is invisible; on a case-sensitive filesystem
`Get-Help` silently falls back to a reflected stub and every command loses its help.

The Linux job in `quality-gates.yml` exists to catch exactly this, and `Build-Help.ps1`
asserts the produced name rather than assuming it.

### Help is compiled, and stale help beats correct help

`docs/KrbEtypeInsight/*.md` is the source; `en-US/KrbEtypeInsight-Help.xml` is the artifact.
After editing anything under `docs/`, run `./Build/Build-Help.ps1` and commit the rebuilt
MAML in the same change. CI compares a fresh build against the committed file byte for byte.

`.EXTERNALHELP` means a user is served the stale content rather than falling back to
anything correct, which is why the staleness gate is a hard failure.

### `ActiveDirectory` is deliberately absent from `RequiredModules`

Three of the six public functions never touch the directory, and the decode and correlation
core runs against archived `.evtx` with no domain present — which is how the test suite
exercises it and how an assessment gets done from an analyst's workstation. Declaring the
dependency would make the module unimportable on any machine without RSAT, including the
Linux CI runner, for the benefit of functions that already import it on demand and report a
clear error when it is missing.

### Never `Publish-PSResource -Path .`

This repository *is* the module root, so packaging it directly ships the entire working
tree. Measured: 313 files, 975 KB, including all 213 files of `.git`.

Gallery versions can never be deleted, only unlisted, and the `.nupkg` stays downloadable at
its direct URL afterwards — so that would publish the repository history permanently.

Always publish through `Build/Publish-Module.ps1`, which stages an **allowlist** into a
git-ignored `out/`. A new folder does not ship until it is named in `$shipFiles` or
`$shipFolders`. Result: 46 files, ~507 KB.

`Troubleshooting/` *is* shipped, because comment-based help in `Private/` links into it
relatively and those links resolve against the installed module.

### `$WhatIfPreference` is inherited by child scopes

This caused two separate failures. Preference variables propagate into called cmdlets *and
called scripts*, so under `-WhatIf` they reach things that are not the destructive step:

- Staging cmdlets in `Publish-Module.ps1` are pinned `-WhatIf:$false`, or the rehearsal
  copies nothing and then fails on an empty folder.
- `Build-Help.ps1` is called with `$WhatIfPreference` saved and cleared, or
  `Export-MamlCommandHelp` compiles nothing and the rehearsal stops verifying the very help
  build it exists to verify. It cannot take `-WhatIf:$false` directly — it declares
  `[CmdletBinding()]` without `SupportsShouldProcess`, so the parameter does not exist on it.

Only the publish itself is gated by `ShouldProcess`. When adding a step, decide whether it is
genuinely destructive; if not, pin it.

**Test `-WhatIf` and `-SkipHelpBuild` in combination, not just individually.** Both bugs
above survived testing because each flag was only ever exercised alone. Note also that a
stale local `maml/` masks failures that appear on a fresh checkout, where it is absent.

### Empty manifest URI keys break the pack

`IconUri = ''` is not "no icon" — the nuspec writer emits an empty `<iconUrl>` and NuGet
aborts with `IconUrl cannot be empty`, naming neither the manifest nor the key. Same for
`HelpInfoURI`. Omit the key entirely. `Publish-Module.ps1` checks for this.

`IconUri` is in any case write-only metadata: the Gallery renders the default PowerShell
logo for every package and does not fetch remote icon URLs. Setting one has no visible
effect.

### Releases are tag-driven and the tag must match the manifest

`git tag v<ModuleVersion> && git push origin v<ModuleVersion>` triggers
`.github/workflows/release.yml`, which re-runs the full quality gates, verifies the tag
against `ModuleVersion`, stages, imports the staged tree, and publishes.

A version number is consumed permanently on first publish. Bump `ModuleVersion`, update
`CHANGELOG.md`, and tag — the workflow blocks a tag that disagrees with the manifest, so the
two cannot drift.

The API key is the `PSGALLERY_API_KEY` repository secret, passed as an environment variable
rather than `-ApiKey` to keep it out of the run log and process command line. Locally the
script resolves `-ApiKey` → `$env:PSGALLERY_API_KEY` → a SecretManagement secret named
`PSGallery-ApiKey`.

## Targeting

PowerShell 7.4, `CompatiblePSEditions = Core`. 7.4 is the floor the module actually needs —
it uses nothing introduced in 7.5 or 7.6, so a higher target would only narrow the Gallery
audience. Raise it to the next LTS when 7.4 loses support on 10 November 2026.

## Checks

```powershell
Invoke-Pester ./Tests/Unit              # 403 tests
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error, Warning
./Build/Build-Help.ps1                  # rebuild MAML after editing docs/
./Build/Publish-Module.ps1 -WhatIf      # full release rehearsal, publishes nothing
```

`Tests/Integration` and `Tests/Performance` are not run by CI; unit tests use the
`ActiveDirectory` stub under `Tests/Stubs`.
