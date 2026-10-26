# UniVPN-Multi build porting workflow

## Scope and safety

- This workflow supports adding a profile for **one byte-identical installed build**. A version string alone is not evidence.
- Require these exact original files:
  - `UniVPN.exe`
  - `promote\UniVPNPromoteService.exe`
  - `serviceclient\UniVPNCS.exe`
- Record all three SHA256 values before editing. Keep rejecting unknown hashes.
- Do not modify the original vendor EXEs. The project patches in-memory copies and writes only generated instance files.
- Do not create services, TAP adapters, or client instances while deriving the profile. Read-only `-SelfTest` is the maximum live-system operation unless the user explicitly asks for a real instance.
- Offline success does not establish VPN login, routing, DNS, or multi-tunnel business connectivity.

## Read-only analysis

Run the bundled analyzer from this skill:

```bash
python3 /path/to/univpn-multi-adapter/scripts/analyze_univpn.py \
  '/mnt/c/Program Files (x86)/UniVPN' --markdown
```

It reports PE architecture, sections, hashes, executable occurrences of known RPC/backend ports, useful string addresses, direct code references, `.rdata` padding, and candidate intermediate hashes. Review the bytes and control-flow context; do not select an offset merely because a numeric value occurs once.

Also record the Windows version resource:

```powershell
Get-Item 'C:\Program Files (x86)\UniVPN\UniVPN.exe' |
  Select-Object Length,@{n='Version';e={$_.VersionInfo.FileVersion}}
```

If the user provides an installer, expand it into a disposable directory and compare its files with the installed files. Same-version installers and installed files can differ; the profile must target the files the script will actually read.

## Patch invariants

The existing project changes generated copies in four areas:

1. **Product identity**
   - ASCII and UTF-16 forms of `UniVPN` / `Univpn` are replaced with equal-length six-character names.
   - `Global\SVN` becomes an instance-specific global mutex prefix.
2. **Ports**
   - `UniVPN.exe` and `UniVPNPromoteService.exe` use RPC port `29190`.
   - `UniVPNCS.exe` uses backend port `19060`.
   - Find the actual instruction immediate in executable code. The candidate must make sense in its function and normally be unique.
3. **TAP selection**
   - `UniVPN.exe` and `UniVPNCS.exe` contain adapter registry checks based on `ComponentId` and `tap0901`.
   - Replace the relevant `ComponentId` value-name references with `NetCfgInstanceID`.
   - Replace the relevant fixed `tap0901` comparisons with the generated GUID payload: uppercase GUID NUL lowercase GUID NUL.
   - Preserve unrelated driver/service checks. More occurrences of `tap0901` do not mean every occurrence should be changed.
4. **PE payload**
   - Write the GUID strings only into confirmed zero padding at the end of `.rdata`.
   - Increase `.rdata` virtual size by the payload length.
   - Convert every generated pointer through VA/RVA/section mapping; never reuse an old build's address because its version number looks similar.

## Identifying adapter references

- `UniVPN.exe` is normally 32-bit. Relevant references are typically `mov dword ptr [esp...]` instructions with absolute string-address immediates.
- `UniVPNCS.exe` is normally x64. Relevant references are typically `lea rdx, [rip+disp32]`.
- Group references by surrounding function and purpose:
  - three `ComponentId` comparisons should normally map to the selected `NetCfgInstanceID` string;
  - three per-adapter `tap0901` comparisons map to upper/lower GUID strings;
  - ignore separate driver-type checks and references that already read `NetCfgInstanceID`.
- If grouping is ambiguous, compiler patterns changed materially, or there are not enough confirmed references, stop and report that this build needs manual reverse engineering. Do not guess.

## Add a profile to `src/PatchEngine.cs`

Keep the existing supported profile(s) and add an independent profile containing:

- the three exact source hashes;
- the three file offsets for the port immediates;
- the three intermediate hashes after only identity replacement and port `+1`;
- every adapter instruction VA, expected old string VA, and new target VA;
- architecture-specific pointer validation.

A maintainable implementation selects the profile by source hash before applying any mutation. Do not put offsets into a shared array keyed only by version.

Compute intermediate hashes with the exact same byte replacements as the C# implementation. A mismatch means either the source file, replacement behavior, or chosen port offset is wrong.

## Build and verification

From the repository root on Windows/WSL:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\RunTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\UniVPN-Multi.ps1 `
  -SelfTest -SourceDirectory 'C:\Program Files (x86)\UniVPN'
```

Then inspect generated in-memory/temporary copies without starting them:

- PE parsing succeeds and file length is unchanged except intended metadata/section-size bytes;
- all expected product-name replacements occurred;
- `UniVPN` no longer occurs in generated names where the old implementation replaced it;
- port immediates are `29190 + N - 1` or `19060 + N - 1`;
- each changed adapter pointer resolves to `NetCfgInstanceID` or the expected upper/lower GUID;
- unchanged original files still have their recorded hashes.

Run `tools\Build.ps1 -Check` as the final reproducibility check. If deployment is requested, copy the generated root `UniVPN-Multi.ps1` to the official installation directory using an elevated Windows copy, then rerun `-SelfTest` from that installed path.

## Required reporting

Tell the user:

- the exact version and three source hashes accepted;
- which files changed;
- which tests passed;
- that no service, adapter, or client instance was created unless one explicitly was;
- that actual creation/login/multi-tunnel behavior still requires live verification.
