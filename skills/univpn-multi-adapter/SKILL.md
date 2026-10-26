---
name: univpn-multi-adapter
description: Adapt the UniVPN-Multi PowerShell project to one exact installed Windows UniVPN build by deriving and verifying a binary-patch profile; not for unrelated VPN setup or bypass work.
---

# UniVPN Multi Adapter

Use this skill when the user supplies an existing `univpn-multi-main` checkout and wants `UniVPN-Multi.ps1` adapted to a particular installed UniVPN build.

The goal is a **new, independently verified binary profile**, not a blanket version check. Never weaken SHA256 validation, guess offsets, patch the original vendor executables, or claim full multi-tunnel compatibility from offline tests alone.

1. Start with `references/porting-workflow.md`. It defines the required evidence, binary-analysis rules, profile changes, build checks, and stopping conditions.
2. Use `scripts/analyze_univpn.py` for a read-only first pass over the three installed EXEs. Treat its output as evidence to review, not as permission to patch automatically.
3. Preserve the project structure: edit `src/PatchEngine.cs` and other source files, then generate the root script with `tools/Build.ps1`.
4. Run the offline suite and `-SelfTest` against the exact installed source directory. Only perform live service/TAP/adapter operations when explicitly requested by the user.
