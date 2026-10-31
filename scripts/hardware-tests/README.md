# Hardware tests

Qualifies HkdfGuard on a machine other than the development box - a laptop
with a different TPM, a Hyper-V guest with a virtual TPM - and produces the
evidence behind the "tested" entries in the README's Testing and
compatibility section and SecurityAssumptions.md sections 12 and 17.

CI and `scripts\Test-Containers.ps1` run without a TPM, so they cover the
Software Key Storage Provider only. These scripts are how the TPM path gets
tested on a given TPM.

## Steps

1. On the development machine, build in Release and make the bundle:

   ```powershell
   cmake --build build-ninja
   scripts\hardware-tests\New-HardwareTestBundle.ps1          # -OutDir <folder> to put it elsewhere
   ```

   The bundle is `build-hardware-tests\bundle` by default: the DLL, the CLI,
   the test programs and scripts, `v2_provider_probe.exe`, and the runner.
   Everything links the C/C++ runtime statically, so the target needs nothing
   installed.

2. Copy the bundle folder to the target.

3. On the target, from an **elevated PowerShell at its own console**:

   ```powershell
   powershell -ExecutionPolicy Bypass -File <bundle>\Run-HardwareTests.ps1
   ```

   Not over PowerShell remoting or PowerShell Direct: there is no desktop
   there, so the processes `test_roles.ps1` starts as its test accounts die
   before they run, and `roles` fails for that reason alone. The runner warns
   when it sees a remote session. Copying files in and out over PowerShell
   Direct (`Copy-Item -ToSession` / `-FromSession`) is fine.

4. Bring back `hardware-tests-<COMPUTERNAME>.log` from the bundle folder.

For Hyper-V guests, `Enable-HyperVTpm.ps1` (on the host, elevated) enables a
vTPM on Generation 2 VMs and takes a checkpoint to roll back to afterwards.

## What counts as a pass

- Every suite in the summary says `passed`. (`harden_process` may say
  `skipped (SYSTEM)` only when run as SYSTEM.)
- **No `[SKIP]` line about the TPM or the PCP.** A TPM skip means the TPM path
  never ran, so the TPM is not qualified, whatever the summary says. The
  runner lists every `[SKIP]` line at the end.
- `provider_probe` ran its machine-scope section (it needs elevation) and the
  unelevated copy's checks passed.

`[INFO]` lines in the probe's output report provider behavior the library works
around either way - for example, whether the PCP writes a short output buffer.
They are not failures, but a value different from earlier TPMs is worth noting
in SecurityAssumptions.md section 17.

A `[WARN] could not remove C:\HkdfGuardRoleTest-...` line from `roles` is a
known cleanup quirk; delete the folder by hand.

## What to record

From the top of the log:

| Item | Where in the log |
|---|---|
| Windows edition and build with UBR | `== Host:` line |
| TPM manufacturer | `ManufacturerIdTxt` (`AMD`, `INTC` and `MSFT` are firmware or virtual TPMs; `IFX`, `NTC`, `STM`, `ATML` are discrete chips) |
| TPM firmware version | `ManufacturerVersion` |
| TPM spec version and revision | `tpmtool`: `TPM Version`, `TPM Spec Version` |
| Firmware advisories | `tpmtool`: `TPM Has Vulnerable Firmware` |
| The date | the transcript's `Start time` |

Then fold the result into the README's Testing and compatibility section,
SecurityAssumptions.md section 12 (other TPMs) and the "Verified how" list in
section 17, and docs/adr/0001-post-quantum-payload-version-2.md's follow-up -
saying whether the provider probe ran, and any new `[INFO]` behavior. The
logs themselves are not committed.

## The provider probe

`tests/v2_provider_probe.cpp` checks what version 2 relies on from Windows
itself, through NCrypt directly and without HkdfGuard.dll, so a provider or
TPM that behaves differently is caught at its source:

- **Software KSP**: an `SP800_108_CTR_HMAC` key is persisted non-exportable,
  reopened and used; its derivation equals HMAC-SHA-256 over the SP 800-108
  block built by hand, for service names of 0 to 128 bytes and for the
  fingerprint.
- **Platform Crypto Provider**: an `HMAC-SHA256` key with the SIGNATURE usage
  is persisted, reports hardware backing and no export; its output is 32
  bytes, deterministic and keyed for inputs of 1 to 1,024 bytes, and 1,025 is
  refused.
- **Machine scope** (elevated): both keys are created as machine keys with the
  library's ACL shape, and a copy of the probe running with the token
  restricted as an unelevated administrator's is can use them, but is refused
  export, making them exportable, widening their DACL and deleting them.

Every key it makes is a throwaway, deleted before it exits. It can be run on
its own, elevated or not.
