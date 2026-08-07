# Neousys WDT_DIO integration

## Reviewed package

- File: `WDT_DIO_202505_v2-4-1-0_Linux (1).zip`
- Neousys release: `2.4.1.0`, dated 24 December 2024
- SHA256: `e78018ea9c45c4bcc6ad5a3a1c42dfe092e126093d267eecacfbe7f1e8d2f658`
- Architecture: x86-64
- POC-451VTC is explicitly present in the vendor release history.

The package provides a GPL-labelled `wdt_dio` kernel module, a binary-only
`libwdt_dio.so`, headers, examples, and prebuilt modules. This test branch includes
the original hash-verified archive at `v3/vendor/neousys/` solely for controlled
POC-451VTC testing. Redistribution or production deployment requires a separate
licence review.

## Why this backend exists

The Intel `iTCO_wdt` driver exposes `/dev/watchdog0` on POC-451VTC, but an
attended trip test showed that its counter remained at 30 seconds when feeding
stopped. It therefore did not reset that gateway.

The Neousys package exposes `/dev/wdt_dio` and uses the vendor API:

- `InitWDT`
- `SetWDT`
- `StartWDT`
- `ResetWDT`
- `StopWDT`

This is a separate hardware path and must be proven by an attended deliberate
trip test before production use.

## Installation

Install without activation first (the bundled archive is selected automatically):

```bash
cd /opt/va-connect-watchdog-v3
sudo ./v3/scripts/install_neousys_wdt.sh
```

The script validates the exact archive hash, verifies POC-451VTC DMI identity,
builds `wdt_dio.ko` for the running kernel, installs the private library, and
checks the five required API symbols. It does not start the hardware watchdog.

Activation is explicit and must be performed during an attended test window:

```bash
sudo ./v3/scripts/install_neousys_wdt.sh --activate
```

Activation backs up the existing configuration, selects the
`neousys_wdt_dio` backend, removes legacy watchdog daemons and Intel TCO hardware
paths, and applies a 15-minute startup safety extension.

## Runtime behaviour

- Normal feeder stop calls `StopWDT` before exiting.
- Main `va-watchdog.service` restarts do not restart the independent feeder.
- A feeder crash cannot call `StopWDT`; the hardware timer should expire.
- A deliberate trip test stops calling `ResetWDT` without closing the backend.
- If no reboot occurs within the configured timeout plus five seconds, feeding
  resumes and the test is recorded as failed.
- The existing single-owner feeder lock remains active.

## Kernel updates

The module is built for the exact running kernel. After a kernel update, rerun
the installer against the same reviewed vendor archive before activating the
new kernel in production. Automated DKMS packaging is intentionally deferred
until the vendor confirms support and redistribution terms.
