# Retired V1/V2 Runtime

The current branch deploys V3 only. Old V1/V2 installers, runtime daemons, web
assets and the legacy build-info stamping workflow have been removed to prevent
new installations from choosing a competing watchdog or obsolete reboot policy.

The complete pre-cleanup source is retained at Git commit `0d7ea74`:
[legacy source snapshot](https://github.com/JW-Arentis-UK/va-connect_watchdog/tree/0d7ea74/tools/ubuntu).
Use an isolated historical checkout for investigation, not the active V3 checkout.

`README.v2.md`, historical documents and tracked `.v2-data` evidence are retained
as archives, not current installation instructions. No site incident archives,
CCTV recordings, user configuration, or local untracked files are deleted.

The old uninstall helpers are also retired: they could delete logs and backups.
Before retiring an installed legacy unit, identify its services and device
ownership, back up its configuration and logs, and verify that V3 owns the required
monitoring/recovery functions. This source cleanup does not automatically stop or
uninstall legacy services on field gateways. Do not run an archived uninstaller
blindly on a current unit.

V3 continues to read old reboot evidence and detect conflicting watchdog daemons.
Removing the retired runtime must not remove those safety and forensic checks.
