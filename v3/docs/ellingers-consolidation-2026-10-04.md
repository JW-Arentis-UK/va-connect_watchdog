# Ellingers consolidation — deployed 4 October 2026

V3 is now the single application/network recovery owner. The hardware feeder and
web service remain independent. Other review recommendations are deferred.

## Active and retired services

Active: `va-watchdog.service`, `va-watchdog-feed.service`, `va-watchdog-web.service`.
Videosoft's `esg`, `sysops` and `bridge` remain running.

Stopped, disabled and masked: `va-connect-site-watchdog.service`,
`va-connect-watchdog-web.service`, `va-connect-watchdog.timer`,
`va-connect-watchdog.service`. Masking prevents normal starts, including after boot.
The legacy website on port 80 is retired; V3 remains on port 9110, including `/lite`.

Legacy files, logs, snapshots and incident records are retained. No purge, history
compression, retention-policy change or wholesale collector redesign was applied.

## Migrated policy

| Concern | Behaviour |
|---|---|
| Application | Explicit `vsapp` process check, as in the old monitor |
| Required services | `esg.service`, `sysops.service`, `bridge.service` |
| LAN | TCP connection to `192.168.1.1:80` |
| Internet | `1.1.1.1` and `8.8.8.8`; either responding is sufficient |
| Application recovery | Queue `esg.service` restart; three attempts per fault episode |
| Network recovery | On loss of both internet targets, queue NetworkManager restart; fall back to systemd-networkd if the command is rejected |
| Settle interval | Require fresh checks collected at least 20s after an action |
| Network restart cooldown | 600s, persisted across monitor restarts |
| Reboot | Persistent application/service/LAN/WAN fault for 300s; double delay after repeated unsuccessful recovery boots, maximum 3,600s |
| Healthy recovery | Reset failure count and app retry budget |
| Startup protection | 60s before software actions; healthy monitoring available immediately |

This preserves the legacy trigger scope. It does not newly reboot the host for
every warning or CPU/storage threshold. The old monitor restarted the app when
the process was absent; other persistent service failures escalated to reboot.
The consolidated policy retains that distinction. It adds bounded app retries,
persistent action state, explicit ownership checks and fresh-observation gates.

Actions are dispatched without blocking the monitoring loop on a full systemd
restart. “Queued” is not treated as recovered: fresh observations establish the
result. One failed internet target is an advisory, not a reboot condition.

The new policy is selected by `recovery.consolidated_policy.enabled`. While selected,
`RecoveryEngine` dispatches only to that policy. The original general critical-check
recovery branch remains available for other installations and is not also run.

Before any action V3 checks that the old monitor is inactive. It blocks actions
if ownership cannot be established. Required observations must be present and no
older than 90s. Unknown service/process results pause recovery and reset the fault
timer, rather than escalating stale evidence. This gate is specific to recovery;
the broader collector-cache freshness improvement is still deferred.

## Persistent state and reboot attribution

Recovery state: `/var/lib/va-watchdog/recovery/state.json`. Boot ID, backoff,
attempt counts, cooldown and pending reboot state survive main-process restarts.
New boot resets in-flight state; backoff carries over until a healthy observation.

Before requesting shutdown, V3 atomically saves and fsyncs the cause, boot ID,
failed-check summary and timestamp to `last-reboot-reason.json`. A known failed
command restores the previous attribution and waits before retrying. Repeated
loops cannot issue another accepted reboot command for the same boot. Boot
classification rejects consolidated reasons for a different preceding boot ID.

Network-triggered restarts retain the dashboard label:
**Watchdog reboot — no network access**. Application/service failures get their
own cause. The lite page now identifies V3 as recovery owner.

## Validation and deployment

67 targeted tests passed across consolidated recovery/collector contracts (14),
existing events/retention/recovery (11), network reboot attribution (7), forensic
evidence (28), and lite view (7). The tests simulate recovery commands and time;
they do not reboot the host or deliberately break connectivity.

Live preflight used staged collectors with all recovery commands blocked. It
confirmed the process, required services, LAN and internet were healthy. It found
that the raw V3 service list needed an explicit `sysops.service` entry, which was
added to the migrated configuration.

During cutover the hardware timer was disarmed by an orderly feeder stop. V3 was
loaded and its fresh idle recovery result verified before retiring the legacy
units. The feeder was restarted; subsequent status confirmed feeding with zero
errors. The boot ID stayed `1d0d707a-04be-420d-a021-6233dbfab48b`.

No live network interruption, host reboot or destructive trip test was performed.
Therefore command policy is regression-tested and live normal operation is
verified, while end-to-end recovery under a real outage remains untested here.

## Backup and rollback

Root-only backup: `/var/backups/va-watchdog/consolidation-20261004/`.
Contains original Python modules, original configuration, legacy state, staged
files/configuration, retired unit files, and `deployment.json`.

Rollback order for an administrator: orderly-stop the hardware feeder; stop V3
main; restore original configuration and Python modules; unmask legacy units and
restore the retired unit files under `/etc/systemd/system`; daemon-reload; restart
V3 main/web with the original recovery-disabled configuration; enable/start the
two former legacy services; restart and verify the hardware feeder. Leave the
old timer disabled, as it was before migration. Do not enable competing recovery
policies during rollback. No rollback is currently required.

The earlier monitoring review describes the pre-consolidation state. This note
records the completed change; its other recommendations remain pending.
