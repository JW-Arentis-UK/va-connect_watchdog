# Ellingers gateway recovery test plan

## Incident and current limits

The September 30 support bundle captured a final healthy gateway heartbeat at
2026-09-25 17:40:06 UTC and a final blackbox sample at 17:40:09 UTC. The
Neousys feeder last recorded a successful feed at 17:40:04 UTC with no error.
The operator reported that the RUT remained reachable while forwarding to the
gateway watchdog failed. The operator then cycled the relay, and the gateway
booted on September 30 at approximately 11:08 UTC. The bundle classifies the
preceding shutdown as Unknown. It does not prove whether the PC was powered
and frozen, had lost only its own power, or had lost its network path.

The hardware feeder uses a 5-second heartbeat, a 15-second stale-heartbeat
limit, a 90-second health-progress limit, a 10-second feed interval, and a
30-second hardware timeout. Startup grace feeds the device without stale
enforcement for 300 seconds. `va-watchdog.service` has a separate 30-second
systemd watchdog. A healthy core loop can coexist with a failed HTTP thread;
the new `va-watchdog-web.service` supervises HTTP separately. Normal feeder
service shutdown calls the vendor `StopWDT`; this policy is unchanged until
its hardware behavior is measured on the gateway.

## Function-by-function failure path

| Component | Live contract | What it can and cannot recover |
| --- | --- | --- |
| `watchdog.py` | Health loop sends `WATCHDOG=1` to systemd after each completed pass. | Systemd can restart a stalled core process. Before this change, it did not detect a failed HTTP thread. |
| `heartbeat.py` | Separate thread publishes process heartbeat every 5 seconds and the last completed health sample. | The feeder can detect a stale heartbeat or a health loop that stops advancing. A fresh heartbeat alone does not prove that HTTP or the recording application works. |
| `watchdog_feed.py` | Independent process checks heartbeat age, health progress, boot ID, and grace before each vendor feed. | It stops feeding on stale liveness. Ordinary service, storage, and network warnings do not trigger a PC reset. |
| `neousys_watchdog.py` | Vendor `ResetWDT` feeds a 30-second timer; `StopWDT` disarms it on an orderly feeder stop. | Deliberate tests on September 15 proved reset on those test paths, but the September 25 failure path remains unproven. |
| `web_service.py` | A local HTTP response is required before systemd readiness and on subsequent probes. | Three failed probes exit for a web-only restart; a stalled web process also misses systemd watchdog notifications. |
| RUT forwarding | Remote access depends on the RUT, gateway LAN, and web server. | Failure of the forwarded page alone does not prove that the PC is frozen. RUT-side local LAN probes and PC power evidence are needed. |

## Before deployment

1. Arrange an attended window with a working relay fallback and a second path
   to reach the RUT. Confirm that power cycling the PC does not cycle the RUT.
2. Record the installed commit, active configuration, unit states, boot ID,
   current feeder state, and recent support bundle. Keep the relay event log.
   The following commands capture the local baseline:

   ```bash
   cat /proc/sys/kernel/random/boot_id
   systemctl show va-watchdog va-watchdog-feed va-watchdog-web -p ActiveState -p MainPID -p NRestarts -p WatchdogUSec
   curl --max-time 3 -fsS http://127.0.0.1:9110/api/healthz
   cat /var/lib/va-watchdog/hardware-watchdog-feed.json
   ```
3. Confirm the target is the POC-451VTC with `/dev/wdt_dio`, that the feeder
   owns the device, and that its `last_feed_utc` advances every 10 seconds.
4. Deploy the new code and units. Confirm that `va-watchdog`,
   `va-watchdog-feed`, and `va-watchdog-web` are active. Check the local
   `/api/healthz` endpoint, the RUT forwarding path, and the normal UI.
5. Check that the web and feeder journals are included in a fresh support
   bundle. A web-only restart must not restart the core or feeder.
6. Open Evidence > Previous-boot black-box evidence. Confirm the September 25
   preserved window ends at 17:40:09 UTC and that its full JSON download has
   the previous boot ID. Compare `/api/blackbox`: its live samples must have
   only the current boot ID, even while old rolling segments remain on disk.

## Non-disruptive web isolation tests

1. Record the boot ID, core PID, feeder PID and feed count. Stop only
   `va-watchdog-web.service`. The core heartbeat and hardware feed must keep
   advancing. Start the web unit and confirm local HTTP and RUT forwarding.
2. Kill only the web unit's main process with
   `sudo systemctl kill --signal=SIGKILL --kill-whom=main va-watchdog-web.service`.
   Verify systemd restarts the web unit, the boot ID stays the same, and the
   core heartbeat and hardware feed continue. The local three-probe failure
   path is covered by the automated `test_web_service.py` test; exercise a
   deliberately stalled HTTP handler separately in staging before using that
   fault injection on the gateway.
3. Block only the remote forwarding path. Local `/api/healthz` must continue
   responding and must not reset the PC. This separates a RUT or forwarding
   fault from a gateway process failure.

## Attended hardware recovery tests

1. After the startup grace ends, run the existing deliberate hardware trip
   test. Confirm a new boot ID within the measured hardware timeout, and
   inspect the post-boot reboot evidence and feeder lifecycle. Do not treat
   `proven_this_boot` alone as proof of an actual reset.
2. Run the existing full liveness-path test, which stops the core while the
   feeder remains active. Confirm the feeder records `main heartbeat stale`,
   stops feeding, and the PC boots into a new boot ID. The test's same-boot
   fallback must be recorded as a failure, not a pass.
3. With local console and relay recovery available, test a controlled
   kernel or process stall that leaves PC power on. Record whether the
   hardware timer resets the machine. If it does not, investigate the Neousys
   driver, BIOS settings, device ownership, and vendor watchdog behavior
   before relying on a 30-second recovery target.
4. Separately test feeder SIGTERM, crash, service restart, and normal OS
   shutdown. Determine exactly when `StopWDT` disarms the timer and whether a
   service stop can leave a running gateway unprotected. Do not change the
   stop policy based on a software mock alone.

After each induced failure, collect the three unit journals, the feeder
lifecycle file, and the RUT relay log:

```bash
journalctl -u va-watchdog -u va-watchdog-feed -u va-watchdog-web -b --no-pager
```

Record the old and new boot IDs and elapsed seconds.
On the new boot, open the Evidence page and verify that the preceding boot's
black-box archive is listed with its first and last sample times. Download
the archived samples and confirm the last sequence and boot ID match the
incident manifest. The last sample may precede the reboot by more than the
15-minute retained window if the recorder had already stopped.
The trip and liveness tests pass only if the boot ID changes without relay
action. If the web-only test changes the boot ID or stops feeder progress,
isolation has failed.

## Independent fallback and acceptance

Use the RUT or another powered controller to probe the gateway over the local
LAN, including the watchdog HTTP endpoint and a second gateway service. Log
probe failures and relay actions outside the PC. Cycle only PC power after a
sustained local failure, with a cooldown and retry limit. Do not trigger the
relay from remote Internet or LTE loss alone.

The recovery path passes only when each induced failure has a recorded cause,
the expected component restarts, the gateway or web endpoint returns without
manual relay action, and a fresh support bundle contains the relevant service
and feeder evidence. If the PC remains unresponsive, use the attended relay
fallback and preserve its event time before further changes.
