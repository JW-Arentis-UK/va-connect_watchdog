# Watchdog Implementation And Reassessment

Candidate build: `20261027.4`. Build `20261027.1` was installed on the local
POC-551VTC test gateway on 27 October. Its live reassessment found that the full
support bundle omitted syslog, despite the compact bundle including it. Build .2
shares the bounded syslog collector between both formats and retains the compact
download URL on full dashboards. The live browser also exposed a permission error
when recording history scanned an optional private-home fallback as the new web
account. Build .2 reports unreadable paths without losing accessible recording
history or the dashboard. Build .3 collects recording timestamps in a bounded core
worker and shares the saved, freshness-checked result with the read-only dashboard;
the web account does not need access to private footage directories. Deployment
checks are recorded below.

Build .4 follow-up closes a cross-boot status gap: core snapshots now carry an
explicit boot ID, and readiness, the public status API, and the dashboard reject
saved observations from a different or unidentified boot when the running boot
identity is available. Earlier .3 snapshots remain compatible through their
embedded heartbeat boot ID. Original evidence on disk is not rewritten.
The gateway hardware card uses current core feed/proof evidence rather than an
independent saved feeder file. Pi native watchdog observations retain their
systemd-specific interpretation. Black Box health also requires current-boot
samples and no reported recorder write error. An unreadable syslog directory is
recorded as omitted evidence instead of aborting the whole download.

## Implemented Changes

| Review issue | Result |
|---|---|
| Network or general health faults can reboot the gateway | Both previous recovery policies now use one engine that only queues configured service restarts. Legacy `allow_reboot: true` is overridden. NetworkManager/systemd-networkd restarts and software reboot escalation are removed. Manual reboot and attended hardware tests remain. |
| Failed service recovery can loop | Restarts require a fresh failed/inactive service observation, explicit service permission, cooldown, and a persisted attempt limit. A service must stay healthy before its attempts reset. Legacy ownership conflicts block migrated service recovery. |
| A blocked check stalls the core | Hardware, storage, service, network, router, process, display, service recovery, kernel evidence, and retention work run in bounded daemon workers. Each collector has one worker; missed deadlines produce unavailable results without spawning replacement threads. The main loop and independent feeder continue. |
| Root web listener and unguarded actions | The installed web service runs as `va-watchdog-web`. Operator authentication is checked through a short-lived root helper. Only enumerated action routes are accepted; request bodies and headers are bounded. Cross-site browser actions are rejected. Config/state directories retain group readability without granting web permission to forge heartbeat or feeder files. |
| Separate HTTP action implementations | The lightweight entry point is now an adapter to the same protected HTTP server. Lightweight rendering and evidence helpers remain for existing Pi installations. |
| Ambiguous health endpoint | `/api/healthz` remains the web liveness interface and reports readiness separately. `/api/livez` reports web responsiveness. `/api/readyz` returns 503 unless a fresh core status is healthy. The web supervisor now rejects an explicit `ok: false`. |
| Duplicate recording usage checks | The recording storage check is authoritative; the parallel legacy used-percentage check is removed. The two setup choices remain: prepare a new disk, or monitor an existing location. |
| Read pages can repeat storage writes | Read-only storage pages use the saved core result and expose its staleness. They cannot run a write probe as the web account. |
| Black Box write failures can grow memory | Pending samples are limited to the configured rolling window. Dropped pending samples are reported. Segment and state renames include directory fsync where supported. |
| Previous feeder state can look current | Protection proof and feed status must match the current boot when its identity is known. |
| Large mixed UI source | The dashboard shell is a separate HTML asset. Unused hidden refresh controls are removed. Existing operator pages and URL aliases remain available. |
| Stale release test | The test validates the build-number contract instead of a superseded hard-coded release. |

## Operator Access And Compatibility

The status page and saved status/liveness APIs remain available without operator
login. Other remote diagnostics and every administrative POST require the configured
gateway operator account, default `vsuser`. The `Operator sign-in` link invokes the
browser's authentication prompt. Credentials are verified against the existing local
account and are not stored in configuration or passed on command lines.

Local loopback read-only diagnostics remain available for commissioning and update
smoke checks. Loopback does not bypass authentication for administrative actions.
Camera HTTP delivery has a separate bounded receiver policy and cannot invoke
operator actions; it is restricted to the configured camera and event transport.

Forwarded browsers must preserve the external Host and Origin consistently. The
software does not trust arbitrary forwarded-host headers. Command-line action
clients must authenticate and include `X-VA-Watchdog-Action: 1` when they have no
browser Origin or Referer. Existing `/api/settings`, `/api/update`, and `/api/purge`
actions retain their routes and query parameters behind this boundary.

The existing HTTP listener does not encrypt credentials. Remote operator use must
be through a trusted encrypted path such as VPN or HTTPS forwarding. Native TLS and
external identity integration are not part of this candidate.

Run the complete current installer/updater when deploying. Copying just Python
files is insufficient: the service account, groups, sudo rule, root-owned helper,
and directory permissions are required together. The root core no longer starts a
web listener when the separate web unit is absent.

## Verification

Final full suites: 373 tests on Windows/Python 3.13 (10 skipped), and 373 on
Ubuntu/Python 3.14 (9 skipped). Both completed successfully. Bash syntax checks
passed for installation, update, and web-access setup. `git diff --check` passed.

The automated suite covers the changed recovery rules, collector isolation, HTTP
authentication and cross-site rejection, action dispatch and query compatibility,
readiness, previous-boot feed proof, and bounded evidence buffering. Linux tests
also exercise password verification with libcrypt without Python's removed crypt
and spwd modules. Installation shell syntax and whitespace checks are included.

Hardware reset behavior, root helper installation under systemd, router forwarding,
and recording under prolonged real disk pressure require the attended test below.
Passing unit tests does not establish those results.

## Attended Gateway Acceptance

1. Install the candidate on the local recording test gateway using the complete
   installer. Check the web process runs as `va-watchdog-web`, all three watchdog
   units start, and the page still opens through the actual forwarding path.
2. Sign in with the local operator account. Confirm anonymous and cross-site
   administrative requests fail, and authenticated operator changes work. Check
   newly saved config and state remain readable after helper execution.
3. Verify the drive is mounted, old footage remains, and camera recordings continue
   while the page and evidence downloads are used.
4. Block external connectivity on the test gateway for longer than the former reboot
   threshold. Expect network warnings, continuing local recording, and no software
   reboot or network-manager restart. Restore connectivity and check recovery.
5. Inject a collector that blocks past its deadline. Expect an unavailable check,
   continuing supervisor progress, and uninterrupted hardware feed. Confirm the
   worker/thread count remains bounded.
6. Stop one explicitly permitted application service. Expect bounded service restart
   attempts with cooldown; verify missing, stale, or unknown checks cannot act.
7. Run the attended full liveness and hardware trip procedures. Confirm an actual
   reset, same-boot protection proof, and matching previous-boot attribution after
   startup. Keep KVM access available and verify recording resumes.
8. Reboot normally and verify automatic remount, camera recording, web operator
   access, and all services. Then perform an agreed power-cut test to verify
   preserved pre-crash samples and explicitly quantify the final checkpoint gap.

## Reassessment

### Local Gateway Checks

Build .1 installation completed with all three watchdog services and Videosoft
active. The web unit runs as `va-watchdog-web`; the installed helper rejected an
invalid operator password. Anonymous administrative POSTs returned an authentication
challenge. The web account could not write the heartbeat state. Health and readiness
both reported healthy, with all saved checks healthy. Hardware proof recorded
successful consecutive feeds on the current boot, with no feed errors.

The existing ext4 `/recordings` mount and camera configuration were preserved;
new recording files were present during testing. The full support ZIP passed its
integrity check and contained current and archived black-box and feeder evidence.
Its missing syslog collection prompted build .2 rather than treating that download
as complete. A rollback archive is retained on the gateway.

Build .2 was then installed through the updater, which passed its setup smoke
check. Both support formats passed ZIP integrity checks. The full bundle contained
the bounded current syslog tail, syslog.1, and compressed rotations .2 through .4;
its syslog manifest had no omitted or missing files. The dashboard data endpoint
and actual Firefox page recovered. Its recording-history permissions limitation
prompted build .3's core-owned timestamp collector rather than broadening web
access to private footage.

Build .3 (software commit `d50a146`) was installed through the updater and passed
its setup smoke check. All six live dashboard cards were healthy, including
recording history, before a normal test reboot at approximately 12:37 UTC.
After reboot, the public status APIs confirmed build .3, a fresh healthy core,
all four monitored application services running, and the expected ext4 recording
drive mounted read-write. Old footage remained visible and new timestamps advanced
from 12:38:09 to 12:40:09. The before-crash buffer resumed with two-second samples,
no missed deadlines, no dropped pending samples, and no recorder errors.

The new boot identity was `c2df67e8-1f8b-42e4-b3c9-b8caf4e2c319`. Hardware proof
matched that boot and consecutive feeds completed with no errors. The normal
300-second startup safety window was preserved, not bypassed for the test.
At 12:43 UTC the safety window had ended, the feeder reported that the main
process and health loop were fresh, and hardware feeding continued with zero
errors. New recording timestamps had advanced to 12:42:09. This verifies normal
post-boot enforcement startup, not a deliberate hardware trip or power-cut test.
Remote readiness returned HTTP 200; anonymous settings POSTs, invalid operator
credentials, and unauthenticated evidence downloads returned HTTP 401.

The USB-powered KVM also restarted and required its admin login again. Read-only
API access remained available and was used for the post-reboot checks. A successful
operator sign-in/settings change still needs the user's existing local account;
the password was neither requested in chat nor changed for testing.

Successful operator sign-in, an authenticated settings change, forwarded browser
access, prolonged network-loss/blocked-I/O testing, a new hardware trip, and power-cut
retention testing have not yet been established by these deployment checks.

The core responsibilities are now clearer: supervise liveness, observe faults,
retain evidence, and perform only bounded service recovery. Existing configuration
cannot re-enable software reboots for WAN/LAN or health faults. The persistent
pre-crash ring and independent hardware feeder remain essential.

This candidate still retains the large compatibility renderer and optional camera
analytics. Removing those pages outright would remove existing functions; subsequent
extraction should be guided by deployed usage and forwarded-browser testing.
The privileged helper temporarily reuses the existing validated action handlers;
it is a narrower process boundary, not a claim that every setup operation has
already been rewritten as an independent command module.

### Remaining Work After Build .4

| Item | Status |
|---|---|
| Cross-boot readiness, status and dashboard claims | Corrected in .4; regression coverage includes current, previous, missing and unavailable boot IDs. |
| Black Box write-error reporting on the main page | Corrected in .4; a fresh in-memory sample cannot hide a reported persistence error. |
| Unreadable system-log directory | Corrected in .4; omissions are listed in the support manifest. |
| .4 installation on POC-551VTC | Completed after KVM access was restored. Updater finished software commit `83458ff`; all three watchdog services and Videosoft are active. |
| Operator sign-in and authenticated settings round trip | Pending the existing local operator account; no bypass or replacement password is introduced. |
| Actual router/HTTPS forwarding | Pending testing through that deployed path; plain HTTP does not encrypt operator credentials. |
| Network-loss and blocked-collector acceptance | Automated policy/isolation coverage exists; sustained live fault injection is still outstanding. |
| Bounded application-service recovery | Automated recovery coverage exists; attended live stop/restart verification is still outstanding. |
| Hardware trip and forced-power-loss preservation | Not performed in this follow-up. Require attended access and recovery capability. |
| Large compatibility renderer and optional camera analytics | Retained to avoid removing deployed functions. Further extraction is optional maintenance, not an incident fix. |

### Build .4 Deployment Verification

On 27 October at approximately 13:53 UTC, the complete updater installed build
`20261027.4` / software commit `83458ff` on POC-551VTC and passed its setup HTTP
smoke check. The 12 new boot-freshness regression tests also passed using the
gateway's own deployed Python runtime. These tests use temporary fixtures; they
do not replace or falsify the gateway's live evidence files.

Live health, status and dashboard responses agreed: ready, fresh, same-boot and
healthy. All six dashboard cards were healthy. The recording drive remained
mounted, footage timestamps advanced past the update, and Black Box recording
reported its full 450-sample window without errors. Hardware feeding continued
with current-boot proof, fresh main-loop progress and zero feed errors.

The web service still runs as `va-watchdog-web`. Readiness returned HTTP 200;
anonymous settings changes and unauthenticated remote evidence downloads returned
HTTP 401. A locally generated full support bundle passed ZIP integrity validation
and included the current syslog tail, syslog.1 and compressed rotations .2 through
.4. Its system-log manifest reported no missing or omitted files.

No new reboot, deliberate hardware trip, network interruption or power cut was
performed during this deployment. The earlier .3 normal reboot results remain
documented separately. Restored KVM access is not evidence that the distinct local
gateway operator sign-in and authenticated settings round trip have passed.

The remaining acceptance risks are physical watchdog behavior, device I/O under
recording load, and the new authentication/permission boundary on a real gateway.
Keep the candidate out of unattended field rollout until the acceptance tests pass.
