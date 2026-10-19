# Network reboot attribution

The Recent Restarts card shows **Watchdog reboot — no network access** when the
older site watchdog recorded a successful reboot command alongside failed LAN
or internet checks. The status page shows the recorded reason. This identifies
the recovery trigger; it does not establish why the network stopped working.

V3 reads `/var/log/va-connect-site-watchdog/events.jsonl` at monitor startup.
`legacy_watchdog_events_path` overrides this location. Attribution requires a
heartbeat belonging to the previous boot, a nearby successful reboot action,
and a short interval to the next boot. Failed checks alone do not change the
reboot classification. Missing, malformed, or unavailable evidence leaves the
cause unestablished. Only selected fields are copied; legacy startup settings
and credentials are excluded.

The reader scans the last 16 MiB of the legacy event log. Older or rotated-out
events may therefore remain unclassified. On monitor restart it can amend the
latest previously recorded unknown/clean reboot, including its archive and
restart-history entry, if the matching evidence is still available. Existing
explicit causes and confirmed watchdog tests are preserved.

The legacy watchdog also saves its reboot reason and originating boot ID before
issuing shutdown, so its next startup can identify its own requested reboot.
Failed commands restore the previous attribution state.

These changes require deployment to the gateway. This source change does not
alter the running gateway or restart its services.
