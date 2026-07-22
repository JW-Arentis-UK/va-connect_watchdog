# Branch and Rollback Strategy

Status: Ready for approval

## Source Baseline

- Current development branch: `codex/gui-refresh`
- Reviewed runtime commit: `252ac5a`
- Remote: `origin` at `JW-Arentis-UK/va-connect_watchdog`

The architecture documentation and Stage 0 artifacts should be committed before creating the immutable pre-refactor tag.

## Proposed Git Structure

| Purpose | Name |
|---|---|
| Last validated pre-refactor release | annotated tag `v3-pre-architecture-refactor-20260722` |
| Refactor integration branch | `codex/watchdog-architecture-refactor` |
| Short implementation branches | `codex/watchdog-refactor-<stage>-<topic>` |
| POC release candidates | annotated tags `watchdog-rc-<build>` |
| Validated appliance releases | annotated tags `watchdog-<build>` |

Do not retarget deployed gateways to a moving feature branch. POC deployment should record an exact commit or release-candidate tag.

## Commit Policy

- One responsibility boundary per commit where practical.
- No unrelated features during the refactor.
- Compatibility adapters and their planned removal are documented together.
- Every behaviour change includes tests and migration notes.
- Systemd, installer, configuration, and runtime changes are reviewed as one deployment unit when they depend on each other.

## POC Deployment Policy

Before updating:

1. Record the current commit and branch.
2. Export `/etc/va-watchdog/config.json`.
3. Preserve `/var/lib/va-watchdog` evidence indexes and any active incident.
4. Generate a support bundle.
5. Confirm SSH and an independent remote path are working.
6. Confirm startup grace is configured.
7. Confirm the rollback commit exists locally or is fetchable.

Only the POC gateway receives architecture refactor builds until field validation is approved.

## Rollback Principles

- Code rollback must not delete configuration, history, incidents, or CCTV recordings.
- Configuration migration always creates a backup and must be reversible.
- New state files use schema versions and remain ignorable by the old build.
- Old state files are not destructively rewritten until the migration is validated.
- Systemd unit rollback is included with code rollback.
- Rollback does not automatically alter recording storage or `/etc/fstab`.

## Planned Rollback Procedure

The exact command is validated during Stage 1, but the controlled sequence is:

```bash
cd /opt/va-connect-watchdog-v3
sudo systemctl stop va-watchdog-web.service 2>/dev/null || true
sudo systemctl stop va-watchdog-core.service 2>/dev/null || true
sudo git -c safe.directory=/opt/va-connect-watchdog-v3 fetch --tags origin
sudo git -c safe.directory=/opt/va-connect-watchdog-v3 checkout v3-pre-architecture-refactor-20260722
sudo ./v3/scripts/install.sh
sudo systemctl status va-watchdog va-watchdog-feed --no-pager
```

Before this is used in the field, it must be tested against:

- A clean current V3 installation.
- A partially migrated configuration.
- New systemd units already installed.
- A failed Core/Web split deployment.
- A gateway with an active recording mount.

## Emergency Safety

If the new Core cannot remain running but remote access is available:

- Stop the new Core/Web units.
- Keep or disable hardware feeding according to the approved device policy and startup grace.
- Do not improvise device closure when nowayout behaviour is unknown.
- Roll back the complete deployment unit, not individual Python files.
- Preserve all logs and incident state before retrying.

