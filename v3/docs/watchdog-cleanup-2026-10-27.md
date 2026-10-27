# Watchdog Cleanup: 27 October 2026

## Scope

Build 20261027.5 removes obsolete deployment sources, not active analytics.
The operator explicitly retained ANPR, people/crossing analytics, analytics camera
diagnostics/configuration/capture, PDF reports, speed tests, custom web links and
TeamViewer password controls. Their dependencies remain installed.

## Removed

- Historical V1/V2 tools runtimes, web assets, installers and uninstall helpers.
- Root V2 launch/bootstrap entry points and obsolete root build-stamping workflow.
- Tracked temporary copies of generated JavaScript.
- Unused consolidated-recovery import wrapper; tests use the active engine.
- Duplicate legacy status rendering and unused reboot-grace settings.
- Duplicate engineering-status entry points; existing links redirect safely.

Historical source remains recoverable from Git commit `0d7ea74`. Legacy data and
incident records are retained. No legacy uninstaller was executed: those helpers
could delete logs and backups. Removing source does not stop a separately
installed legacy service. Conflict detection and read-only legacy evidence
attribution therefore remain essential.

## Simplified

- One everyday status renderer, with support/commissioning kept apart.
- Maintenance and shortcuts select links for the actual device profile.
- Pi reports native systemd protection instead of Neousys commissioning controls.
- HTTP access and privileged replay both reject wrong-device tools.
- Optional router details are hidden when monitoring is disabled.
- Documentation describes the two current storage choices and current security.

## Deliberately Kept

Recovery safety guards, startup grace, deliberate-test confirmations, current-boot
freshness, independent feeding, bounded collectors and black-box evidence remain.
The shared detailed-page renderer is still used for setup and support. Historical
incident documents and data must not be deleted as UI clutter. Reportlab and ONVIF
dependencies remain because retained features use them.

## Verification And Limits

Regression tests cover retained navigation, profile-specific pages and guards,
redirects, helper enforcement, analytics exports, recovery and evidence. Physical
Pi acceptance remains separate from profile tests. No deliberate hardware reset
or destructive recording test is required by this cleanup.

Use the full updater so installed permissions and services match the source.
Before a field upgrade, preserve evidence and confirm identity. Source tests alone
do not establish that a build has been installed or physically tested.

Local verification completed:

- Windows Python 3.13: 380 tests, no failures, ten platform/dependency skips.
- Ubuntu WSL Python 3.14: 380 tests, no failures, nine skips. Existing tests emit
  HTTPError cleanup ResourceWarnings; these do not fail the suite.
- Eight cleanup regression tests exercise both device profiles, actual retained
  feature pages, redirects, wrong-device HTTP rejection and helper rejection.
- Access-setup shell syntax and whitespace checks passed.

Deployment must be verified against the running build after installation; the
test results above describe source validation, not physical Pi acceptance.
No footage, credentials or incident archives were changed by the cleanup.
