# GUI Review Checklist

This checklist is the working record for the six-page VA-Connect Watchdog interface review. Update it after each GUI change so unfinished work remains visible.

## Completed

- [x] Reduce navigation to Overview, Events, Hardware, Network, Services, and Settings.
- [x] Redirect removed page routes to their replacement sections.
- [x] Remove Quick Actions from Overview.
- [x] Show the build identifier above its build time and date.
- [x] Separate oldest-recording availability from storage-capacity information.
- [x] Show Root and Storage as separate lines when a dedicated recording disk is configured.
- [x] Replace the initial Events wall with a compact summary and collapsed event log.
- [x] Replace the Overview percentage and donut with a linked operational status list.
- [x] Split Events, History, and Evidence into separate server-rendered tabs.
- [x] Add event filters, compact result rows, expandable evidence, load-more, and filtered exports.
- [x] Remove score-based history and reduce Evidence to incident-focused tools.

## Remaining Page Review

- [ ] Hardware: add System, Disks and Storage, and BIOS/Firmware tabs plus storage validation summary.
- [ ] Network: add staged connectivity results and move raw routes, sockets, and counters into Advanced.
- [ ] Services: simplify normal service rows and add a backend-independent watchdog summary and guided setup.
- [ ] Settings: simplify field-adjustable settings and consolidate TeamViewer, updates, and recovery tools.

## Later Architecture Work

- [ ] Classify runtime collectors as Keep, Reduce, Incident-only, or Remove.
- [ ] Ensure normal pages read stored status instead of launching expensive diagnostics.
- [ ] Preserve only lightweight continuous monitoring and move forensic detail into Black Box incidents.
