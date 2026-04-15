# VA-Connect Monitoring Refactor Plan

This plan is intentionally conservative. The goal is not to rebuild the whole app at once, but to make the codebase smaller, clearer, and easier to debug without losing the current operational value.

## Goals

- Simpler logging.
- Clearer crash tracing.
- Separation of API clients from services.
- Thinner routes.
- Less duplicated normalization logic.
- Easier testing.

## Minimum v2 Baseline

The clean v2 should keep only the features needed to monitor, diagnose, and recover a single VA-Connect encoder reliably.

### Keep in v2 baseline

- Process watchdog for VA-Connect start/stop detection.
- Site watchdog for:
  - WAN ping checks
  - LAN TCP checks
  - app process checks
  - systemd service checks
  - reboot detection
  - snapshot capture
  - incident recording
- Web UI for:
  - current status
  - recent events
  - current metrics
  - previous-boot crash review
  - download of incident evidence
- Basic config editing for monitored hosts and commands.

### The smallest useful data model

The v2 baseline should center on a single incident-oriented model:

- `site_state`
- `check_result`
- `incident`
- `snapshot`
- `export_job`

Everything else should be derived from those records rather than invented separately in the UI.

## Phase Plan

### Phase 1: Stabilize the shared foundations

Status: safe to do now

What to do:

- Create shared modules for:
  - JSON read/write helpers
  - ISO timestamp parsing
  - common path constants
  - file naming helpers
  - simple status-file helpers
- Put current file paths in one place.
- Normalize the shape of current state and incident records.
- Add a single incident ID and boot ID to every related artifact where practical.

Why first:

- This reduces repeated code without changing user-facing behavior.
- It makes later testing much easier.
- It helps every future change point back to one record shape.

Done when:

- The site watchdog and web UI both use the same helper layer for shared primitives.
- Status files are still compatible with the current system.
- No feature behavior changes are required yet.

### Phase 2: Make logging and crash tracing coherent

Status: safe to do now

What to do:

- Simplify event logging into a small number of event types.
- Ensure each event includes:
  - incident ID if available
  - boot ID if available
  - timestamp
  - source component
  - short evidence text
- Write one canonical incident summary when a fault is detected.
- Keep the previous-boot snapshot naming consistent with the incident record.
- Make the web UI read the canonical incident summary instead of re-deriving it from scattered files.

Why now:

- The current tracing problem is mostly a data-shape problem.
- Better logs and incident records will improve debugging immediately.

Done when:

- A crash can be followed from one incident ID across state, event logs, and snapshot folders.
- The UI can explain what happened without pulling from several unrelated sources.

### Phase 3: Separate services from routes

Status: safe to do now

What to do:

- Split the web app into thin route handlers and service modules.
- Move business rules out of route functions.
- Keep routes responsible only for:
  - auth check
  - parsing input
  - calling services
  - returning responses
- Separate read-only status logic from write/action logic.

Why now:

- This is the main path to cleaner code without changing the product scope.
- Thin routes are easier to test and review.

Done when:

- Routes are small and mostly delegating.
- Service functions can be tested without HTTP machinery.

### Phase 4: Replace duplicated normalization with shared mappers

Status: safe to do now

What to do:

- Consolidate status normalization into one module.
- Create shared normalization functions for:
  - running/idle/failed job states
  - export state
  - update state
  - incident export state
  - tool-install state
- Standardize field names and timeout behavior where the features are conceptually the same.

Why now:

- The project currently has too many small one-off normalizers.
- Shared normalization reduces bugs and makes the UI more consistent.

Done when:

- Repeated “status” code is mostly gone.
- Similar background jobs behave the same way across the UI.

### Phase 5: Simplify the web surface

Status: should wait

What to do:

- Keep the web UI, but remove the giant all-in-one render function.
- Move HTML into templates.
- Move JavaScript into static files.
- Keep the existing screens and flows at first, but simplify the implementation.

Why wait:

- This is lower risk after the shared data model and services are in place.
- The UI rewrite should happen after the backend concepts are stable.

Done when:

- The UI becomes template-driven.
- The page structure is no longer embedded in one giant Python string.

### Phase 6: Trim the monitoring scope to the clean baseline

Status: optional

What to do:

- Review every feature beyond the v2 baseline.
- Keep only the parts that support diagnosis and recovery.
- Retire features that are useful but not essential to the clean baseline.

Why optional:

- This is a product decision as much as a technical one.
- It should not block the architectural cleanup.

Done when:

- The core product is clearly smaller than the current version.
- Non-essential capabilities are either deferred or placed behind explicit opt-in.

## Current Features That Should Not Be Ported First

These are useful, but they should not be part of the initial clean v2 baseline:

- Hikvision probe and related camera-specific UI/actions.
- Memtest launcher and memtest download/status flow.
- Speedtest launcher and speedtest history flow.
- TeamViewer password reset and TeamViewer-specific command actions.
- Required-tools install automation from the web UI.
- GitHub update check and self-update automation from the web UI.
- Broad incident-pack export automation beyond the minimum incident download path.
- Any additional device-specific probes that are not needed for the main VA-Connect watchdog path.

## Recommended Build Order

1. Shared helpers and path constants.
2. Canonical incident and event records.
3. Thin service modules for watchdog and web behavior.
4. Shared status normalization.
5. Testing around the shared model and the most important flows.
6. Template/static split for the web UI.
7. Optional features only after the baseline is stable.

## Testing Focus

The first tests should cover the parts most likely to break while refactoring:

- config loading
- status normalization
- incident record creation
- snapshot naming
- export naming
- log/event summarization
- route-to-service wiring

## Practical Boundaries

- Do not rewrite the entire app in one pass.
- Do not move optional features into the baseline by accident.
- Do not add clever abstractions that make the code harder to read.
- Prefer boring, explicit modules over deep inheritance or plugin systems.
- Keep FastAPI as the target web framework for v2, but migrate there incrementally.

## Short Version

The refactor should make the app easier to reason about in this order:

1. shared primitives
2. canonical incident data
3. thin services and routes
4. shared normalization
5. simpler UI implementation
6. only then optional extras

That keeps the project maintainable for a small team and avoids a risky full rewrite.
