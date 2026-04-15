# VA-Connect Watchdog Architecture Review

## Scope

This review covers the current repository shape, the main runtime path, the deployment scripts, and the biggest architecture issues that make the project hard to debug and evolve.

The codebase is small at the top level, but the runtime is concentrated in two large Python files:

- `tools/ubuntu/va_connect_site_watchdog.py`
- `tools/ubuntu/va_connect_watchdog_web.py`

The supporting shell scripts are mostly deployment and bootstrap helpers.

## Current Structure

### Root

- `README.md` explains the current deployment and operating model.
- `docs/ubuntu_va_connect_watchdog.md` is the main operator guide.
- `docs/moor_lane_incident_test_plan.md` and `recovery.md` are incident and investigation notes, not architecture sources.
- `thread-notes.md` and the `tmp_*.js` / `.tmp_*.js` files are historical artifacts and do not appear to participate in runtime behavior.

### `tools/ubuntu`

#### Core runtime

- `va_connect_watchdog.sh`
  - Lightweight process watchdog.
  - Loads `va-connect.env`.
  - Checks whether the VA-Connect process is running.
  - Restarts it with a cooldown and grace period.

- `va_connect_site_watchdog.py`
  - Continuous site watchdog.
  - Performs WAN checks, LAN TCP checks, process/service checks, snapshot capture, reboot detection, and incident recording.
  - Owns the primary state file and JSONL event/metrics files.

- `va_connect_watchdog_web.py`
  - Web UI plus API endpoint layer.
  - Reads state, builds summaries, launches exports, launches update jobs, exposes downloads, and renders the HTML UI.

#### Deployment and maintenance

- `install_watchdog.sh`
  - Copies files into `/opt/va-connect-watchdog`.
  - Installs systemd units.
  - Creates command wrappers.
  - Writes build info.

- `update_watchdog.sh`
  - Pulls updates and re-runs the installer and service restart.

- `git_update_watchdog.sh`
  - Git-based update helper used by the web UI and operator commands.

- `bootstrap_watchdog_from_github.sh`
  - Clone/bootstrap script for a fresh machine.

- `bootstrap_gateway_watchdog.sh`
  - More opinionated bootstrap with preflight checks.

- `collect_va_connect_site_info.sh`
  - Site inventory collection script.

- `export_watchdog_incident.sh`
  - Incident bundle export helper.

- `restart_watchdog_services.sh`
  - Restarts the site watchdog and web UI services.

#### Systemd units and config examples

- `va-connect-watchdog.service`
- `va-connect-watchdog.timer`
- `va-connect-site-watchdog.service`
- `va-connect-watchdog-web.service`
- `va-connect.env.example`
- `site-watchdog.json.example`

## Problem Areas

### 1. The project has two monoliths

`va_connect_site_watchdog.py` is already a large orchestration file, but `va_connect_watchdog_web.py` is the real pressure point. It is roughly 7,100 lines long and mixes:

- HTTP request handling
- config updates
- status normalization
- crash analysis
- export orchestration
- update orchestration
- device-specific probes
- HTML generation
- JavaScript UI logic

The web file is effectively the whole product surface in one file. That makes any change risky and makes it hard to tell where a behavior belongs.

### 2. Responsibilities are mixed in the same files

#### `va_connect_site_watchdog.py`

The site watchdog mixes:

- configuration loading
- monitoring loop
- WAN/LAN/process/service checks
- recovery actions
- reboot backoff logic
- snapshot capture
- previous-boot classification
- incident creation
- persistent state management
- hardware health sampling

The line between “business rules” and “side effects” is thin. For example, the class writes events, writes metrics, mutates state, classifies outcomes, and manages cleanup all in the same object.

#### `va_connect_watchdog_web.py`

The web process mixes:

- data access
- data normalization
- derived diagnosis logic
- incident summarization
- HTTP routing
- file downloads
- action launching
- update checking
- HTML/CSS/JavaScript rendering

The `Handler` class is only the final endpoint layer. Most of the behavior has already been decided earlier in the file, which makes the UI hard to test independently.

#### Shell scripts

The installer and update scripts are small enough to keep, but even there several files combine multiple concerns:

- install file deployment
- service installation
- wrapper generation
- build metadata writing
- runtime verification

That is acceptable for deployment scripts, but it reinforces the current “everything in one place” pattern.

### 3. Helper logic is duplicated across files

There is repeated utility code in both Python programs:

- `read_json`
- `write_json`
- `parse_iso`
- `run_shell`
- status file reading/writing patterns
- config loading and default merging

There is also duplicated path knowledge:

- `/var/log/va-connect-site-watchdog/...`
- `/var/lib/va-connect-site-watchdog/...`
- `/opt/va-connect-watchdog/...`

Those paths are repeated as literals in multiple places, which makes future changes easy to miss.

### 4. Normalization logic is fragmented and inconsistent

The web file contains many separate normalization functions:

- `normalize_update_status`
- `normalize_export_status`
- `normalize_incident_export_status`
- `normalize_memtest_status`
- `normalize_speedtest_status`
- `normalize_tools_install_status`

That pattern is a sign that the project is missing a shared state model.

The practical problem is not just repetition. It is that the same kinds of objects are being normalized in slightly different ways:

- “running” state handling differs by feature
- timeout handling differs by feature
- message text differs by feature
- file naming differs by feature
- final state persistence differs by feature

This makes it hard to know whether a status file means the same thing across the UI.

### 5. Crash results and logs are hard to understand

This is mostly an architecture problem, not just a UX problem.

Right now crash evidence is spread across:

- JSONL event streams
- JSONL metrics streams
- incident records
- previous-boot snapshot directories
- ad hoc export status files
- web update logs
- manual export folders
- derived summaries in the web UI

That creates several debugging problems:

- There is no single canonical incident record.
- The same incident is represented in multiple places with slightly different shapes.
- Plain text and JSONL are mixed together.
- Some summaries are derived from heuristics rather than a shared incident model.
- The web UI often presents a conclusion without showing which source file established it.

The biggest issue is traceability. It is hard to answer “what happened, in what order, and which signal proved it?” without cross-checking multiple files.

### 6. Bridge and RMS normalization is not centralized

I did not find separate `Bridge` or `RMS` modules in the codebase. The likely reality is that those concepts are represented indirectly inside the web layer and incident/export shaping logic.

So the problem is the same even if the names are different:

- normalization is embedded in feature code
- related records are shaped in more than one place
- there is no shared mapping layer for domain-to-UI translation

If Bridge and RMS are both represented in the current project, their normalization should live in one shared module, not in UI handlers or export helpers.

### 7. The UI is too stateful for the amount of logic it carries

The HTML page is generated from a huge `render_page` function, and the JavaScript logic for the page is embedded inline.

This causes:

- poor separation of concerns
- difficult diff reviews
- large unrelated edits when the page changes
- high risk of regression in unrelated UI sections

### 8. There are tracked temporary artifacts

The repository includes temporary `tmp_*.js` and `.tmp_*.js` files at the root.

They appear to be generated or exploratory artifacts, not runtime sources, and they are not referenced by the operational scripts. They add noise to the repository and should not stay in the long-term codebase.

## Why Debugging Is Hard

The project currently has weak observability boundaries.

### The same event is represented in several forms

Example sources:

- a site watchdog event in JSONL
- a state update in a JSON file
- a previous-boot journal snapshot
- a rendered UI summary
- an export pack written to disk

Those representations are related, but not mechanically linked.

### There is no stable incident model

The codebase does not appear to have a single typed incident schema that everything else consumes.

Instead, the project uses:

- raw dictionaries
- feature-specific payload builders
- feature-specific status normalizers
- heuristics in the web UI

That is flexible, but it is exactly why crash tracing feels inconsistent.

### Logging is operational, not diagnostic

The current logs are useful for watching activity, but they are not optimized for reconstructing a failure path.

Missing pieces include:

- one incident ID across all related files
- one boot/session ID shared across state, events, and snapshot artifacts
- one standard “cause / evidence / action” format
- a short canonical summary written at the moment a fault is detected

## Quick Wins

1. Delete the root temporary JS artifacts once they are no longer needed.
2. Introduce a small shared module for:
   - JSON read/write helpers
   - ISO timestamp parsing
   - path constants
   - status-file helpers
3. Move repeated status normalization into shared functions.
4. Introduce a single incident schema for the site watchdog and web UI.
5. Separate pure data shaping from HTTP handlers.
6. Split the current web file into route handlers, service logic, and presentation helpers.
7. Make log lines and incident records carry the same incident ID and boot ID.
8. Add one canonical “failure summary” record when a fault is detected.
9. Keep deployment scripts small, but stop duplicating logic that should live in shared code.

## Proposed Modular Structure For V2

The goal should be simpler, not cleverer.

```text
tools/ubuntu/
  deploy/
    install_watchdog.sh
    update_watchdog.sh
    git_update_watchdog.sh
    bootstrap_watchdog_from_github.sh
    bootstrap_gateway_watchdog.sh
    restart_watchdog_services.sh
  runtime/
    process_watchdog.sh or process_watchdog.py
    site_watchdog.py
  shared/
    config.py
    io.py
    paths.py
    time.py
    logging.py
    models.py
    normalization.py
    health.py
  web/
    app.py
    routes_status.py
    routes_actions.py
    routes_downloads.py
    services.py
    templates/
    static/
  export/
    incident_pack.py
    snapshots.py
    journal_slices.py
```

### Design principles for v2

- Keep FastAPI for the web surface.
- Keep the process watchdog tiny.
- Keep the site watchdog focused on monitoring and recovery.
- Keep file-system state simple and explicit.
- Prefer one data model over many ad hoc dictionaries.
- Use thin route handlers and service functions.
- Keep diagnostic summaries close to the data model, not inside the HTML renderer.

## Keep, Rewrite, Merge, Remove

### Keep

- `va_connect_watchdog.sh` as a small process-health shim.
- The core monitoring intent in `va_connect_site_watchdog.py`.
- The deployment scripts that install, update, and restart the stack.
- The operator documentation in `docs/ubuntu_va_connect_watchdog.md`.

### Rewrite

- `va_connect_watchdog_web.py`
  - This is the best candidate for a substantial rewrite.
  - It should become a FastAPI app with separated route modules and service modules.
  - The current inline HTML and inline JavaScript should move into templates/static assets.

- The orchestration portions of `va_connect_site_watchdog.py`
  - Keep the functionality, but split monitoring, recovery, snapshotting, and incident-building into separate modules.

### Merge

- Duplicate JSON helpers
- Timestamp parsing helpers
- Status normalization helpers
- Path definitions
- Export/incident naming helpers
- Crash-summary helpers

### Remove

- `tmp_rendered_script.js`
- `tmp_script_1.js`
- `tmp_script_2.js`
- `tmp_script_2_checked.js`
- `.tmp_script1.js`
- `.tmp_script2.js`

If any of those files are still needed for a specific investigation, they should be moved into a named `scratch/` or `archive/` location with an explanation, not left at the repository root.

## Migration Plan

### Phase 1: Stabilize the current shape

- Record the current output contracts for the state file, events, metrics, incidents, and exports.
- Remove obvious temp artifacts from the tracked root once confirmed unused.
- Add a shared constants module for paths and file names.

### Phase 2: Extract shared primitives

- Move `read_json`, `write_json`, `parse_iso`, and related helpers into a shared module.
- Move config loading into one shared config loader.
- Move status-model helpers into one normalization module.

### Phase 3: Split the monitoring layer

- Separate check collection from recovery action execution.
- Separate snapshot capture from incident creation.
- Make the site watchdog write one canonical incident record.

### Phase 4: Replace the web monolith

- Introduce a FastAPI app for the web UI and API.
- Split routes by concern:
  - status/read-only endpoints
  - action endpoints
  - export/download endpoints
  - admin/config endpoints
- Move HTML into templates and static assets.
- Keep the page behavior, but stop generating the entire app from one function.

### Phase 5: Tighten observability

- Add a single incident ID and boot/session ID to every related artifact.
- Make summaries point back to source evidence.
- Standardize “what happened / evidence / action taken” fields.

### Phase 6: Clean up and retire legacy shapes

- Remove duplicate logic that survives the extraction.
- Replace ad hoc status files with a smaller set of typed files.
- Retire the minute timer if the site watchdog covers the same function cleanly.

## Bottom Line

The project is functional, but the architecture has grown in a way that makes troubleshooting harder than it should be for a small-team system.

The main problem is not raw feature count. It is that the same concepts are represented in too many places, and the web UI has become the place where monitoring data, operational state, crash analysis, and presentation all meet.

For a v2, the best path is a simpler module layout, a shared model layer, a FastAPI web surface with thin routes, and much stronger incident traceability.
