# VA-Connect v3 Start

The v3 line begins as a compatibility-preserving rename and launch refresh.

## Current v3 baseline

- v3-prefixed environment variables are preferred
- v2 environment variables remain supported as fallback
- the default data directory is `.v3-data`
- the default log file is `logs/v3.log`
- the desktop launcher is `run_v3.bat`
- the web app branding now says `VA-Connect V3`

## Why this is the starting point

The existing v2 scaffold is already a stable operational base. v3 should start by making the version boundary explicit before any deeper rewrite happens.

That gives us:

- a clear place to put new work
- a safe compatibility path for old configs
- a smaller risk of mixing v2 and v3 semantics in the same naming scheme

## Next implementation steps

1. Split the remaining watchdog logic into smaller runtime modules.
2. Split the web surface into routes, services, and presentation helpers.
3. Introduce v3-specific deployment scripts only after the runtime shape settles.
