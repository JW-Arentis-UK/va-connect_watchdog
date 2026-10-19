# Lightweight Single-Page Review

This note captures the simplified direction for the dashboard after reviewing the current multi-section page and the v3 dump.

## Recommendation

Make the default operator view a single lightweight page that answers three questions fast:

1. Is the gateway healthy?
2. If not, what should I check first?
3. Is there a recent incident or warning worth opening?

Keep the rest of the data available, but move it out of the main scan path.

## What to keep on the main page

- Overall state and score
- One-line recommendation
- Recovery state
- Recording storage state
- Hardware watchdog feed state
- Top warning or critical checks
- Last incident summary
- Short event timeline

## What to move behind diagnostics

- Raw JSON
- Full service tables
- Deep hardware inventory
- Kernel and journal detail
- Update logs
- Support-bundle style information

## Why this is better

- It reduces scanning time for operators.
- It keeps the page usable on smaller screens.
- It makes the page feel like an appliance view instead of a debug console.
- It still preserves the detailed pages for engineers.

## Suggested Layout

```text
------------------------------------------------------------
VA-Connect Watchdog Lite
Overall state | Score | Updated | Build

Recommended next step

Overall | Recovery | Storage | Hardware WDT

Keep in view                 Last incident
Top checks                   Recent fault summary

Recent activity              What stays hidden
Latest events                Advanced-only items
------------------------------------------------------------
```

## Small wording change I would keep

Rename:

- `Hardware WDT` to `Hardware Watchdog Feed`

That makes the distinction clearer between the device existing and the watchdog actually being fed.
