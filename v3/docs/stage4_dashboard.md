# Stage 4 Dashboard Refinement

This stage makes the main page easier to scan at a glance.

## Layout goals

- put the overall health card near the top
- keep update and recovery status visible
- group checks into hardware, services, storage, and system
- keep the hardware watchdog warning visible as a distinct signal
- keep raw JSON out of normal operator views

## What the operator should see first

1. Update state
2. Recovery state
3. Startup summary
4. Overall health
5. Hardware checks
6. Service checks
7. Storage checks

## Appliance dashboard changes

- the Overview page uses compact tiles instead of full-width debug cards
- service health appears as a table
- recent events are read from `events.jsonl`
- raw status JSON is only shown under Diagnostics
- `/api/status` remains unchanged
