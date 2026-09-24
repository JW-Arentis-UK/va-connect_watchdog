# Hikvision Counting Integration Review

Date: 2026-09-24

Reviewed revision: `f7d7e5f` on `codex/gui-refresh`, with existing unrelated working-tree changes left untouched.

Scope: camera configuration UI, capability and historical-report probes, ONVIF subscription lifecycle, native event listener, parsing, totals, request capture, tests, and update checks. This is a review, not a claim of successful live integration. No camera traffic was available to this review environment.

## Findings

### 1. P1: The active collector has no working native Hikvision transport

Code: [hikvision_events.py:357](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:357), [hikvision_events.py:422](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:422).

The worker always calls `_onvif_stream`. When subscription creation fails, it retries the same path indefinitely. The native `alertStream` method exists but is never called by that worker. There is no camera event HTTP POST receiver in the web request handler. The counter and metadata threads are constructed but not started.

Impact: the enabled collection checkbox does not mean native ISAPI collection is active. The latest screenshot shows failure before a subscription exists, so further crossings cannot test the parser or totals. Changing the lease alone has not established an accepted request.

Required correction: select a transport from verified device capabilities, report which transport is actually running, and distinguish connection, subscription, notification receipt, count receipt, and validated totals. Do not automatically combine multiple transports and double-count their reports.

### 2. P1: The native parser discards documented counting fields

Code: [hikvision_events.py:24](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:24), [hikvision_events.py:44](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:44).

The whitelist accepts names such as `enterCount` and `AtoB`, but omits `enter`, `exit`, `pass`, `statisticalMethods`, `regionsID`, and camera timestamps. Hikvision's counting example uses these omitted fields. A local replay of that field structure returned `event_type: PeopleCounting` but `counts: {}`. See the [Hikvision integration guide, pages 19-20](https://www.hikvisioneurope.com/eu/portal/portal/Technology%20Partner%20Program/02-Solutioins%20of%20Hikvision%20product%20integration/Multi-Target%20Counting%20Integration%20Solution.pdf).

Impact: restoring native delivery alone would still not produce usable counts. This defect is independent of the current ONVIF rejection.

Required correction: use independently sourced message fixtures and preserve count mode, source time, channel, rule/region, target category, and directional counters. Do not infer a line crossing from any message that merely mentions a human.

### 3. P1: The capture timer can discard all captured requests on Linux

Code: [web.py:2702](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/web.py:2702), [web.py:2705](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/web.py:2705).

The long-running packet capture is normally stopped by its 60-second timeout. The exception handler keeps output only when it is a string. POSIX subprocess timeout output is bytes, so the handler replaces successfully captured traffic with an empty string and reports completion with no paths. Python documents this distinction for [TimeoutExpired.output](https://docs.python.org/3/library/subprocess.html#subprocess.TimeoutExpired).

Verification: a bytes-valued timeout exception loses its content through the current expression. A real timeout experiment on this Windows review host returned a string, so that experiment alone does not reproduce Linux behavior; CPython's POSIX timeout code and the documented API establish the platform difference.

There are two further limitations. Nonzero packet-capture exit codes and stderr are ignored, so permission or interface errors can also look like an empty successful capture. And capturing on the gateway can only observe traffic visible to its interfaces: a browser on another switched-LAN host is not automatically visible; HTTPS request paths are encrypted.

Required correction: decode bytes, retain actionable process errors, explain traffic visibility, and stop making this feature the prerequisite for integration. A path alone also does not supply a report request's XML/JSON body.

### 4. P1: Successful ONVIF collection would still not complete people counting

Code: [hikvision.py:297](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:297), [onvif_pull.py:55](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/onvif_pull.py:55), [hikvision_events.py:195](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:195).

The topic probe discards the result of `GetEventProperties`. The collector uses the Events address without checking the advertised PullPoint capability. Consequently, the green probe does not establish a usable counting topic or its field semantics. Separately, the summary intentionally skips all `onvif_notification` records and the collector never marks their counts verified.

Impact: fixing authentication or subscription creation is not enough to deliver directional totals. Keeping unverified values out of totals is correct, but the promised feature remains incomplete.

Required correction: inspect the actual TopicSet and message schema, then implement a verified mapping if counting is exposed. Otherwise report ONVIF as diagnostic-only and use a verified native interface. Preserve the safety rule against inventing totals.

### 5. P2: Capability results are misleading and useful error details are lost

Code: [hikvision.py:100](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:100), [hikvision.py:157](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:157), [hikvision.py:378](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:378).

The probe lists XML tag names as supported without reading their boolean values. A local response containing `isSupportPeopleCounting=false` was displayed as supported. A 200 response containing an error-shaped `ResponseStatus` was also accepted. The metadata probe labels any successful HTTP response as an available stream without examining its content.

On HTTP errors, the camera's response body is discarded. A local HTTP 403 with an explanatory `subStatusCode` was reduced to only "Camera returned HTTP 403".

Impact: previous green capability rows did not prove count delivery, and the repeated 403 rows do not identify whether the request, permissions, active application, or interface support is responsible.

Required correction: parse capability values and bounded error bodies; separate endpoint reachability from feature support and live data receipt. Keep credentials and media out of diagnostics.

### 6. P2: Historical-report discovery is incomplete for the active application

Code: [hikvision.py:19](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:19), [hikvision.py:445](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:445).

The only implemented report query is the traditional `/ISAPI/System/Video/inputs/channels/1/counting/search` family. Repeated rejection of that endpoint does not rule out a separate interface for the active application. The code does not inspect the documented `isSupportRegionTargetNumberCounting` capability or its referenced `/ISAPI/Event/channels/<channelID>/RegionTargetNumberCounting/Capabilities?format=json` endpoint. See [Hikvision's system capability reference](https://open.hikvision.com/hardware/v2/08%E5%8D%8F%E8%AE%AE%E9%80%8F%E4%BC%A0/%E5%BC%82%E5%B8%B8%E8%A1%8C%E4%B8%BA%E8%AF%86%E5%88%AB.html).

This is a documented discovery lead, not proof that this camera implements that feature or that it maps to the visible report. A current-firmware historical-search request schema has not been verified. No guessed search body should be presented as a confirmed fix.

Required correction: obtain the device's actual capabilities and the matching report contract. Keep historical retrieval separate from live event subscriptions.

### 7. P2: The totals model cannot safely consume real-time and interval reports

Code: [hikvision_events.py:176](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:176), [hikvision_events.py:203](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:203).

Ordinary native event counter values are simply added. Only the separate `counter_snapshot` kind gets delta treatment, and its baseline is keyed by field alone rather than source/channel/rule. Timestamps are replaced by receipt time. The daily filter compares a local date to the prefix of a UTC timestamp, assigning events incorrectly around local midnight when those dates differ.

Hikvision's [PDC alarm structure reference](https://open.hikvision.com/hardware/structures/NET_DVR_PDC_ALRAM_INFO.html) distinguishes real-time cumulative counts since reset from interval increments. It also describes retransmission. Adding successive cumulative values or duplicated interval reports will overcount. Merely adding the missing parser fields is therefore insufficient.

Required correction: store source timestamps and method; persist per-source/rule/category baselines; handle resets and duplicate intervals; convert timestamps into the reporting timezone before date filtering. Reconcile only matching periods, not reports exported at different times.

### 8. P2: Tests validate assumptions rather than camera compatibility

Code: [test_onvif_pull.py:64](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/tests/test_onvif_pull.py:64), [test_hikvision.py:54](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/tests/test_hikvision.py:54).

The SOAP test double rejects a missing lease and explicitly accepts `PT60S`. This checks serialization and our assumption, not what this camera accepts. The notification fixture supplies invented `AtoB`/`BtoA` fields. The tests do not independently establish that this firmware emits that schema. Passing these tests did not justify describing the lease adjustment as a camera fix.

Required correction: add official-schema fixtures, genuine redacted device responses, Linux capture error cases, capability-false cases, multipart boundaries, resets, retransmissions, timezone boundaries, and live acceptance criteria. Label simulated protocol tests accurately.

## Additional Risks

- [hikvision.py:307](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:307): the probe still constructs `ONVIFCamera`. Inspection of installed `onvif-zeep==0.2.12` confirms its constructor attempts an implicit subscription. The collector deliberately avoids this side effect, but the probe does not. Successful repeated probes can temporarily consume subscription resources. This is not established as the cause of the current rejection.
- [hikvision.py:329](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision.py:329): the authentication fallback sets `encrypt=False`, which the installed library maps to a WS-Security PasswordText token. HTTP Digest does not encrypt the SOAP body. On HTTP this can disclose the password to an observer, even though the interface says HTTP-Digest. Avoid silently downgrading authentication.
- [hikvision_events.py:432](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/va_watchdog/hikvision_events.py:432): the dormant native stream parser splits on one literal XML closing tag rather than MIME framing. It does not handle JSON event parts. Hikvision's [mixed-target capture schema](https://open.hikvision.com/hardware/v2/JSON%E6%96%87%E4%BB%B6/EVENT_JSON_mixedTargetDetection.html) describes target capture data, not a substitute for a confirmed directional counting report. Do not count captured human records as line crossings.
- [update.sh:113](C:/Users/jwuser/JW-Development/va-connect-watchdog/v3/scripts/update.sh:113): deployment checks service activity, not successful rendering of Setup or working camera collection. A running process can still serve HTTP 500. Future releases need an HTTP smoke test and a recovery path; service-active alone is not application-health verification.

## What The Hikvision Guide Actually Establishes

The official [Multi-Target Counting Integration Solution](https://www.hikvisioneurope.com/eu/portal/portal/Technology%20Partner%20Program/02-Solutioins%20of%20Hikvision%20product%20integration/Multi-Target%20Counting%20Integration%20Solution.pdf) describes native HTTP uploads configured through `httpHosts`, or SDK `COMM_ALARM_PDC` callbacks. It also shows counting upload settings. Its applicability statement names customised V5.5.804 firmware, not the user's V5.8.60 build 240807. It is evidence for an integration approach, not permission to flash that old firmware or proof that the current camera supports every example.

The ONVIF error identifies subscription creation as the failing stage. It does not identify the rejected parameter. Changing usernames already resolved the earlier topic-read authentication problem; the new fault must not be relabelled as another password problem without evidence.

## Verification Performed

- Camera-focused tests: 53 passed using the installed ONVIF/Zeep runtime and simulated network responses.
- Full V3 suite: 197 tests, 195 passed, one failure and one error. Both unsuccessful tests inspect expected package-install command strings in the already-modified Neousys installer. That unrelated file was not changed by this review.
- Documented counting field shape: reproduced empty parsed counts.
- False capability and successful-status error body: reproduced incorrect support results.
- HTTP 403 body: reproduced loss of diagnostic substatus.
- Linux-shaped timeout output: reproduced loss through the capture expression; reviewed the platform-specific subprocess code.
- No live subscription, event upload, directional total, or historical report was verified against the user's camera.

## Recovery Path

1. Stop treating a successful login or available ONVIF service as working counting. Leave firmware and authentication settings unchanged while collecting evidence.
2. Make one bounded, read-only native diagnostic run from the gateway. Read full system/event capabilities, the advertised counting capability family, and existing HTTP upload-host capabilities/configuration. Preserve useful error codes and count-related configuration; redact credentials and media. Report each request separately.
3. Select the native transport only after that result. If HTTP upload is supported, implement and test a receiver before configuring the camera to send to it. Read and back up existing destinations; preserve other integrations. Configuring an upload destination changes the camera and needs a deliberate setup step, not a hidden side effect of a test button.
4. If the necessary interface or schema remains unavailable, use the official SDK demonstration or request the model/firmware-specific integration contract from Hikvision. Do not continue cycling guessed ONVIF parameters or unrelated report endpoints.
5. Validate a real count message before asking for more walking tests. Record method, channel/rule, category, source timestamp, and counters. Then implement totals with reset and duplicate handling, and history retrieval as a separate feature.
6. Acceptance requires a baseline followed by one controlled crossing in each direction, agreement with camera counts for the same period, no increase on duplicate delivery, correct reset/reconnect behavior, and a clear stale-data state during outages. Startup, Setup, and update smoke tests must also pass.

## Outcome

The existing integration is incomplete and has reproducible defects. The review does not establish that the camera is incapable of supplying the data. No production code, camera configuration, or remote deployment was changed during this review. Earlier lease and protocol assumptions must be replaced with device evidence before another fix is claimed.

## Implementation Follow-Up

The subsequent, user-authorised implementation adds:

- A bounded native diagnostic button with individual GET paths, HTTP results, prioritised capability values, protocol error codes, and HTTP destination configuration summaries. It performs no camera writes and stops further requests after an authentication failure.
- Native ISAPI alert-stream collection as the default. ONVIF remains an explicit diagnostic option; the two are not combined.
- Bounded multipart XML/JSON parsing with media parts discarded, documented counting field support, rule/channel/timestamp retention, and conservative schema recognition.
- Unverified human counter observations with persistent history baselines, repeated-report handling, separate interval data, per-rule isolation, timezone-aware day filtering, and reset/out-of-order safeguards. Observations are deliberately not labelled verified directional totals or complete daily counts.
- Capture timeout decoding, actionable capture-process failures, HTTPS/traffic-visibility guidance, query-value removal, a packet cap, and single-capture concurrency control.
- Capability boolean and protocol-error interpretation; the metadata endpoint no longer claims a verified live stream merely because it returns HTTP 200.
- Side-effect-free ONVIF topic discovery, advertised PullPoint checks, and removal of the PasswordText authentication downgrade.
- Web import and actual Setup HTTP checks during updates, plus HTTP rendering regression tests.

Still dependent on real device evidence: current-firmware historical search, selection/configuration of camera HTTP push or SDK transport, and live direction/count validation. No HTTP upload destination is changed automatically, no vendor SDK binary is introduced, and no unsupported historical request body is guessed. Use **Run native API diagnostic** after updating to collect the next evidence from the gateway.

## Device Evidence Follow-Up

The gateway diagnostic from build `a17c721` established that this camera advertises `regionTargetNumberCounting`, `supportSearchReport=true`, HTTP event-host configuration, and three currently empty HTTP host slots. The implementation therefore adds a bounded `/hikvision/events` receiver and a guarded camera-slot configuration action for the documented `regionTargetNumberCounting` subscription. The receiver accepts only the configured camera address, limits request size, retains XML/JSON metadata only, and never stores image parts. The selected slot is backed up before a PUT is attempted. This still does not label counts as verified until an actual camera message and controlled crossing test have been observed.
