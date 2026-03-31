I was looking at the issue on ChatGPT and it came up with this. 🧠 POC-451VTC Linux Stability Investigation – Summary

1\) System Context

Hardware: Neousys POC-451VTC

CPU: Intel Elkhart Lake (x6425E)

NICs: 3 × Intel I225 (2.5GbE, igc driver)

OS: Linux (kernel 6.8)

2\) Observed Behaviour

A) Hard lockups

Occur:

after reboot

while idle (no workload)

No prior warning or logs → indicates low-level freeze

B) Network instability (confirmed)



From dmesg:



enp3s0: Link Up → Down → Up → Down (repeating)

Only affects one NIC (enp3s0)

Happens immediately after boot

Independent of workload

3\) Key Findings

🔴 1. Intel I225 instability (primary issue)

Known issue on Linux:

link flapping

drops / resets

instability across kernels

Your logs match exactly:

repeated link renegotiation

unstable PHY behaviour

🔴 2. Kernel mismatch (critical)

Manual states:

Linux support ≤ kernel 5.8

System is running:

6.8 (unsupported)



👉 This introduces:



power management incompatibilities

PCIe/NIC instability

🔴 3. Power management instability (very likely root cause of freeze)



Typical for this platform:



CPU C-states (idle sleep)

PCIe ASPM

NIC power states



👉 Especially when:



system is idle

no workload present

🟡 4. Secondary signal

EDAC igen6 MC0: HANDLING IBECC MEMORY ERROR

Correctable memory event

Not currently root cause

Monitor if frequency increases

4\) Root Cause (Combined)



System instability is likely caused by a combination of:



Intel I225 NIC instability

Aggressive power management (CPU + PCIe)

Running unsupported/new kernel (6.8)



👉 These interact, causing:



NIC resets

interrupt storms

eventual system freeze

5\) Confirmed Behaviour Pattern

Condition	Result

Idle after boot	Freeze

NIC active (enp3s0)	Link flapping

Multiple NICs present	Increased instability risk

6\) Recommended Fix Strategy

Immediate (stabilisation)

Force NIC settings:

1Gb fixed speed

disable offloads

disable EEE

Disable power saving:

CPU C-states

PCIe ASPM

Medium-term (recommended baseline)

Move to:

Kernel 5.15 LTS



👉 Best balance:



newer than vendor limit (5.8)

stable for igc

Diagnostic validation

Disconnect enp3s0

If stable → NIC confirmed root contributor

7\) Key Conclusion



This is not a missing driver issue.



It is a platform-level stability issue caused by:



Intel I225 NIC behaviour + Linux kernel + power management interaction



8\) Operational Impact

Random system freezes

Network instability

Potential loss of CCTV streams / gateway function

9\) Suggested Monitoring Enhancements (for your tool)



Add detection for:



NIC link flaps:



ip link / ethtool state changes

Kernel soft lock indicators:

watchdog events

interrupt spikes

Pre-freeze indicators:

rapid link up/down cycles

NIC resets

Bottom line

Hardware is supported

Drivers exist in kernel

But combination = unstable without tuning





Also added this If you want next step, I can:



turn this into a health-check script your tool can run

or define alert rules (e.g. “X link drops in Y seconds = fault”)

yes



Below is a drop-in monitoring + mitigation package you can plug into your Codex tool.



1\) What this adds

Detects:

NIC link flapping

Kernel errors (igc / PCIe / resets)

Logs to file

Optional alerts (stdout for your tool to pick up)

Auto-applies stabilisation (optional)

2\) Monitoring Script (Python)



Save as: poc\_monitor.py



import subprocess

import time

import re

from datetime import datetime



LOG\_FILE = "/var/log/poc\_monitor.log"



INTERFACES = \["enp1s0", "enp2s0", "enp3s0"]

FLAP\_THRESHOLD = 5      # events

FLAP\_WINDOW = 30        # seconds



link\_events = {iface: \[] for iface in INTERFACES}





def log(msg):

&#x20;   line = f"{datetime.now()} | {msg}"

&#x20;   print(line)

&#x20;   with open(LOG\_FILE, "a") as f:

&#x20;       f.write(line + "\\n")





def get\_link\_state(iface):

&#x20;   try:

&#x20;       out = subprocess.check\_output(\["cat", f"/sys/class/net/{iface}/operstate"]).decode().strip()

&#x20;       return out

&#x20;   except:

&#x20;       return "unknown"





def check\_links():

&#x20;   for iface in INTERFACES:

&#x20;       state = get\_link\_state(iface)



&#x20;       now = time.time()

&#x20;       link\_events\[iface].append((now, state))



&#x20;       # keep only recent window

&#x20;       link\_events\[iface] = \[

&#x20;           (t, s) for t, s in link\_events\[iface]

&#x20;           if now - t < FLAP\_WINDOW

&#x20;       ]



&#x20;       # count transitions

&#x20;       transitions = 0

&#x20;       prev = None

&#x20;       for \_, s in link\_events\[iface]:

&#x20;           if prev and s != prev:

&#x20;               transitions += 1

&#x20;           prev = s



&#x20;       if transitions >= FLAP\_THRESHOLD:

&#x20;           log(f"\[ALERT] {iface} LINK FLAPPING ({transitions} changes in {FLAP\_WINDOW}s)")





def check\_dmesg():

&#x20;   try:

&#x20;       out = subprocess.check\_output(\["dmesg", "-T"], stderr=subprocess.DEVNULL).decode()



&#x20;       patterns = \[

&#x20;           "igc",

&#x20;           "reset",

&#x20;           "watchdog",

&#x20;           "pcie",

&#x20;           "AER"

&#x20;       ]



&#x20;       for line in out.splitlines()\[-50:]:

&#x20;           if any(p.lower() in line.lower() for p in patterns):

&#x20;               log(f"\[DMESG] {line}")



&#x20;   except:

&#x20;       pass





def main():

&#x20;   log("=== POC Monitor Started ===")



&#x20;   while True:

&#x20;       check\_links()

&#x20;       check\_dmesg()

&#x20;       time.sleep(5)





if \_\_name\_\_ == "\_\_main\_\_":

&#x20;   main()

3\) Auto-Fix Script (optional but recommended)



Save as: poc\_fix.sh



\#!/bin/bash



echo "Applying NIC stability settings..."



for i in enp1s0 enp2s0 enp3s0; do

&#x20;   ethtool -K $i tso off gso off gro off 2>/dev/null

&#x20;   ethtool --set-eee $i eee off 2>/dev/null

&#x20;   ethtool -s $i speed 1000 duplex full autoneg off 2>/dev/null

done



echo "Done."



Make executable:



chmod +x poc\_fix.sh

4\) Make it persistent (recommended)

A) Create systemd service

sudo nano /etc/systemd/system/poc-monitor.service

\[Unit]

Description=POC Stability Monitor

After=network.target



\[Service]

ExecStart=/usr/bin/python3 /opt/poc\_monitor.py

Restart=always



\[Install]

WantedBy=multi-user.target

B) Enable it

sudo systemctl daemon-reexec

sudo systemctl daemon-reload

sudo systemctl enable poc-monitor

sudo systemctl start poc-monitor

5\) Optional: Auto-run fix on boot

sudo crontab -e



Add:



@reboot /opt/poc\_fix.sh

6\) What your Codex tool can watch for

Key alerts to parse:

Link instability

\[ALERT] enp3s0 LINK FLAPPING

Kernel issues

\[DMESG] igc ...

\[DMESG] reset ...

\[DMESG] watchdog ...

7\) Suggested alert logic

Condition	Action

>5 link changes / 30s	Flag NIC fault

repeated igc logs	Flag driver instability

watchdog / reset logs	Flag imminent crash

8\) Minimal integration option



If you don’t want full script:



Just monitor:



ip monitor link



and trigger if:



same interface toggles repeatedly

Bottom line



This gives you:



Detection before failure

Correlation (NIC ↔ crash)

Auto-stabilisation



If you want next step, I can extend this into:



a GUI panel inside your Codex app

or push alerts (tray popup / email / webhook)





Can you look as see if anything is good to look at.









Worked for 44s

Some of it is worth looking at, but a few parts are overstated.



What looks solid



The vendor/kernel mismatch is real. Neousys’ POC-451VTC manual says Linux should use kernels “no later than 5.8” and lists Ubuntu 20.04.2 with a 5.8 kernel as the tested Linux option. Neousys manual

Focusing on the igc/I225 path is reasonable if your logs show one interface repeatedly going Link Up / Link Down.

EEE is a good thing to test. There’s evidence in igc-related code/discussion that EEE on I225/I226 can cause hangs/instability, and disabling it is a sensible experiment. igc EEE patch discussion

Isolating enp3s0 is a strong next diagnostic step. If the box becomes stable with that NIC disconnected or disabled, that’s a very useful signal.

What I’d treat as unproven



“Kernel 6.8 is the root cause” is too strong. The vendor only says <= 5.8 is their tested Linux baseline, not that every newer kernel is broken.

“Move to 5.15 LTS” is not backed by the sources I checked. In fact, Intel’s own support material for one igc crash case told users to update from 5.19 to 6.0.10, not downgrade to 5.15. Intel article

“Hard freeze is caused by NIC + power management” is plausible, but still a hypothesis unless you capture pre-freeze evidence.

What I’d actually do next



Test with enp3s0 physically disconnected or administratively down.

Disable EEE on that NIC and retest.

Disable ASPM/C-state tuning one change at a time, not all at once.

Compare behavior on a vendor-aligned kernel baseline before making bigger conclusions.

Add persistent logging that survives freezes if possible, like serial console, netconsole, or remote journald.

About the script

Good idea, but I would not ship that exact version as-is.



It rereads all of dmesg -T every cycle, which is noisy and expensive.

It will log the same kernel lines over and over.

subprocess.check\_output(\["cat", ...]) should be replaced with direct file reads.

ethtool -s ... autoneg off at forced 1G is a test, not a safe default.

poc\_fix.sh is weaker than a proper systemd unit.

So: yes, there are good leads in it, especially igc/I225, EEE, ASPM/C-states, and isolating enp3s0. But I would treat the “root cause” and “5.15 is the answer” parts as unverified.



If you want, I can turn this into a cleaner Linux health-check module for your tool and separate it into:



safe monitoring

optional mitigations

alert rules for link flaps and igc resets



Yes, also can you search to see if anyone else has had issues with this kernal and intel verwsion etc.







Worked for 59s

Yes. There is enough out there to say this is a real class of problem, not just a one-off on your box.



What I found



Neousys explicitly says the POC-451VTC Linux baseline is kernel <= 5.8, with Ubuntu 20.04.2 / 5.8 as the tested Linux combo. That makes your current kernel 6.8 outside the vendor-tested range. Neousys manual

Intel’s own supported-kernel table for igc is narrow. For I225, Intel lists tested Linux kernels including 5.8 and 5.16.18, not a broad “all modern kernels” promise. Intel supported OS list

There are community reports of I225-family devices breaking on newer kernels:

one Intel Community report says an I225-LMvP worked on 6.1.90 but failed on 6.8.9 and 6.9.0 with “PCIe link lost, device now detached.” Intel Community

a Linux kernel mailing list report shows an I225 losing PCIe link and becoming unusable on Debian kernel 6.5.10, with igc\_rd32 warnings. LKML thread

Power-management interaction is a credible lead, not just guesswork:

a netdev bug report shows an I226 dropping after idle when ASPM is enabled, and becoming stable with pcie\_aspm=off. netdev report

there is also a stable-kernel patch disabling PCIe L1.2 for I226 to avoid performance problems caused by that low-power state. stable patch

There is silicon-level history here too: Intel’s I225 spec update documents a known erratum and says forcing link speed to 1 Gbps is a workaround in some scenarios. Intel I225 spec update

What that means for your case



The exact claim “kernel 6.8 is definitely the root cause” is still too strong.

But “newer kernel + igc/I225 + PCIe/power-management interaction can cause real instability” is well supported.

Your symptom pattern:

idle freezes

repeated link renegotiation on one NIC

I225 hardware

lines up well enough that this is worth treating as a primary investigation path.

Best leads to test first



Disable or unplug the bad interface enp3s0 and see if overall stability improves.

Test with ASPM disabled in BIOS or via kernel parameter pcie\_aspm=off.

Test with EEE disabled on the affected NIC.

Force that NIC to 1 Gbps as a diagnostic, not as a permanent assumption.

Compare against a vendor-aligned kernel baseline before drawing conclusions about hardware failure.

One interesting extra



In that Intel Community thread, the reporter later said their solution was adding pcie\_ports=native. That is only one report, so I would treat it as a targeted experiment, not a general fix. same thread snippet

So the short answer is: yes, other people have hit similar igc/I225-family problems on newer kernels, including around 6.8, and the power-management angle is credible.



If you want, I can now turn this into:



a cleaned-up monitoring script

a safer mitigation script

a small “Linux stability” panel in your tool with alert rules for link flaps, igc errors, and PCIe detach events



User attachment

The Nic looked like it was a repower due to the unit locked up, so dont know if this was the issue as I think this was reported after the lockup (cant be sure, can we check?) 



What was reported before was somthing to do with memory issues can we check that too?





Also add some more things to the list:



1, add teamviewer details to the webpage. so I can remote in and also an ability to reset the password.

2, add  in brakets no of alerts next to the watchchdog/rebout count etc on the PC Stats graph.

3, Add the extra above but try to make the fault reporting better as its getting harder to faultfind. 











Worked for 1m 21s

We can check both of those, but not from this repo alone.



This repo is still the relay tool. It does not contain the PC Stats graph, watchdog/reboot charts, or TeamViewer page from your screenshots, so I can’t safely add those UI changes here yet. Those screenshots look like the broader ops app you mentioned earlier. If you want those exact changes implemented, I need that repo or those page/component files.



On the lockup question:



We cannot yet prove whether the NIC flap happened before the freeze or only after the repower.

To check that properly, we need the previous boot’s kernel log, not just the current boot.

What to check on the Linux box:



journalctl --list-boots

journalctl -b -1 -k -o short-monotonic | grep -Ei 'igc|enp3s0|link|reset|watchdog|edac|mce|memory'

journalctl -b -1 -k | tail -200

last -x | head -20

What we’re looking for:



If the final lines before the abrupt end are igc / enp3s0 / link up-down events, the NIC is a strong pre-freeze lead.

If the NIC events only appear on the next boot, your “that was just after the repower” theory is very plausible.

If the final lines show EDAC, MCE, machine check, or memory-controller messages first, then the earlier memory concern moves back up the list.

On the memory issue:



Check these too:



journalctl -k | grep -Ei 'EDAC|MCE|machine check|IBECC|memory error'

dmesg -T | grep -Ei 'EDAC|MCE|machine check|IBECC|memory error'

grep . /sys/devices/system/edac/mc/mc\*/ce\_count 2>/dev/null

grep . /sys/devices/system/edac/mc/mc\*/ue\_count 2>/dev/null

That will tell us:



whether there were only correctable events

whether counts are increasing

whether memory errors were seen near the freeze window

For the app changes you listed, I can do them, but I need the actual codebase that contains:



the PC Stats graph

watchdog/reboot counters

the host/device details page

If you want, next I can do one of these:



Help you inspect the Linux logs and decide NIC-before-freeze vs post-repower.

Add a future-ready schema/spec for TeamViewer, alert counts, and better fault reporting in this relay repo.

Work on the real top-level app repo if you point me at it.

