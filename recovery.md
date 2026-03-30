

File
Edit
View
Window
Help
Add adaptive watchdog reset timer

va-connect-watchdog










+98
-11

I need a tool to monitor . attached is a chat i did with chatgpt. read it and recap. 

Watchdog that resets Ubuntu pc if no internet, need the timer to expand over time so it's not resetting all the time

You can implement this with a watchdog script that gradually increases the reset threshold when repeated failures occur. The idea:

The script periodically checks connectivity (e.g., ping a reliable host).

If the internet fails, it starts a timer.

Each time a reset happens, the next timeout becomes longer (back-off logic).

When connectivity is stable again, the timer resets to the default.

This prevents a machine from rebooting repeatedly during long outages.

Option 1 — Python Watchdog (recommended)

This version uses exponential back-off and logs activity.

Behaviour

Checks internet every 30 seconds

First reboot after 5 minutes offline

Next reboot after 10 min

Then 20 min

Max wait 60 minutes

Script: internet_watchdog.py
import subprocess
import time
import os
from datetime import datetime

CHECK_HOST = "8.8.8.8"
CHECK_INTERVAL = 30

BASE_TIMEOUT = 300        # 5 minutes
MAX_TIMEOUT = 3600        # 60 minutes
BACKOFF_MULTIPLIER = 2

timeout = BASE_TIMEOUT
offline_start = None


def log(msg):
    print(f"{datetime.now()} - {msg}")


def internet_ok():
    try:
        subprocess.check_output(
            ["ping", "-c", "1", "-W", "2", CHECK_HOST],
            stderr=subprocess.DEVNULL
        )
        return True
    except:
        return False


log("Internet watchdog started")

while True:

    if internet_ok():

        if offline_start:
            log("Internet restored. Resetting timers")

        offline_start = None
        timeout = BASE_TIMEOUT

    else:

        if offline_start is None:
            offline_start = time.time()
            log("Internet lost")

        elapsed = time.time() - offline_start

        if elapsed > timeout:
            log(f"No internet for {timeout} seconds. Rebooting.")

            os.system("sudo reboot")

            timeout = min(timeout * BACKOFF_MULTIPLIER, MAX_TIMEOUT)
            offline_start = time.time()

    time.sleep(CHECK_INTERVAL)
Run automatically on Ubuntu
Create service
sudo nano /etc/systemd/system/internet-watchdog.service
[Unit]
Description=Internet Watchdog

[Service]
ExecStart=/usr/bin/python3 /home/ubuntu/internet_watchdog.py
Restart=always

[Install]
WantedBy=multi-user.target

Enable it:

sudo systemctl daemon-reload
sudo systemctl enable internet-watchdog
sudo systemctl start internet-watchdog

Check status:

systemctl status internet-watchdog
Option 2 — Hardware watchdog (more reliable)

For industrial setups (similar to your remote CCTV / gateway deployments) a better design is:

Enable Linux hardware watchdog

Reset if system lockups occur

Combine with network script

Example:

sudo apt install watchdog
sudo nano /etc/watchdog.conf

Add:

ping = 8.8.8.8
interval = 30
realtime = yes
priority = 1

This uses /dev/watchdog so the kernel will reboot the system automatically if the daemon stops responding.

Practical Improvements (recommended)

For field devices such as routers / NVRs / gateways:

Check multiple hosts

8.8.8.8

1.1.1.1

Your VPN gateway or RMS server

Add route test

ip route get 8.8.8.8

Reset network first before reboot

systemctl restart NetworkManager

Only reboot if that fails.

If you want, I can also build a more advanced watchdog used in remote sites:

Features:

Expanding reboot timer

Network restart before reboot

Detect WAN vs LAN failure

Local web dashboard showing uptime and resets

JSON log file

Systemd installer

This is closer to what you might want for VA-Connect / remote gateway monitoring nodes.


The chat outlines a watchdog idea for an Ubuntu PC that reboots only after internet loss persists, and uses a growing timeout so it does not keep resetting during long outages.

The main proposal is a Python script that:

checks connectivity every 30 seconds by pinging 8.8.8.8
starts with a 5 minute offline timeout
reboots if the machine stays offline past that timeout
doubles the timeout after each reboot to reduce reset frequency
caps the wait at 60 minutes
resets back to the 5 minute baseline once internet is stable again
It also suggests running that script as a systemd service so it starts automatically on Ubuntu.

A second option mentioned is using the Linux hardware watchdog for better reliability, especially for remote or industrial-style deployments. That would let the kernel force a reboot if the watchdog process stops responding, and it can be combined with the network-check script.

The “practical improvements” section recommends making it smarter by:

checking multiple hosts instead of just one
testing routing as well as ping
trying a network service restart before doing a full reboot
distinguishing WAN failure from LAN failure
The chat ends by suggesting a more advanced watchdog for field devices, with extras like an expanding reboot timer, network restart before reboot, LAN/WAN detection, a local dashboard, JSON logs, and a systemd installer.

If you want, I can turn that recap into an actual working Ubuntu watchdog tool in this workspace next.



Ellingers.csv
Would that do the job? I had another unit go offline last night (Attached is the log file) 
The connected rut was working fine so its comms to the from the rut is ok, I couldnt remot connect via teamview but when i reset the pc (Remotley with a gsm reply ) and the system was contactable after the restart. 

I need some way of tracking the faults, logging the issues and working out why the system is hanging (If thats what is happening).

Issues.

I dont have access to this locally as its Trackside on network rail so all fault findings need to be done remotly.



8 previous messages
No, the original “reboot if no internet” idea by itself would not fully cover what happened last night.

The log you attached at logfile.log shows repeated RTSP connection failures to 192.168.1.132 with connect error 107, plus periodic rtsp timeout / cmd_abort entries. That suggests the PC and app were still alive enough to keep retrying, so this does not look like a simple total internet outage. Given the RUT stayed up, but TeamViewer access only came back after a reboot, the likely fault space is closer to:

VA-Connect hung or partially hung
local network stack / routing issue on the PC
LAN-side device path issue to 192.168.1.132
remote-access service degraded while the OS was still partly alive
I’ve added a stronger remote-site watchdog to the repo:

va_connect_site_watchdog.py
site-watchdog.json.example
va-connect-site-watchdog.service
updated installer/docs in install_watchdog.sh and ubuntu_va_connect_watchdog.md
This version does what you actually need for a trackside box:

checks WAN against multiple public hosts
checks LAN/TCP targets like the RUT and RTSP device
checks the VA-Connect process
captures evidence snapshots when a fault starts or changes
logs structured events to JSONL for later review
tries app restart, then network restart, then reboot
expands the reboot timer after repeated failures so it does not flap constantly
The evidence capture is the key part for you, because all fault finding has to be remote. On the Ubuntu box it will leave:

/var/log/va-connect-site-watchdog/events.jsonl
/var/log/va-connect-site-watchdog/snapshots/
/var/lib/va-connect-site-watchdog/state.json
Those snapshots include ip addr, ip route, resolver state, memory, disk, top processes, recent system journal, network journal, and TeamViewer journal if present. That should give us a much better chance of separating “internet down” from “PC alive but app/network stack unhappy”.

I couldn’t run a local Python syntax check in this Windows workspace because there’s no Python installed here, so the code still needs its first real test on the Ubuntu target.

If you want, the next step is for me to tailor the JSON config for your actual site layout: RUT IP, VA-Connect process name/start command, and the exact local device IPs you want monitored.


can we have this as a web gui on the va-connect encoder? (This is the name of the pc on site we use for future refrance)
We could then enable and disable the setting from it. 




8 previous messages
Yes. I’ve added a simple web GUI for the VA-Connect encoder so you can control the watchdog from the box itself.

The main pieces are:

va_connect_watchdog_web.py
va-connect-watchdog-web.service
updated watchdog logic in va_connect_site_watchdog.py
updated install/config/docs in install_watchdog.sh, site-watchdog.json.example, and ubuntu_va_connect_watchdog.md
What the GUI gives you on the encoder:

live view of last WAN, LAN, and app checks
recent watchdog events
toggles for monitoring_enabled, app_restart_enabled, restart_network_before_reboot, and reboot_enabled
buttons for manual check, snapshot, and network restart
By default it will be on:

http://<encoder-ip>:8787/
If you set web_token in the JSON config, use:

http://<encoder-ip>:8787/?token=your-token
One important limitation: I couldn’t run a real Python syntax test in this Windows workspace because Python isn’t installed here, so this still needs its first live test on the Ubuntu encoder. The design is there, though, and the watchdog now reloads its config each cycle so changes from the web page actually take effect.

If you want, next I can tailor the site-watchdog.json for your actual VA-Connect encoder site, including the real RUT IP, TeamViewer expectations, and the specific stream/device IPs you want shown in the GUI.


can we add that that webpage for config?



5 previous messages
Yes. The web page now includes a proper config section, not just enable/disable switches.

You can now edit from the VA-Connect encoder UI:

app match text
app start command
internet hosts
TCP targets as host:port
check interval
reboot timers and backoff
network restart cooldown
web bind / port / token
network restart command
The main change is in va_connect_watchdog_web.py, and I updated the docs in ubuntu_va_connect_watchdog.md.

One thing to note: I still haven’t been able to run a real Python test in this Windows workspace because Python isn’t installed here, so the next step is to deploy it on the Ubuntu VA-Connect encoder and verify the page live at http://<encoder-ip>:8787/.

If you want, I can do the next pass and pre-fill the page defaults for your actual encoder layout and device IPs.


i can do that,  how to deploy it?


Deploy it onto the Ubuntu VA-Connect encoder like this.

Copy the project folder to the encoder, for example into /opt or your home folder, then run the installer:

cd /path/to/va-connect-watchdog
sudo ./tools/ubuntu/install_watchdog.sh
That installs:

the basic process watchdog
the site watchdog
the web UI
the systemd services
Then edit the main config file:

sudo nano /opt/va-connect-watchdog/site-watchdog.json
Set the real values for your site:

app_match
app_start_command
internet_hosts
tcp_targets
timers and backoff
optional web_token
If you also want the simple process watchdog, edit:

sudo nano /opt/va-connect-watchdog/va-connect.env
Start or enable everything:

sudo systemctl daemon-reload
sudo systemctl enable --now va-connect-watchdog.timer
sudo systemctl enable --now va-connect-site-watchdog.service
sudo systemctl enable --now va-connect-watchdog-web.service
Check status:

systemctl status va-connect-watchdog.timer
systemctl status va-connect-site-watchdog.service
systemctl status va-connect-watchdog-web.service
journalctl -u va-connect-site-watchdog.service -n 50 --no-pager
journalctl -u va-connect-watchdog-web.service -n 50 --no-pager
Open the web page from your remote machine:

http://<encoder-ip>:8787/
If you set a token:

http://<encoder-ip>:8787/?token=your-token
Useful log locations on the encoder:

/var/log/va-connect-site-watchdog/events.jsonl
/var/log/va-connect-site-watchdog/snapshots/
/var/lib/va-connect-site-watchdog/state.json
The deployment notes are in ubuntu_va_connect_watchdog.md, and the installer is install_watchdog.sh.

If you want, I can also give you a ready-to-paste site-watchdog.json template for the VA-Connect encoder.


I will put the folder on the desktop for new to test, can you edit everything to match this?


I can, but I need one concrete detail first: what should “this” map to on the Ubuntu box?

If you mean “assume the project folder will be on the Desktop of the VA-Connect encoder user”, send me:

the Linux username
the exact Desktop path if it isn’t /home/<user>/Desktop/va-connect-watchdog
the real app_match
the real app_start_command
the IPs/ports you want preloaded in tcp_targets
If you want, paste those 4 items and I’ll edit the config template, installer notes, and docs to match that exact setup.


User attachment
what do I need to show, I have opened terminal in the folder 


Please run these on the VA-Connect encoder and paste the output:

pwd
whoami
hostname
ls -la
Then these so I can prefill the watchdog correctly:

ps -ef | grep -i va-connect
ps -ef | grep -i teamviewer
ip addr
ip route
If you already know the device IPs you want monitored, paste those too:

RUT IP
camera / RTSP device IP
any other local target IPs
If VA-Connect is started by a script or desktop launcher, also show me whichever of these exists:

ls -la ~/Desktop
ls -la ~/Desktop/*.desktop
ls -la ~/Desktop/*.sh
That’ll be enough for me to tell you exactly what to edit.







GPT-5.4

Medium



Local

Full access

master
Terminal
PowerShell

