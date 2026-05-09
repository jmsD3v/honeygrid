"""
Fake filesystem responses for SSH honeypot.

Simulates a realistic Debian 12 server to keep attackers engaged long enough
to capture their full TTPs. All commands return plausible fake output.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

_HOSTNAME = "prod-srv-01"
_USERNAME = "root"
_UNAME = "Linux prod-srv-01 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux"
_DISTRO = "Debian GNU/Linux 12 (bookworm)"

_FAKE_PROCESSES = """  PID TTY          TIME CMD
    1 ?        00:00:03 systemd
  425 ?        00:00:00 sshd
  812 ?        00:00:01 nginx
  891 ?        00:00:00 postgres
  923 ?        00:00:00 mysqld
 1234 pts/0    00:00:00 bash
 1235 pts/0    00:00:00 ps"""

_FAKE_IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0"""

_FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:112:118:MySQL Server:/nonexistent:/bin/false
postgres:x:113:119:PostgreSQL:/var/lib/postgresql:/bin/bash
deploy:x:1000:1000::/home/deploy:/bin/bash"""

_FAKE_SHADOW = """root:$6$random$hashedpassword123:19000:0:99999:7:::
deploy:$6$random$hashedpassword456:19000:0:99999:7:::"""

_FAKE_HISTORY = """ls -la
cd /var/www/html
cat /etc/passwd
netstat -tulpn
ps aux
wget http://example.com/file.sh
chmod +x file.sh
./file.sh"""

_FAKE_CRONTAB = """# m h dom mon dow command
0 * * * * /usr/bin/certbot renew --quiet
*/5 * * * * /opt/scripts/backup.sh
0 2 * * * /usr/local/bin/db_backup.sh"""

_FAKE_ENV = """PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
SHELL=/bin/bash
USER=root
LOGNAME=root
TERM=xterm-256color
LANG=en_US.UTF-8"""

_FAKE_NETSTAT = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      425/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      812/nginx
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      812/nginx
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      891/postgres
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      923/mysqld"""

_FAKE_LSBLK = """NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda      8:0    0   20G  0 disk
|-sda1   8:1    0  512M  0 part /boot/efi
|-sda2   8:2    0    1G  0 part /boot
`-sda3   8:3    0 18.5G  0 part /"""

_FAKE_FREE = """              total        used        free      shared  buff/cache   available
Mem:        4048036     1234567     1456789       12345     1234567     2456789
Swap:       2097148           0     2097148"""

_FAKE_CPUINFO = """processor       : 0
vendor_id       : GenuineIntel
model name      : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
cpu MHz         : 2400.000
cache size      : 30720 KB
cpu cores       : 2"""

_DOWNLOADS_IN_PROGRESS: list[str] = []


def _now_prompt() -> str:
    return f"root@{_HOSTNAME}:~#"


def fake_response(command: str) -> str:
    """Return a realistic fake response for a given shell command."""
    cmd = command.strip()
    parts = cmd.split()
    if not parts:
        return ""
    base = parts[0]

    # whoami / id
    if base in ("whoami",):
        return "root"
    if base == "id":
        return "uid=0(root) gid=0(root) groups=0(root)"

    # hostname / uname
    if base == "hostname":
        return _HOSTNAME
    if base == "uname":
        if "-a" in parts or "-r" in parts:
            return _UNAME
        return "Linux"

    # ls
    if base == "ls":
        if any(p in ("/etc", "/etc/") for p in parts):
            return "passwd  shadow  hosts  hostname  crontab  nginx  mysql  ssh  ssl"
        if "/root" in parts or "~" in parts:
            return ".bash_history  .bashrc  .ssh  backup.tar.gz  flag.txt"
        # default ls
        path = parts[-1] if len(parts) > 1 and not parts[-1].startswith("-") else "."
        return ".bash_history  .bashrc  .ssh  snap  flag.txt  secret.db"

    # cat
    if base == "cat":
        target = parts[-1] if len(parts) > 1 else ""
        if "passwd" in target:
            return _FAKE_PASSWD
        if "shadow" in target:
            return _FAKE_SHADOW
        if "history" in target or ".bash_history" in target:
            return _FAKE_HISTORY
        if "crontab" in target or "/etc/cron" in target:
            return _FAKE_CRONTAB
        if "flag" in target:
            return "HG{fake_flag_capture_recorded_" + str(random.randint(10000, 99999)) + "}"
        if "hostname" in target:
            return _HOSTNAME
        if "os-release" in target or "issue" in target:
            return _DISTRO
        return ""

    # ps
    if base == "ps":
        return _FAKE_PROCESSES

    # ifconfig / ip
    if base in ("ifconfig", "ip"):
        return _FAKE_IFCONFIG

    # env / printenv
    if base in ("env", "printenv"):
        return _FAKE_ENV

    # netstat / ss
    if base in ("netstat", "ss"):
        return _FAKE_NETSTAT

    # free
    if base == "free":
        return _FAKE_FREE

    # df
    if base == "df":
        return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda3        19G  8.2G  9.8G  46% /"

    # lsblk
    if base == "lsblk":
        return _FAKE_LSBLK

    # pwd
    if base == "pwd":
        return "/root"

    # history
    if base == "history":
        return "\n".join(f"  {i+1}  {c}" for i, c in enumerate(_FAKE_HISTORY.splitlines()))

    # wget / curl — simulate download attempt
    if base in ("wget", "curl"):
        url = next((p for p in parts if p.startswith("http")), "unknown")
        _DOWNLOADS_IN_PROGRESS.append(url)
        return f"--{datetime.now(timezone.utc).strftime('%H:%M:%S')}-- {url}\nConnecting to ... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 4096 (4.0K)\nSaving to: '{url.split('/')[-1]}'\n100%[======================================>] 4,096  --.-K/s  in 0s"

    # chmod / chown
    if base in ("chmod", "chown"):
        return ""

    # ./script or sh/bash/python execution
    if base.startswith("./") or base in ("sh", "bash", "python", "python3", "perl", "ruby"):
        return f"-bash: {parts[-1]}: Permission denied"

    # which
    if base == "which":
        target = parts[-1] if len(parts) > 1 else ""
        paths = {"python": "/usr/bin/python3", "python3": "/usr/bin/python3",
                 "wget": "/usr/bin/wget", "curl": "/usr/bin/curl",
                 "nc": "/usr/bin/nc", "netcat": "/usr/bin/nc",
                 "nmap": "/usr/bin/nmap", "gcc": "/usr/bin/gcc"}
        return paths.get(target, f"which: no {target} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin)")

    # find
    if base == "find":
        return "/etc/passwd\n/etc/shadow\n/root/.bash_history\n/root/.ssh/authorized_keys"

    # uptime
    if base == "uptime":
        return f" {datetime.now(timezone.utc).strftime('%H:%M:%S')} up 42 days, 7:15, 1 user, load average: 0.01, 0.05, 0.01"

    # w / who
    if base in ("w", "who"):
        return f"root     pts/0        {datetime.now(timezone.utc).strftime('%H:%M')}   0.00s  0.04s  0.00s w"

    # crontab
    if base == "crontab":
        if "-l" in parts:
            return _FAKE_CRONTAB
        return ""

    # mkdir / touch / rm / cp / mv — succeed silently
    if base in ("mkdir", "touch", "rm", "cp", "mv", "ln", "echo", "export", "cd", "unset"):
        return ""

    # systemctl
    if base == "systemctl":
        return "Unit nginx.service could not be found." if "stop" in parts else "active (running)"

    # iptables / ufw — deny modification
    if base in ("iptables", "ufw", "firewall-cmd"):
        return f"-bash: {base}: command not found"

    # adduser / useradd
    if base in ("adduser", "useradd"):
        return f"adduser: The user `{parts[-1]}' already exists."

    # nc / netcat — dangerous, fake busy
    if base in ("nc", "netcat", "ncat"):
        return ""  # Hang silently — attacker thinks it's working

    # default — command not found
    return f"-bash: {base}: command not found"
