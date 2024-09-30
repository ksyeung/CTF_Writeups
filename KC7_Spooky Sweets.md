https://kc7cyber.com/challenges/104

# Section 0
## Question 2

How many employees are in the company?

---

```
Employees
| count
```

## Question 3

Each employee at Spooky Sweets Candy Company is assigned an IP address. Which employee has the IP address: “10.10.0.251”?

---

```
Employees
| where ip_addr == '10.10.0.251'
| project name
```

## Question 4

How many emails did Timothy Moran receive?

---

```
let addr = Employees
| where name contains 'Timothy Moran'
| project email = email_addr;
Email
| join kind=inner (addr) on $left.recipient == $right.email;
```

## Question 5

How many distinct senders were seen in the email logs from spoopycandysupplies.com?

---

```
Email
| where sender contains 'spoopycandysupplies.com'
| distinct sender
| count;
```

## Question 6

How many unique websites did “Michael Dawson” visit?

---

Initially, I started with this query, which didn't feel like a streamlined solution but did work:
```
let ip = Employees
| where name == 'Michael Dawson'
| project ip_addr;
OutboundNetworkEvents
| join kind=inner (ip) on $left.src_ip == $right.ip_addr
| distinct url
```

I did some searching, and found the toscalar() function https://learn.microsoft.com/en-us/kusto/query/toscalar-function, which retrieves a single value. This makes it easier to assign to the 'ip' variable for use:

```
let ip = toscalar(Employees | where name == 'Michael Dawson' | project ip_addr);
OutboundNetworkEvents
| where src_ip == ip
| distinct url
```

## Question 7

How many domains in the PassiveDns records contain the word “Halloween”? (hint: use the contains operator instead of has. If you get stuck, do a take 10 on the table to see what fields are available.)

---

```
PassiveDns
| where domain contains "halloween"
| count
```

## Question 8

What IPs did the domain “halloween-infrastructure.com” resolve to (enter any one of them)?

---

```
PassiveDns
| where domain == 'halloween-infrastructure.com'
| project ip;
```

## Question 9

How many unique URLs were browsed by employees named “Karen”?

---

```
let karen_ips = Employees
| where name contains 'Karen'
| project ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ips)
| distinct url;
```

# Section 1

## Question 1

Oh no! A bunch of computers had their wallpapers changed. Your IT was able to grab a copy of one of them, but it seems that it slightly changes each time it's on a computer. You can download the file here: [Download](https://github.com/KC7-Foundation/kc7_data/blob/main/SpookySweets/spooky.png?raw=true). What is the name of the file?

---

spooky.png

## Question 2

Let's search for this file. How many hosts have this file?

---

```
FileCreationEvents
| where filename == 'spooky.png'
| distinct hostname
| count;
```
## Question 3

What folder is this file found in?

---

```
FileCreationEvents
| where filename == 'spooky.png'
| project path
| distinct path;
```

## Question 4

When was the first wallpaper created?

---

```
FileCreationEvents
| where filename == 'spooky.png'
| order by timestamp asc
| take 1
| project timestamp;
```

## Question 5

What is the SHA256 of that file?

---

```
FileCreationEvents
| where filename == 'spooky.png'
| order by timestamp asc
| take 1
| project sha256;
```

## Question 6

Let's look at the host where the first wallpaper was created. What is the role of the employee that uses this computer?

---

```
let host = toscalar(FileCreationEvents | where filename == 'spooky.png' | order by timestamp asc | take 1 | project hostname);
Employees
| where hostname == host
| project role;
```

## Question 7

The threat actor must have left something behind to show how they set the wallpaper. What time did they set the wallpaper on this host?

---

```
ProcessEvents
| where hostname == 'KQQT-DESKTOP'
| where process_commandline contains 'spooky.png'
| project timestamp
```

## Question 8

What command did they run to update the host system to the new wallpaper?

---

Given the timestamp from the last query, I reviewed all the commands that immediately followed:

```
ProcessEvents
| where hostname == 'KQQT-DESKTOP'
| where timestamp > datetime(2023-10-09T04:18:46Z);
```

## Question 9

It was reported that around the same time the wallpapers changed, a lot of people got an email about mandatory training they had to do. **How long was this video? Provide the format in MM:SS (ex. 12:34).**

---

```
Email
| where subject contains 'training'
| project link;
```

### Question 10

All of these training emails were sent to employees with the same role. Which job role received the email?

---

```
let recipients = Email
| where subject contains 'training'
| project recipient;
Employees
| where email_addr in (recipients)
| project role;
```

## Question 11

Let's see if the threat actor reached out to targets via email in the past. How many emails have subject lines with the hacker group's name in them?

---

```
Email
| where subject contains 'pumpkin patch pirates'
| count
```

## Question 12

Most of those emails were sent from which email address?

---

```
Email
| where subject contains 'pumpkin patch pirates'
```

Question 13

Which of the links in those emails contains an important file?

---

See above.

## Question 14

What IP does the domain from that link resolve to?

```
PassiveDns
| where domain == 'spooky-fall.com'
| project ip
```

## Question 15

When did that IP visit the Spooky Sweets website?

```
InboundNetworkEvents
| where src_ip == '141.107.162.16'
| project timestamp
```

## Question 16

The activity from Q15 demonstrates which MITRE ATT&CK technique?

---


## Question 17

Hey!! The IT folks said to stop what you're doing and investigate another set of emails they got around the same time wallpapers were changed. Within the link, what is the wisdom they impart?

---

First, I looked up emails for IT employees:

```
Employees
| where role == 'IT Specialist'
```

Then, using an email address for a random employee, I reviewed their messages:

```
Email
| where recipient == 'della_bergman@spookysweets.xyz'
| where timestamp > datetime(2023-10-09T04:18:46Z);
```

I watched the YouTube video in order to learn the answer.

## Question 18

… Let's go back to our email investigation. Looking at the phishing emails sent by the adversary, which number will surprise us?

---

First, I ran this query:

```
Email
| where sender == 'boo.boo@hotmail.com'
```

This didn't produce any unusual results, and the number of emails wasn't the expected answer. I added another conditional, which produced the answer:

```
Email
| where sender == 'boo.boo@hotmail.com' or reply_to == 'boo.boo@hotmail.com'
```

## Question 19

What's the name of the excel document they sent?

---

See above query.

## Question 20

Some time after the initial emails they sent follow up emails to gather more information. What domain did the senders come from?

---

I grabbed a timestamp and recipient email address from a row at random, and reviewed their messages shortly after the timestamp:

```
Email
| where timestamp > datetime(2023-10-05T09:59:46Z)
| where recipient == 'susie_warrington@spookysweets.xyz'
```

## Question 21

Hmm, that's really weird. What was the subject?

---


## Question 22

Several employees clicked on the link and got compromised. When the attackers got access to those employees' machines, they decided to move laterally. What command was used to dump credentials on several hosts?

---

To find out who clicked the link, I checked to see who downloaded it:

```
FileCreationEvents
| where filename contains 'final_notice.xlsx'
```

Using a hostname and timestamp from the results, I examined the process events log immediately following the download:

```
ProcessEvents
| where hostname == 'UK0S-MACHINE'
| where timestamp > datetime(2023-10-04T09:29:38Z)
| order by timestamp asc
| take 3
```

| Timestamp            | Parent Process Name | Parent Process Hash                                              | Process Commandline                     | Process Name | Process Hash                                                     | Hostname     | Username |
| -------------------- | ------------------- | ---------------------------------------------------------------- | --------------------------------------- | ------------ | ---------------------------------------------------------------- | ------------ | -------- |
| 2023-10-04T09:32:46Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | systeminfo                              | cmd.exe      | f72cc36bdd5d1675e14d54193f5617153bc4849c195c65e024a59ef9fc7b03cf | UK0S-MACHINE | alkelley |
| 2023-10-04T09:44:11Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | mimikatz.exe "sekurlsa::logonpasswords" | mimikatz.exe | 8c7073475ccc384aa7bb13d766160ce9067a6c8c399494fbbd6887313f909bdb | UK0S-MACHINE | alkelley |
| 2023-10-04T09:52:26Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | netstat -ano                            | cmd.exe      | ce8c4cf3a826b64f6bd03d3eb6d13f82348732fc57e58d2cdfe2fc1dbda41584 | UK0S-MACHINE | alkelley |

## Question 23

What is the MITRE ATT&CK ID of this tool?

---

I did a search on the MITRE site: https://attack.mitre.org/software/S0002/

## Question 24

What command was used to look at all of the computers within a domain?

---

I expanded the query used to answer question 22 with 'take 10':

```
ProcessEvents
| where hostname == 'UK0S-MACHINE'
| where timestamp > datetime(2023-10-04T09:29:38Z)
| order by timestamp asc
| take 15
```

## Question 25

When was the first time this command was executed?

---

```
ProcessEvents
| where process_commandline == 'net view /all /domain'
| order by timestamp asc
| take 1
```

| Timestamp            | Parent Process Name | Parent Process Hash                                              | Process Commandline   | Process Name | Process Hash                                                     | Hostname     | Username   |
| -------------------- | ------------------- | ---------------------------------------------------------------- | --------------------- | ------------ | ---------------------------------------------------------------- | ------------ | ---------- |
| 2023-10-02T11:55:34Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | net view /all /domain | cmd.exe      | 3b3386ff64e012e12adfb533dc3f9a9137119bbb2f896cdbdc8a540a29bd6e4a | TQ3G-DESKTOP | sccrissman |

## Question 26

Who is the user of that host? Provide the full name.

---


## Question 27

What command used by the threat actor was used to look for information about services?

---

Review the results of the query in question 24.

## Question 28

What is the MITRE ATT&CK ID for this type of technique?

---

I used the command (wrapped in quotes) and added the "MITRE" keyword in a Google query, and found the answer in the first result.

## Question 29

It was reported that Carlton Toth had a significant security alert. Look for what the alert is. What file was alerted?

---

```
let host = toscalar(Employees | where name == "Carlton Toth" | project hostname);
SecurityAlerts
| where description contains host;
```

| Timestamp            | Alert Type | Severity | Description                                                                                                                                       | Indicators                                                                                                                           |
| -------------------- | ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| 2023-10-02T09:13:33Z | HOST       | High     | A suspicious file was detected on host P7DJ-LAPTOP. Filename: treat.ps1. Sha256: 5ca8e69c92fd1ae4bef806b97ff7dd301c2efc3a962c6229057ebfc26a034eed | [{'hostname': 'P7DJ-LAPTOP', 'sha256': '5ca8e69c92fd1ae4bef806b97ff7dd301c2efc3a962c6229057ebfc26a034eed', 'filename': 'treat.ps1'}] |

## Question 30

Let's investigate that file path across all of the hosts. How many other files were found in that directory?

---

 First, I extracted the path:

```
FileCreationEvents 
| where hostname == 'P7DJ-LAPTOP' 
| where filename == 'treat.ps1' 
| project parse_path(path).DirectoryPath
```

I added it to a variable in order to search for it:

```
let directory_path = toscalar(
    FileCreationEvents
    | where hostname == 'P7DJ-LAPTOP'
    | where filename == 'treat.ps1'
    | project parse_path(path).DirectoryPath
);
FileCreationEvents
| where path contains directory_path
| distinct path
| count
```

## Question 31

Which file was executed through a network share?

---

I searched for 'cmd.exe' execution:

```
ProcessEvents
| where process_commandline contains 'cmd.exe'
| distinct process_commandline
```

# Question 32

Which other file was executed?

---

I reviewed the results of this query:

```
ProcessEvents
| where process_commandline contains 'powershell.exe'
| distinct process_commandline
```

## Question 33

Which executive management role had some of these files on their host?

---

I reviewed the results of this query to find the answer:

```
let hosts = FileCreationEvents
| where filename == 'ded.ps1' or filename == 'trick.ps1'
| project hostname;
Employees
| where hostname in (hosts)
| project name, role;
```

## Question 34

How many distinct job roles had these files in that directory?

---

```
let users = FileCreationEvents
| where path contains @'C:\PerfLogs\'
| project username;
Employees
| where username in (users)
| distinct role;
```

## Question 35

What is the SHA256 hash of the wallpaper from Section 1, Q1?

---

I was a bit confused by the question at first: after all, the wording from Q1 specifically indicates the wallpaper changes slightly on each computer, which would in turn result in a different hash. I confirmed this was accurate with a quick check:

```
FileCreationEvents
| where filename == 'spooky.png'
```

After some consideration, I downloaded the wallpaper using the given URL, then obtained the hash with the macOS sha256sum utility in Terminal:

```
sha256sum spooky.jpg
```

## Question 36

It doesn't seem to be the same file extension it's saying it is. What type of file is it?

---

The file extension indicates it is a jpeg file, which is different than the png file extension it has in the SpookySweets network. Just to double check in Terminal, I ran:

```
file spooky.jpg
```

Which produced the output:

```
spooky.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 216x216, segment length 16, baseline, precision 8, 1179x878, components 3
```

## Question 37

It looks like the threat actor tried different filenames. What was the first one?

---


## Question 38

Let's go back and double check. What other picture did the threat actor drop on the systems?

---

Reviewing the file creation events to see when the image was dropped:

```
FileCreationEvents
| where path contains @'C:\Users\Public\Pictures\'
| take 1
```

Grabbing the username and timestamp for another query to see what happened afterwards:

```
FileCreationEvents
| where username == 'rojoyner' and timestamp > datetime(2023-10-09T02:00:41Z)
```

## Question 39

The CEO of the company sat everyone down during the all hands meeting and said it was all a test. What type of group would conduct these types of tests?

---
Red team
