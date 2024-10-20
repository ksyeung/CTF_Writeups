https://kc7cyber.com/challenges/26

# Section 1

## Question 1

Now that we have familiarized ourselves to some of the data, we'll need to get a lay of the land. Let's figure out the scale of our company so we have a better understanding of what we're protecting at Balloons Over Iowa. How many employees are in the company?

---

```
Employees
| count
```

## Question 2

Each employee at BallonsOverIowa is assigned an IP address. Which employee has the IP address: “192.168.2.191”?

---

```
Employees
| where ip_addr == "192.168.2.191"
```

## Question 3

We can learn more about 'Ronald Walker' using information from other tables. Let's take his email address from the Employees table and use it in a query for the Email table. How many emails did Ronald Walker receive?

---

```
Email
| where recipient == "ronald_walker@iowaballoons.com"
| count
```

## Question 4

You can use the distinct operator to find unique values in a specific column. You can also string together multiple where operators to help narrow down on the results. How many Balloons Over Iowa employees received emails with the term "ufos" in the subject?

---

```
Email
| where subject has "ufos"
| where recipient has "iowaballoons"
| distinct recipient
```

## Question 4

How many unique websites did Jorge Hardwick visit?

---

```
let jorges_ip = toscalar(Employees
| where name contains "Jorge Hardwick"
| project ip_addr);
OutboundNetworkEvents
| where src_ip == jorges_ip
| distinct url
| count;
```

## Question 5

How many distinct domains in the PassiveDns records contain the word “infiltrate”?

---

```
PassiveDns
| where domain contains "infiltrate"
| distinct domain
| count;
```

## Question 6

What IP did the domain cheeseburger-infiltrate.com resolve to on February 8th?  

---

```
PassiveDns
| where domain contains "cheeseburger-infiltrate.com"
| where timestamp between (datetime(2023-02-08) .. datetime(2023-02-08 23:59:59))
| project ip;
```

## Question 7

How many distinct URLs were browsed by employees with the first name Karen?

---

```
let karen_ips =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ips)
| distinct url
| count
```

# Section 2

## Question 1

One of the senior SOC analysts is asking us to investigate a possible lead on some suspicious email activity. Which email address sent a message containing the domain invasion.xyz?

---

```
Email
| where link contains "invasion.xyz"
| project sender;
```

## Question 2

It just looks like spam mail from initial inspection. 🤔 We should continue to investigate to be sure. How many users received email with links to the domain invasion.xyz?

---

```
Email
| where link contains "invasion.xyz"
| distinct recipient
| count;
```

## Question 3

What was the subject of those emails?

---

```
Email
| where link contains "invasion.xyz"
| project subject;
```

## Question 4

For most of these email, it looks like our email security appliance fell asleep let them in. But at least it was able to block one of them. 🤷🏾‍♂️ What is the email address of the person that did not receive the emails? (where accept was false)

---

```
Email
| where link contains "invasion.xyz"
| where accepted == false
| project recipient;
```

## Question 5

What file (name) was sent as a link in these emails?

---

```
let url = toscalar(Email
| where link contains "invasion.xyz"
| where accepted == false
| project link);
let result = parse_path(url).Filename;
print result;
```

## Question 6

Upon closer inspection, we were able to see that the link provided is a direct download link. This could be serious trouble if the right precautions were not taken. We should check to see if anyone clicked on the link. What is the IP of the user who clicked on the link from the email containing the domain invasion.xyz?

---

```
let sus_url = toscalar(Email
| where link contains "invasion.xyz"
| where accepted == false
| project link);
OutboundNetworkEvents
| where url == sus_url
| project src_ip;
```

## Question 7

What is the name of the user from question 6?

---

```
let sus_url = toscalar(Email
| where link contains "invasion.xyz"
| where accepted == false
| project link);
let employee_ip = toscalar(OutboundNetworkEvents
| where url == sus_url
| project src_ip);
Employees
| where ip_addr == employee_ip
| project name;
```

## Question 8

When did the user in question 6 click on the link? Provide an exact timestamp.

---

```
let sus_url = toscalar(Email
| where link contains "invasion.xyz"
| where accepted == false
| project link);
let click_time = toscalar(OutboundNetworkEvents
| where url == sus_url
| project timestamp);
print click_time
```

## Question 9

What is the hostname of the user in question 6?

---

```
let sus_url = toscalar(Email
| where link contains "invasion.xyz"
| where accepted == false
| project link);
let employee_ip = toscalar(OutboundNetworkEvents
| where url == sus_url
| project src_ip);
Employees
| where ip_addr == employee_ip
| project hostname;
```

## Question 10

Did the user in question 6 download the file from the link? (yes/no)

---

See above queries.

## Question 11

Nice! It looks like they did not fall for the email, but that is not the end of our investigation. We should go back to make sure we did not leave any stones unturned. How many total emails were sent by the email address in question 1?

---

```
Email
| where sender == "tethys@pocketbook.xyz"
| count;
```

## Question 12

That is quite a bit of emails sent from this email address. How many unique filenames were sent by the email address in question 1?

---

```
Email
| where sender == "tethys@pocketbook.xyz"
| distinct link
| extend parsed_link = tostring(parse_path(link).Filename)
| distinct parsed_link;
```

## Question 13

During your lunch break, one employee, Richard Clements, mentions out loud by the water cooler that some important files are missing from his PC.🥶 You remember that prior to your break, you saw his name within the list of employees who received an email in question 1. What domain did the email address in question 1 use to target Richard Clements?

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_url(link).Host;
```

## Question 14

Your suspicions were true and it looks like he clicked on the link. When did Richard Clements click on the link sent by the sender in question 1?

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_ip = toscalar(Employees
| where name == "Richard Clements"
| project ip_addr);
let clicked = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project link);
OutboundNetworkEvents
| where src_ip == richards_ip
| where url == clicked
| project timestamp;
```

## Question 15

Not only did Richard click on the link, it looks like he also downloaded the file attached to it! When did Richard Clements download the file in the link?

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
FileCreationEvents
| where hostname == richards_hostname
| where filename == downloaded
| project timestamp;
```

## Question 16

You notice that the email sent to Richard has the same subject, but contains a very different link compared to what you saw sent to Eugene. What was the name of the file that Richard Clements downloaded after clicking on the link?

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
print downloaded
```

## Question 17

Now that we know the file was downloaded, we should further investigate Richard's PC to see what damage has been done. What file was observed on Richard Clement's machine immediately after he downloaded the file in question 16? Provide the full path.

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
let dl_timestamp = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where filename == downloaded
| project timestamp);
FileCreationEvents
| where hostname == richards_hostname
| where timestamp > dl_timestamp
| order by timestamp asc
| take 1
| project path;
```

## Question 18

We should gather additional information to help us determine what we're dealing with. OSINT (Open Source Intelligence) that is! What was the SHA256 hash of the file in question 17?

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
let dl_timestamp = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where filename == downloaded
| project timestamp);
FileCreationEvents
| where hostname == richards_hostname
| where timestamp > dl_timestamp
| order by timestamp asc
| take 1
| project sha256;
```

### Question 19

The hash in question 18 can be found on virustotal.com. VirusTotal is a malware repository used by many security researchers. 🕵️‍♂️ Don't worry, it's totally safe! What is the reported name of this file on VirusTotal?

---

https://www.virustotal.com/gui/file/3666cb55d0c4974bfee855ba43d596fc6d10baff5eb45ac8b6432a7d604cb8e9

## Question 20

What is the popular threat label for the file in question 18 on VirusTotal?

---

See above.

## Question 21

---

The file in question 18 established a remote connection from Richard Clement's machine to an external IP over port 443. 🪲 What was this IP?

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
let dl_timestamp = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where filename == downloaded
| project timestamp);
let sus_filename = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where timestamp > dl_timestamp
| order by timestamp asc
| take 1
| project filename);
ProcessEvents
| where hostname == richards_hostname
| where parent_process_name == sus_filename;
```

## Question 22

The file in question 18 established a remote connection from Richard Clement's machine to an external IP over port 443. 🪲 What was this IP?

---

See the results of above query.

## Question 23

Shortly after the malware ran, the attackers came back to Richard's machine to enumerate Enterprise Admins. What command did they run?

---

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
let dl_timestamp = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where filename == downloaded
| project timestamp);
let sus_filename = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where timestamp > dl_timestamp
| order by timestamp asc
| take 1
| project filename);
let cmd_exec_timestamp = toscalar(ProcessEvents
| where hostname == richards_hostname
| where parent_process_name == sus_filename
| project timestamp
| take 1);
ProcessEvents
| where hostname == richards_hostname
| where timestamp > cmd_exec_timestamp
| where process_commandline contains "Enterprise Admins";
```

## Question 24

What command did the attackers run to dump credentials on Richard's machine?

---

Reviewing the results from this query, we find the answer:

```
let richards_email = toscalar(Employees
| where name == "Richard Clements"
| project email_addr);
let richards_hostname = toscalar(Employees
| where name == "Richard Clements"
| project hostname);
let downloaded = toscalar(Email
| where sender == "tethys@pocketbook.xyz"
| where recipient == richards_email
| project parse_path(link).Filename);
let dl_timestamp = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where filename == downloaded
| project timestamp);
let sus_filename = toscalar(FileCreationEvents
| where hostname == richards_hostname
| where timestamp > dl_timestamp
| order by timestamp asc
| take 1
| project filename);
let cmd_exec_timestamp = toscalar(ProcessEvents
| where hostname == richards_hostname
| where parent_process_name == sus_filename
| project timestamp
| take 1);
ProcessEvents
| where hostname == richards_hostname
| where timestamp > cmd_exec_timestamp
```

## Question 25

The attackers enumerated the contents of a folder on Richard's machine, then dumped its content to a text file. What was the name of that folder?

---

See the results of the query above.

## Question 26

How many machines have similar commands connecting to C2 (command and control) channels as the one observed in question 22?

---

```
ProcessEvents
| where process_commandline contains ":443"
| distinct hostname
| count;
```

## Question 27

How many unique implants were used to establish these C2 connections?

---

```
ProcessEvents
| where process_commandline contains ":443"
| distinct parent_process_hash;
```

## Question 28

One of these C2 connections was observed on hostname 0KYU-DESKTOP. When did this occur?

---

```
ProcessEvents
| where process_commandline contains ":443"
| where hostname == "0KYU-DESKTOP"
| project timestamp;
```

## Question 29

On hostname 0KYU-DESKTOP, what commands did the attackers run to delete data backups?

---

```
let c2_timestamp = toscalar(ProcessEvents
| where process_commandline contains ":443"
| where hostname == "0KYU-DESKTOP"
| project timestamp);
ProcessEvents
| where hostname == "0KYU-DESKTOP"
| where timestamp > c2_timestamp;
```

## Question 30

Looking at the activity seen in question 29, we have a general idea of what their actions on objectives are. What kind of attack could this be a sign of?

---

Probably ransomware.

Section 3

## Question 1

You received a report listing other potential employees that were targeted by a similar attack. The report mentions Son Johnson had downloaded a suspicious Word document file on 2023-02-19 at 05:02. What was the name of this file?

---

```
let son_hostname = toscalar(Employees
| where name == "Son Johnson"
| project hostname);
FileCreationEvents
| where hostname == son_hostname
| where timestamp >= datetime(2023-02-19 05:02:00) and timestamp < datetime(2023-02-19 05:03:00)
| project filename;
```

## Question 2

From which domain did Son Johnson download that docx file?

---

```
let son_ip_addr = toscalar(Employees
| where name == "Son Johnson"
| project ip_addr);
OutboundNetworkEvents
| where src_ip == son_ip_addr
| where timestamp >= datetime(2023-02-19 05:02:00) and timestamp < datetime(2023-02-19 05:03:00);
```

Produces two results:

| Timestamp                  | Method | IP Address   | User Agent                                                                                                                                       | URL                                                                                                        |
|----------------------------|--------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| 2023-02-19T05:02:21.22982Z | GET    | 192.168.2.26 | Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Safari/537.36                               | [https://blimpgoespop.com?redirect=espionage.com](https://blimpgoespop.com?redirect=espionage.com)         |
| 2023-02-19T05:02:57.22982Z | GET    | 192.168.2.26 | Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Safari/537.36                               | [https://espionage.com/online/published/Flight-Crew-Information.docx](https://espionage.com/online/published/Flight-Crew-Information.docx) |

## Question 3

What IP address does espionage.com resolve to?

---

```
PassiveDns
| where domain contains "espionage.com"
| project ip;
```

## Question 4

The PassiveDNS data records a timestamp of when a query was made. This documents what the domain resolved to at the time of the query. What timestamp was recorded for the domain in question 3?

---

Modify the query above.

## Question 5

What other Top Level Domain (TLD) such as .com, .org, is used by the domains hosted on the IP identified in question 3?

---

```
PassiveDns
| where ip == "131.102.77.156"
| project domain;
```

## Question  6

How many domains resolve to the IP identified in question 3?

---

```
PassiveDns
| where ip == "131.102.77.156"
| project domain
| count;
```

## Question 7

One of the domains identified in question 6 resolves to an IP that starts with 194.

What is the IP?

---

```
PassiveDns
| where domain in (
PassiveDns
| where ip == "131.102.77.156"
| distinct domain
)
| project domain, ip;
```

## Question 8

The attackers performed reconnaissance against our organization using the IP identified in question 7. As part of this reconnaissance, the attackers searched for a three-word phrase. What was this phrase?

---

```
InboundNetworkEvents
| where src_ip == "194.235.79.0"
```

## Question 9

Just before downloading the file identified in question 1, Son Johnson browsed to a domain belonging to a partner company. What domain did he browse to?

---

Review the results of the query from question 1.

## Question 10

Take a closer look at the url from question 9. What kind of attack was Son Johnson a victim of?

---

See the training guide.

## Question 11

How many different domains did the attackers use in this kind of attack? (The attack type identified in question 10.)

---

```
OutboundNetworkEvents
| where url has "blimpgoespop.com?redirect="
| distinct url;
```

## Question 12

How many employees at Balloons Over Iowa were victims of this kind of attack? (The attack type identified in question 10)

```
let sources = (OutboundNetworkEvents
| where url has "blimpgoespop.com?redirect="
| distinct src_ip);
Employees
| where ip_addr in (sources)
| count;
```

## Question 13

How many different employee roles did the attackers target using this type of attack? (The attack type identified in question 10)

---

```
let sources = (OutboundNetworkEvents
| where url has "blimpgoespop.com?redirect="
| distinct src_ip);
Employees
| where ip_addr in (sources)
| distinct role
| count;
```

## Question 14

You have received an alert that malware might have infected the device 3CIU-LAPTOP. Some suspicious processes seem to come from a file with the following hash: 4c199019661ef7ef79023e2c960617ec9a2f275ad578b1b1a027adb201c165f3. What is the name of that file?

---

```
FileCreationEvents
| where hostname == "3CIU-LAPTOP"
| where sha256 == "4c199019661ef7ef79023e2c960617ec9a2f275ad578b1b1a027adb201c165f3"
| project filename;
```

## Question 15

What is the username associated with the device from in question 14?

---

```
Employees
| where hostname == "3CIU-LAPTOP"
| project username;
```

## Question 16

Looking deeper at the user from question 15. What is the role of that user in the organization?


Modify the query (or just look at the whole row):

```
Employees
| where hostname == "3CIU-LAPTOP"
| project role;
```

## Question 17

You observe that the file (from question 14) is launching a process on 3CIU-LAPTOP named rundll32.exe with an external IP address. What is that IP address?

```
ProcessEvents
| where hostname == "3CIU-LAPTOP"
| where process_commandline contains "rundll32.exe";
```

## Question 18

What does this connection (from question 17) indicate? (One of the phases of the cyber kill chain.)

---

C2.

## Question 19

Investigating compromised devices in the org, you find malicious activity using a tool called rclone. What domain is listed in its command line on Julie Well's device?

---

```
let julies_hostname = toscalar(Employees
| where name contains "Julie Well"
| project hostname);
ProcessEvents
| where hostname == julies_hostname
| where process_commandline contains "rclone"
| project process_commandline;
```

## Question 20

That's not good. It looks like the attacker copied all files with the extensions listed in the command and extracted it to their domain. What IP address does the domain in question 19 resolve to?

---

```
PassiveDns
| where domain == "infiltrate.air"
| project ip;
```

## Question 21

How many total domains have also resolved to this IP found in question 20?

---

```
let domain_ip = toscalar(PassiveDns
| where domain == "infiltrate.air"
| project ip);
PassiveDns
| where ip == domain_ip
| count;
```

## Question 22

According to MITRE ATT&CK, what kind of activity is the command from question 19 used for?

---

Probably exfiltration!

## Question 23

How many devices did the attackers use rclone on?

---

```
ProcessEvents
| where process_commandline contains "rclone"
| distinct hostname;
```

## Question 24

The attackers disabled Defender (Windows' built-in antivirus) on some devices in the network. How many computers were impacted?

---

This is a difficult question that requires some prior knowledge. Fortunately, I know that "Set-MpPreference -DisableRealtimeMonitoring $true" disables Defender.

```
ProcessEvents 
| where process_commandline contains "disablerealtimemonitoring" 
| distinct hostname 
| count;
```

## Question 25

A member of your investigation team reported that host GWB7-DESKTOP was compromised. What is the timestamp of the earliest suspicious process event you observe on this device?

---

I reviewed the results of this query:

```
ProcessEvents
| where hostname == "GWB7-DESKTOP";
```

| Timestamp                   | Process Name | Process Hash                                                     | Command Line                                 | Parent Process Name | Parent Process Hash                                               | Hostname     | User     |
|-----------------------------|--------------|------------------------------------------------------------------|----------------------------------------------|---------------------|-------------------------------------------------------------------|--------------|----------|
| 2023-02-07T06:54:56.580296Z | blimp.exe    | ebff4951be5e2481866fc61806b6bf8ebad297f09632a9c067bcdcec6d203521 | cmd.exe net localgroup administrators /domain | cmd.exe            | 5db14986062087b74e88053bad0efa25658185ca316510276579a3b403263f57 | GWB7-DESKTOP | chpoulin |

## Question 26

That's not good. It looks like an attacker has established a connection to this host machine. What is the command and control (C2) IP address observed on GWB7-DESKTOP?

---

Review the results of the prior query.

## Question 27

We should go back and look into other domains this IP used. What is the timestamp of the earliest Passive DNS resolution seen on the IP found in question 26?

---

```
PassiveDns
| where ip == "179.175.35.248"
| take 1
| project timestamp;
```

## Question 28

Which of the domains hosted on the IP found in question 26 resolve to the most number of unique IPs? (Answer with the earliest recorded domain.)

---

Compare the results of the previous query with the output from this one:

```
let domains = (PassiveDns
| where ip == "179.175.35.248"
| project domain);
PassiveDns
| where domain in (domains)
| summarize UniqueIpCount = dcount(ip) by domain
| sort by UniqueIpCount desc;
```

## Question 29

What is the domain using the .air TLD that resolves to the IP found in question 26?

---

```
PassiveDns
| where ip == "179.175.35.248"
| project domain;
```

## Question 30

The domain found in question 29 resolves to an IP that starts with "144." What is the hostname on which this IP was used for command and control?

```
let sus_ip = toscalar(PassiveDns
| where domain == "deference.air"
| where ip contains "144"
| distinct ip);
ProcessEvents
| where process_commandline contains sus_ip
| project hostname;
```

# Section 4

## Question 1

The company helpdesk has asked for your help in an ongoing investigation on suspicious emails being received. They suggest taking a look at one in particular. How many emails contained the domain database.io?

---

```
Email
| where link contains "database.io"
```

## Question 2

The subject of that email looks a bit suspicious to you. You've seen this type of phrasing in phishing attempts before. It is just the one email though… To be 100% sure, let's investigate that domain a bit more. What IP does the domain database.io resolve to?

---

```
PassiveDns
| where domain =~ "database.io"
| project ip;
```
## Question 3

How many domains resolve to the same IP as database.io?

---

```
PassiveDns
| where ip == "176.167.219.168"
| count;
```
## Question 4

How many emails contained domains sharing the same IP as database.io?

---

```
let domains = PassiveDns
| where ip == "176.167.219.168"
| project domain = tolower(domain);
Email
| where link has_any (domains)
| count;
```

## Question 5

What was the most prevalent sender of the emails found in question 4?

---

```
let domains = PassiveDns
| where ip == "176.167.219.168"
| project domain = tolower(domain);
Email
| where link has_any (domains)
| summarize count() by sender;
```
## Question 6

How many total emails were sent by the sender found in question 5?

---

```
Email
| where sender == "SSL@hotmail.com"
| count;
```

## Question 7

This sender seems to use email subjects to convey a sense of urgency to trick unsuspecting users into quickly taking action without taking the correct precautions, a common technique used in phishing. What was the most prevalent email subject used by the sender found in question 5?

---

```
Email
| where sender == "SSL@hotmail.com"
| summarize count()by subject;
```

## Question 8

All those subjects sound pretty similar to the first email you were looking at. You were right to research that original domain more thoroughly. Now we have a lot more potential victims to look into. You call back the helpdesk to tell them about the suspicious hotmail address you found. Before you can add anything else, they yelp and tell you about a user that flagged a mail they received from them. The user is called Carolyn, she feels really sorry because she clicked on the link and realised afterwards it might have been malicious… Which user named Carolyn clicked on a link containing the domain hardware.com? (Provide full name.)

---
```
let names = Employees
| where name contains "Carolyn"
| project ip_addr;
OutboundNetworkEvents
| where src_ip has_any (names)
| where url contains "hardware.com";
```

Then look at the results of this query: 

```
Employees
| where name contains "Carolyn"
```
## Question 9

What attacker IP was used to login to Carolyn's account after she clicked the link?

---

```
let names = Employees
| where name contains "Carolyn"
| project ip_addr;
let oops_timestamp = toscalar(OutboundNetworkEvents
| where src_ip has_any (names)
| where url contains "hardware.com"
| project timestamp);
let user = toscalar(Employees
| where name == "Carolyn Schaeffer"
| project username);
AuthenticationEvents
| where username == user
| where timestamp > oops_timestamp;
```

## Question 10

It looks like this same attacker attempted to log into other accounts as well. How many accounts did the attacker try to log into (successfully or unsuccessfully) from the IP in question 9?

---

```
AuthenticationEvents
| where src_ip contains "171.250.201.103";
```

## Question 11

After logging into Carolyn's email, the attackers also used the IP in question 9 to exfiltrate its content. What filename did they save the data to?

---

```
InboundNetworkEvents
| where src_ip contains "171.250.201.103"
```

## Question 12

When did the attackers exfiltrate data from Carolyn's email?

---

See above query.

## Question 13

We should take note of the IP address used by this domain for further research. What IP does the domain hardware.com resolve to?

---

```
PassiveDns
| where domain contains "hardware.com"
```
## Question 14

This IP (from question 13) was used to find out information about the company. What is the first URL the attackers browsed to from this IP?

---

```
InboundNetworkEvents
| where src_ip == "53.85.224.235";
```

## Question 15

As you're finishing up the investigation, Carolyn approaches you sheepishly. She's wondering how the attackers found her work email. Since you still have the browsing data from the attackers up on your screen, you're more than happy to show her how they did it. It's not often you get to educate a willing employee on these matters! Which stage of an attack does the behavior seen in question 14 belong to?

---

Possibly recon.

# Section 5

## Question 1

In this type of attack, adversaries compromise software developers, hardware manufacturers, or service providers and use that access to target downstream users of the software, hardware, or service. Solarwinds was impacted by this type of compromise in 2020.

---

Possibly supply chain?

## Question 2

Attackers often use this legitimate Windows feature as a way to establish persistence on a compromised device.

---

Possibly scheduled task.

## Question 3

Attackers often use this legitimate Windows feature as a way to establish persistence on a compromised device. In an `________-___-___-______` phishing attack, an attacker may steal credentials or cookies to bypass multi-factor authentication and gain access to critical systems.

---

Possibly attacker in the middle.

## Question 4

When using this technique, attackers guess many combinations of usernames and passwords in an attempt to access a system.

---

Possibly brute force.
## Question 5

A `________ ______` attack is when an attacker uses common passwords to try to gain access to multiple accounts in a single environment.

---

Possibly password spray.

## Question 6

This type of malware is designed to permanently erase data from an infected system.

---

Possibly wiper.
## Question 7

This is a collection of databases for configuration settings for the Windows operating system.

---

Possibly registry.

## Question 8

This describes techniques used by attackers to communicate with systems they control within a victim network.

---

Possibly command and control.

## Question 9

This happens when malware or a malicious actor carries out an unauthorized transfer of data from a system.

---

Possibly exfiltration.

## Question 10

This encoding scheme converts "hello world" to aGVsbG8gd29ybGQ=.

---

Possibly base64.

## Question 11

In this type of attack, attackers gain unauthorized access to information, then release that information to the public, often in an attempt to exert influence.

---

Possibly hack and leak.
## Question 12

This is a one-way cryptographic algorithm that converts an input of any length to an output of a fixed length.

---

Possibly hash.

## Question 13

This is a cryptographic hashing function that outputs a value that is 256 bits long.

---

Possibly sha256.

## Question 14

This is the process of tracking and identifying the perpetrator of a cyber attack or intrusion.

---

Possibly attribution.

## Question 15

This Twitter user, also known as "Hutch", co-authored the paper that introduced the kill chain to information security. (enter their @ username)

---

Possibly @killchain.

## Question 16

This Twitter user is the Director of Intel at Red Canary and an instructor for SANS FOR578. (enter their @ username)

---

Possibly @likethecoins.

## Question 17

In this type of attack, adversaries encrypt an organization's files and demand a payment in exchange for the decryption key.

---

Possibly ransomware.

## Question 18

In this type of attack, adversaries gain access to an organization's intellectual property or other sensitive data and threatens to release the data publicly unless the organization pays the adversary.

---

Possibly extortion.

## Question 19

This type of vulnerability is unknown to the people responsible for patching or fixing it.

---

Possibly zero day.

## Question 20

In this phase of the kill chain, attackers try to gather as much information as possible about their victims.

---

Possibly recon.

## Question 21

Attackers use this technique to probe victim infrastructure for vulnerabilities via network traffic.

---

Possibly active scanning.

## Question 22

This data source can be used to get additional information about registered users or assignees of an Internet resource, such as a domain name, an IP address block or an autonomous system.

---

Possibly whois.

## Question 23

In this type of attack, adversaries compromise a legitimate website and add malicious code in an attempt to target users who visit that site.

---

Possibly drive by.
