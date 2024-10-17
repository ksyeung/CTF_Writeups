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
