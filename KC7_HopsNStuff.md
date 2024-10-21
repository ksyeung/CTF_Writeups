https://kc7cyber.com/challenges/38

# Section 2
## Question 1

Let's take a look at our SecurityAlerts. A security alert flagged on a file that was quarantined on March 31, 2023. Which host was this identified on?

---

```
SecurityAlerts
| where timestamp > todatetime("2023-03-31")
| where description contains "quarantine"
| project description;
```

## Question 2

Which employee uses this device?

---

Using the hostname found above,

```
Employees
| where hostname == "QBYQ-DESKTOP"
| project name;
```

## Question 3

How many unique hosts had this file on their system? (the file seen in the alert from question 1)

---

```
FileCreationEvents
| where filename == "Dev-Requirements.zip"
| distinct hostname
| count;
```

## Question 4

When was the earliest time this file was seen? (the file seen in the alert from question 1) Make sure to paste the exact timestamp from ADX.

---

Modify the query from above, and then review the results.

## Question 5

Investigate the earliest device that had this file. (the file seen in the alert from question 1) What's the role of the employee who uses this host machine?

---

```
Employees
| where hostname == "FTVO-LAPTOP"
| project role;
```

## Question 6

How many external emails did this employee (the one from question 5) receive based on the data you have?

---

```
Email
| where recipient == "meghann_geisinsky@hopsnstuff.com"
| where sender !contains "hopsnstuff.com"
| count;
```

## Question 7

How many external emails were sent to the employees from the unique host machines identified in Question 3?

---

```
let hosts = FileCreationEvents
| where filename == "Dev-Requirements.zip"
| distinct hostname;
let employee_emails = Employees
| where hostname has_any (hosts)
| project email_addr;
Email
| where recipient has_any (employee_emails)
| where sender !contains "hopsnstuff.com"
| count;
```

## Question 8

From the emails you've found in Question 7, what is the email address of the sender that sent the most recent email that was BLOCKED?

---

```
let hosts = FileCreationEvents
| where filename == "Dev-Requirements.zip"
| distinct hostname;
let employee_emails = Employees
| where hostname has_any (hosts)
| project email_addr;
Email
| where recipient has_any (employee_emails)
| where sender !contains "hopsnstuff.com"
| where verdict == "BLOCKED"
| order by timestamp desc;
```

## Question 9

What country is the email provider from the sender (8) headquartered in?

---

You can learn this from a brief look at your favourite search engine.

## Question 10

Let's investigate the file name that was flagged in Question 1. Look for this file in the emails you filtered for on Question 7. One of the emails marked SUSPICIOUS looks like it came from a partner company. What was the sender's email address?

---

```
let hosts = FileCreationEvents
| where filename == "Dev-Requirements.zip"
| distinct hostname;
let employee_emails = Employees
| where hostname has_any (hosts)
| project email_addr;
Email
| where recipient has_any (employee_emails)
| where sender !contains "hopsnstuff.com"
| where verdict == "SUSPICIOUS"
| where link contains "Dev-Requirements.zip";
```

## Question 11

When was the email from question 10 sent?

---

See results from the query above.

## Question 12

What is the email in the `reply_to` field in the email from question 10?

---

See results from the query above.

## Question 13

To what IP address does the domain in the link field resolve to? Pick the IP address closest (in time) to when the email was sent to the employee in Question 11. 

---

```
PassiveDns
| where domain == "development-module.com"
```

## Question 14

At what time did the employee click on the link? (from the email in 10) Make sure to copy the exact timestamp.

---

```
let host = Employees
| where email_addr == "john_clark@hopsnstuff.com"
| project ip_addr;
OutboundNetworkEvents
| where url == "http://development-module.com/search/search/images/files/Dev-Requirements.zip"
| project timestamp;
```

## Question 15

How many unique domains hosting the same file were clicked by employees? 

---

```
OutboundNetworkEvents
| where url contains "Dev-Requirements.zip"
| distinct tostring(parse_url(url).Host)
| count;
```

## Question 16

Let's look at the emails from Question 10. Some of the emails mention a programming language. What is it?

---

Review results of the query.

## Question 17

Let's look for any references to the answer from Question 16 in running processes. What's the full command line that references the programming language?

---

```
ProcessEvents

| where process_commandline contains "python"

| distinct process_commandline;
```

## Question 18

How many unique hosts had this command line from the previous question?

---

```
ProcessEvents
| where process_commandline contains "python"
| distinct hostname
| count;
```

## Question 19

Two of the Parent Process Names do not appear to be legitimate Windows executables. How many records in total have these Parent Process Names?

---

```
ProcessEvents
| where parent_process_name has_any ("rabbitmq.exe", "nettor.dll")
| count;
```

## Question 20

How many distinct hosts had these processes run on their systems?

---

```
ProcessEvents
| where parent_process_name has_any ("rabbitmq.exe", "nettor.dll")
| distinct hostname
| count;
```

## Question 21

When was the earliest time these processes were seen? 

---

Truncate the query above.

## Question 22

Look for where the file was first seen on a host. Where was this file located? Copy and paste the full path.

---

See the results of the query above.

## Question 23

What is the SHA256 hash of this file?

---

See the results of the query above.

## Question 24

Search this hash on virustotal.com. What is the md5 hash for this file?

---

No assistance is required for this one.

## Question 25

Let's look for the file in other places. What was the path for the file observed on March 13, 2023?

---

```
FileCreationEvents
| where filename has_any ("rabbitmq.exe", "nettor.dll")
| where timestamp > todatetime("2023-03-12") and timestamp < todatetime("2023-03-14")
```

## Question 26

Now let's look at that path across all of the devices. We've already seen some files here from our previous investigation. Which file haven't we seen before?

---

```
FileCreationEvents
| where path contains "C:\\Users\\Public"
| distinct filename;
```

## Question 27

Now that we have 3 file names, let's go back to our process events and find all parent processes that use these files. How many total records are there?

---

```
let files = FileCreationEvents
| where path contains "C:\\Users\\Public"
| distinct filename;
ProcessEvents
| where parent_process_name has_any (files)
| count;
```

## Question 28

These executables seem to run powershell.exe on the command line and has some garbled text after it. After figuring out how to ungarble it, investigate what it's doing. A file is referenced at the end. What is it?

---

Use CyberChef to decode this base64 encoded content.

## Question 29

This thread actor left the answer to a question among those processes. What's the answer?

---

Use CyberChef to decode this base64 encoded content.

## Question 30

How many unique IP addresses did this attacker use to communicate with the infected hosts?

---

```
let files = FileCreationEvents
| where path contains "C:\\Users\\Public"
| distinct filename;
ProcessEvents
| where parent_process_name in (files)
| where process_commandline has_any ("regsvr32", "SearchProtocolHost")
| extend ip = extract_all(@"((?:[0-9]{1,3}\.){3}[0-9]{1,3})", process_commandline)
| distinct tostring(ip)
| count;
```

## Question 31

On what date did this actor send their earliest email? YYYY-MM-DD

---

Truncate the previous query.

## Question 32

On what date did this actor send their most recent email? YYYY-MM-DD

---

Review the results of the previous query.

## Question 33

What was the earliest time of day that this actor sent an email? (answer is the hour, e.g. 5 or 5am)

---

Review the results of the previous query.

## Question 34

What was the latest time of day that this actor sent an email? (The answer is just one digit or E.G. 3PM)

---

Review the results of the previous query.

# Section 3
## Question 1



---



## Question 2



---



## Question 3



---



## Question 4



---



## Question 5



---



## Question 6



---



## Question 7



---



## Question 8



---



## Question 9



---



## Question 10



---



## Question 11



---



## Question 12



---



## Question 13



---



## Question 14



---



## Question 15



---



## Question 16



---



## Question 17



---



## Question 18



---



## Question 19



---



## Question 20



---



## Question 21



---



## Question 22



---



## Question 23



---



## Question 24



---



## Question 25



---



## Question 26



---



## Question 27



---



## Question 28



---



## Question 29



---



## Question 30



---



## Question 31



---



## Question 32



---



## Question 33



---



## Question 34



---


## Question 35



---

# Section 4

## Question 1



---



## Question 2



---



## Question 3



---



## Question 4



---



## Question 5



---



## Question 6



---



## Question 7



---



## Question 8



---



## Question 9



---



## Question 10



---



## Question 11



---



## Question 12



---



## Question 13



---



## Question 14



---


