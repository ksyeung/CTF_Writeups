[https://kc7cyber.com/challenges/38

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


](https://kc7cyber.com/challenges/38

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

A law enforcement agency informed HopsNStuff that an adversary was attempting to gain access to their company. They said the actor may have sent a PDF file called `Ginger_beer_secret_recipe.pdf` in February of 2023. What hostname had this file first?

---

```
FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| take 1
| project hostname;
```

## Question 2

When was this file created on the host machine?

---

```
FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| take 1
| project timestamp;
```

## Question 3

How many host machines total have a file with this observed filename (Ginger_beer_secret_recipe.pdf)? 

---

```
FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct hostname
| count;
```

## Question 4

What is the role of the employees of those host machines?

---

```
let hosts = FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct hostname;
Employees
| where hostname has_any (hosts)
| project role;
```

## Question 5

Based on where the files are located on the hosts, how many files total are found within that same path? (Hint: count the total number of files across all the observed filepaths)

---

```
let sus_path = FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct tostring(parse_path(path).DirectoryPath);
FileCreationEvents
| where path has_any (sus_path)
| count;
```


## Question 6

How many of those files are PDFs?

---

```
let sus_path = FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct tostring(parse_path(path).DirectoryPath);
FileCreationEvents
| where path has_any (sus_path)
| where parse_path(filename).Extension =~ "pdf"
| count;
```

## Question 7

How many distinct PDF filenames are there from the previous question?

---

```
let sus_path = FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct tostring(parse_path(path).DirectoryPath);
FileCreationEvents
| where path has_any (sus_path)
| where parse_path(filename).Extension =~ "pdf"
| distinct filename
| count;
```

## Question 8

Did any of the other files hit on security alerts? Answer "None" if there weren't any, or submit any of the other filenames that did.

---

```
let sus_path = FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct tostring(parse_path(path).DirectoryPath);
let sus_files = FileCreationEvents
| where path has_any (sus_path)
| where parse_path(filename).Extension =~ "pdf"
| distinct filename;
SecurityAlerts
| where description has_any (sus_files)
```


## Question 9

Were there any additional host machines identified from the answer from the previous question? Answer "None" if there weren't any, or submit any of the other hostnames you identified.

---

```
let include = FileCreationEvents
| where filename == "Brewery_layout.pdf"
| project hostname;
let exclude = FileCreationEvents
| where filename == "Ginger_beer_secret_recipe.pdf"
| distinct hostname;
include
| where not(hostname in (exclude));
```

## Question 10

Let's investigate where the two suspicious pdf files came from. How many emails had a reference to the file(s)?

---

```
Email
| where link contains "Brewery_layout.pdf" or link contains "Ginger_beer_secret_recipe.pdf"
```

## Question 11

How many Outbound connections referenced the file(s)?

---

```
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| count;
```

## Question 12

How many distinct domains were observed in links containing these filenames?

---

```
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| distinct tostring(parse_url(url).Host);
```

## Question 13

How many unique file(s) are referenced from the identified domains?

---

This is a bit ugly, but it works:

```
let domains = OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| distinct tostring(parse_url(url).Host);
OutboundNetworkEvents
| where url has_any (domains)
| project sus_file = tostring(parse_path(tostring(parse_url(url).Path)).Filename) // Cast to string
| where isnotempty(sus_file)
| distinct sus_file
| count;
```

## Question 14

Based on your investigation, HopsNStuff may have been a victim of what type of initial attack?

---

Possibly watering hole.

## Question 15

Let's investigate this activity further. What's the parent_process_hash of the tool that was used to steal user credentials? 

---

I started by reviewing a single host's ProcessEvents and command lines that contain "cmd.exe" or "powershell.exe":

```
let hosts = FileCreationEvents
| where filename contains "Brewery_layout.pdf" or filename contains "Ginger_beer_secret_recipe.pdf"
| distinct hostname
| take 1;
ProcessEvents
| where hostname has_any (hosts)
| where parent_process_name contains "cmd.exe" or parent_process_name contains "powershell.exe"
```

After some examination, I noticed that mimikatz was being run. As this file is often renamed, if I didn't find any results I might try filtering on "sekurlsa" (an argument) if I can't find "mimikatz" in a search, especially in a hunt with more systems and more data.

## Question 16

Investigate the running processes. There are suspicious processes conducting reconnaissance. How many unique directory paths are these suspicious processes located in on infected host machines? (Find the recon command, and go identify its process parent file on disk)

---

```
let sus_processes = ProcessEvents
| where process_commandline contains "cmd.exe"
| distinct parent_process_name;
FileCreationEvents
| where filename has_any (sus_processes)
| project tostring(parse_path(path).DirectoryPath)
| distinct DirectoryPath
```


## Question 17

How many distinct filenames are located in these directory paths? 

---

```
FileCreationEvents
| where path contains "C:\\ProgramData\\PST"
| distinct path;
```


## Question 18

Let's look at the authentication logs for users related to the suspected infected hosts. How many distinct external IP addresses were observed logging into the users of those hosts? 

---

```
let hosts = FileCreationEvents
| where path contains "C:\\ProgramData\\PST"
| distinct hostname;
let users = Employees
| where hostname has_any (hosts)
| project username;
AuthenticationEvents
| where username has_any (users)
| distinct src_ip
| where src_ip !contains "192.168.";
```

## Question 19

Which IP address appears to be located in South America? Hint: Check AbuseIPDB or MaxMind GeoIP2 Database

---

Add an additional line to the last query:
```
| extend geo_info_from_ip_address(src_ip).country;
```

## Question 20

How many IP addresses appear to be located in Asia?

---

See above query results.


## Question 21

What file may have been used to exfiltrate data?

---

Reviewed one of the infected hosts ProcessEvents command-line data:

```
ProcessEvents
| where hostname == "XYTW-LAPTOP"
```

"rclone" is a cloud sync tool seen in the results.

## Question 22

How many unique domains were used for exfiltration? Answer 0 if you did not find any. 

---

```
ProcessEvents
| where process_commandline contains "rclone.exe"
| distinct process_commandline
| count;
```

## Question 23

Let's look at the most recent exfiltration activity and the domain used in Questions 21-22. What IP address does this domain resolve to? (Hint: choose the IP address closest to when the date of activity occured)

---

```
PassiveDns
| where domain == "moneybags.biz"
```

## Question 24

Law enforcement agents say the threat actor may have searched for "egg" on the HopsNStuff's website. How many distinct IP addresses do this?

---

```
InboundNetworkEvents
| where url has "egg" and url contains "search"
| distinct src_ip
```

## Question 25

Law enforcement agents also tell you that the threat actor may have used a batch file but REFUSE to elaborate any further. They tell you it's classified. What command might they be referring to?

---

```
ProcessEvents
| where process_commandline contains ".bat"
| distinct process_commandline;
```

## Question 26

A very specific APT defined by Mandiant has used the exact same cmd.exe command used by this attacker and the same credential stealer for lateral movement. Which APT group is this?

---

This took a few attempts: DuckDuckGo wouldn't surface the results I needed from Mandiant's site, try Google.

## Question 27

What is the name of one of non-Linux backdoors used by the APT group from question 25?

---

Review the PDF from Mandiant's site regarding the APT.

## Question 28

How many DNS records have domains with the word "moneybags"?

---

```
PassiveDns
| where domain contains "moneybags"
| count;
```

## Question 29

On February 8, 2023, Robert Boyce's machine had a file created with a single letter for its name. Search the hash of this file on VirusTotal. When was it first submitted?

---

```
let rob = toscalar(Employees
| where name == "Robert Boyce"
| project hostname);
ProcessEvents
| where hostname == rob
| where timestamp > todatetime("2023-02-07") and timestamp < todatetime("2023-02-09")
```

## Question 30

Employee Cindy Lozano reported some strange activity with her email account. A weird file was seen in her Sent folder but she deleted it right away without looking at the name. What was the name of this file?

---

```
let cindy = toscalar(Employees
| where name == "Cindy Lozano"
| project username);
InboundNetworkEvents
| where url contains cindy
| project url
```

## Question 31

Do you think this activity is linked to Section 2? Yes/No (It's free points, but log down what you answered for future discussions).

---

Possibly!

## Question 32

On what date did this actor send their earliest email? YYYY-MM-DD

---

```
InboundNetworkEvents
| where url contains "login_user" or url contains "mailbox_folder"
```

## Question 33

On what date did this actor send their most recent email? YYYY-MM-DD

---

See above query.

## Question 34

What was the earliest time of day that this actor sent an email? (#AM/PM)

---

See above query.

## Question 35

What was the latest time of day that this actor sent an email? (#AM/PM)

---

See above query.

# Section 4

## Question 1

IP 158.235.158.156 was observed exfiltrating data from mailboxes at HopsNStuff. How many mailboxes were affected?

---



## Question 2

How many total accounts did IP 158.235.158.156 successfully login into?

---



## Question 3

Whose account was first accessed by IP 158.235.158.156?

---



## Question 4

What was the subject of the email that the user in (3) received leading to their account being compromised?

---



## Question 5

How many actor email addresses were observed associated with the subject in (4)?

---



## Question 6

How many actor domains were observed associated with the subject in (5)?

---



## Question 7

How many IP addresses were associated via PassiveDNS with the domains in (6)?

---



## Question 8

How many top level domains (TLDs) are used by this actor (based on your observations so far)?

---



## Question 9

How many domains are associated with this actor? Look for patterns and build a query based on their infrastructure registration TTPs (Hint: between 75 and 300)

---



## Question 10

How many emails did this actor send?

---



## Question 11

How many of this actor's emails were actually delivered (not blocked)?

---



## Question 12

How many HopsNStuff employees clicked on more than 1 link from this actor?

---



## Question 13

How many accounts at HopsNStuff did this actor attempt to log into?

---



## Question 14

How many mail accounts did this actor exfiltrate data from? (Hint: Look for clear evidence of this.)

---


)
