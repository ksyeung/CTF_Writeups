https://kc7cyber.com/challenges/89
# Section 1

As usual, the first section is a bit of a warm-up. There's virtually zero guidance for the follow on section and consequently quite a challenge, especially considering the APT aspects (and worthy, I think, of the Hard designation).\
## Question 1

You notice some security alerts for a file that appears to contain details on the blueprints of the Sunlands' energy grid. Paste the filename.

---

```
SecurityAlerts
| where description contains "blue"
```

## Question 2

Which host did the alert from Q1 detect the suspicious file on?

---
See above query.

## Question 3

Which employee does the host from Q2 belong to?

---

```
Employees
| where hostname == 'NKIG-DESKTOP'
| project name
```

## Question 4

The attacker sent the suspicious file to that employee from what email address?

---

```
Email
| where link contains 'EnergyGrid-Blueprints.docx'
```
## Question 5

Look at the email message from Q4. The webmail service of the other attacker email address is headquartered in what country?

---

See above.

## Question 6

What domain did the victim download the file from?

---

See above.

## Question 7

What is the name of the process through which the suspicious file was downloaded?

---

```
FileCreationEvents
| where filename contains 'EnergyGrid-Blueprints.docx'
```
## Question 8

How many unique IP addresses does the domain from Q6 resolve to?

---

```
PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip
| count;
```
## Question 9

How many domains do the IP addresses from Q8 resolve to?

---

```
let ips = PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip;
let domains = PassiveDns
| where ip in (ips)
| distinct domain
| project domain;
domains
```
## Question 10

How many employees visited the domains from Q9?

---

```
let ips = PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip;
let domains = PassiveDns
| where ip in (ips)
| distinct domain
| project domain;
let emp_ips = Employees
| project ip_addr;
OutboundNetworkEvents
| where tostring(parse_url(url).Host) in (domains)
| where src_ip in (emp_ips)
| project src_ip
| distinct src_ip
| count;
```
## Question 11

How many unique files were downloaded from the domains from Q9?

---

```
let ips = PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip;
let domains = PassiveDns
| where ip in (ips)
| distinct domain
| project domain;
let filenames = OutboundNetworkEvents
| where parse_url(url).Host in (domains)
| where method == 'GET' and isnotempty(tostring(parse_path(url).Extension))
| project Filename = tostring(parse_path(url).Filename), Extension = tostring(parse_path(url).Extension);
filenames
| distinct Filename
```

## Question 12

Looking at the files found in Q11, **which one was downloaded the most?**

---

```
let ips = PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip;
let domains = PassiveDns
| where ip in (ips)
| distinct domain
| project domain;
let filenames = OutboundNetworkEvents
| where parse_url(url).Host in (domains)
| where method == 'GET' and isnotempty(tostring(parse_path(url).Extension))
| project Filename = tostring(parse_path(url).Filename), Extension = tostring(parse_path(url).Extension);
filenames
| summarize count() by Filename
```
## Question 13

Let's take a look at the employees who downloaded the files from question 11. Which role is seen the most?

---

```
let ips = PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip;
let domains = PassiveDns
| where ip in (ips)
| distinct domain;
let emp_ips = Employees
| project ip_addr, role;
let filenames = OutboundNetworkEvents
| where method == 'GET' and isnotempty(tostring(parse_path(url).Extension))
| where parse_url(url).Host in (domains)
| project src_ip, Filename = tostring(parse_path(url).Filename), Extension = tostring(parse_path(url).Extension);
let seen_ips = filenames
| where src_ip in (emp_ips.ip_addr)
| project src_ip;
emp_ips
| where ip_addr in (seen_ips)
| summarize count() by role;
```

---

## Question 14

What is the name of the employee who first downloaded one of the files from question 11?

---

```
let ips = PassiveDns
| where domain == 'renewablesolutionsgriddefender.com'
| distinct ip;
let domains = PassiveDns
| where ip in (ips)
| distinct domain;
let emp_ips = Employees
| project ip_addr, name, role;
let filenames = OutboundNetworkEvents
| where method == 'GET' and isnotempty(tostring(parse_path(url).Extension))
| where parse_url(url).Host in (domains)
| project timestamp, src_ip, Filename = tostring(parse_path(url).Filename), Extension = tostring(parse_path(url).Extension);
let first_downloads = filenames
| summarize first_timestamp = min(timestamp) by src_ip, Filename // Get the first occurrence of each filename per IP
| join kind=inner (emp_ips) on $left.src_ip == $right.ip_addr // Use $left and $right to clarify the join
| project name, role, Filename, first_timestamp
| order by first_timestamp asc;
```

## Question 15

TDMtRDlOeDFYczg9aT91cGduai96YnAucm9oZ2hibC5qamovLzpmY2dndQ==

---

I used CyberChef to decode this. The recipe, in order, is 'From Base64', 'Reverse', and 'ROT13'.

# Section 2
## Question 1

What is the domain the attackers used to compromise SASA employees interested in the International Space Summit?

---

## Question 2

Which top-level domain (TLD) used by the attacker suggests evidence of foreign interference?

---

## Question 3

What was the most common file (name) that victims downloaded from the attacker domains in Q2?

---

## Question 4

Right after the victims downloaded the files from Q3, the attackers ran a command to connect to their infrastructure. What is the password?

---
## Question 5

The attackers ran commands to discover more about their victims’ network. What is the hostname of the first victim with these commands? This includes compromised hosts that may have been impacted outside of the file in Q3.

---

## Question 6

When did the attackers first run a command to maintain their foothold in victim devices despite restarts, changed credentials, and other interruptions?

---

## Question 7

We know that some of the Sunlands bigwigs got compromised by our threat actor, the question is how…find the role that was compromised most frequently with the command from question 6. How many hosts linked to this role were compromised?

---

## Question 8

One of these compromised hosts was used as a vector to target an OP account with full control of the domain. Which account was successfully compromised?

---

## Question 9

What account did the actor compromise in order to gain access to the account from Q8?

---

## Question 10

What time did the attackers dump credentials?

---

## Question 11

Now that the attacker has full access to the network, what file did they use to stage exfiltration data about the United Sunlands’ sensitive rocket tech and spaceport deal?

---

## Question 12

The attackers transferred the exfiltrated data to what URL?

---
## Question 13

