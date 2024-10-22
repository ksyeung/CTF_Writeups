https://kc7cyber.com/challenges/54
## Question 1

First question is a freebie!

---

  
## Question 2

How many employees are in the company?

---

```
Email
| take 10
```

## Question 3

Each employee at Castle&Sand is assigned an IP address. Which employee has the IP address: 10.10.2.1?

---

```
Employees
| where ip_addr == "10.10.2.1"
```

## Question 4

How many emails did Jacqueline Henderson receive?

---

```
let user_email = toscalar(Employees
| where name == "Jacqueline Henderson"
| project email_addr);
Email
| where recipient == user_email
| count;
```

## Question 5

How many distinct senders were seen in the email logs from sunandsandtrading.com?

---

```
Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count;
```

## Question 6

How many unique websites did “Cristin Genao” visit?
  
---
```
let ip = toscalar(Employees
| where name == "Cristin Genao"
| project ip_addr);
OutboundNetworkEvents
| where src_ip == ip
| distinct url
| count;
```

## Question 7

How many distinct domains in the PassiveDns records contain the word “shark”?

---

```
PassiveDns
| where domain contains "shark"
| distinct domain
| count;
```  

## Question 8

What IPs did the domain “sharkfin.com” resolve to (enter any one of them)?

---

```
PassiveDns
| where domain contains "sharkfin.com"
| project ip;
```

## Question 9

How many unique URLs were browsed by employees named “Karen”?

---

```
let karen =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen)
| distinct url
| count;
```

# Section 2

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



## Question 36



---



## Question 37



---



## Question 38



---



## Question 39



---



## Question 40



---



## Question 41



---



## Question 42



---



## Question 43



---



## Question 44



---



## Question 45



---



## Question 46



---



## Question 47



---



## Question 48



---
