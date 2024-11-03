https://cyberdefenders.org/blueteam-ctf-challenges/gitthegate/

This is a medium difficulty, Elastic SIEM threat hunting challenge. I've skipped a few of the questions owing to how trivial they are.

>Scenario:
Overnight we've had an attack on our network, we have two devices in the cloud and it appears both have been compromised.    
The attack appears to have taken place on the 25th of May between 9 am and 11:30 am. Our network is composed of one box that is front-facing with an SSH port open to the web and a second server behind it running an old Elastic Stack. As a soc analyst recover the information requested in these challenges so we can piece together what happened.


**Q4: What percentage of logs are from windows 8 machines on the 11th of May? (time is in UTC)**  

Try the search query:
```
@timestamp: 2020-05-11
```
Then isolate by field "machine.os" and visualise the result.

**Q5: How many 503 errors were there on the 8th of May? (time is in UTC)**  
Try the query, 

```
@timestamp: 2020-05-08 AND response: 503
```

**Q6: How many connections to the host "www.elastic.co" were made on the 12th of May? (time is in UTC)**  

```
@timestamp: 2020-05-12 AND host: www.elastic.co
```

**Q7: What is the second most common extension of files being accessed on the 12th of May? (time is in UTC)**  

```
@timestamp: 2020-05-12 AND extension:\*
```

Then visualise the result.

**Q8: Find the first IP address to connect to the host elastic-elastic-elastic.org on the 12th of May. (time is in UTC)**  

```
@timestamp: 2020-05-12 AND host:elastic-elastic-elastic.org
```

**Q9: What was the username used that failed to log in on the 15th of May at 10:44 pm? (time is in UTC)** 

```
@timestamp: "2020-05-15T22:44" AND \*failed\*
```

**Q10: Using current data in the auditbeat index, what is the name of the elasticsearch node? (one word)**  

```
"host.hostname:\*
```

Then visualise, and add the field "host.hostname.keyword".

**Q16: On the 14th of May, how many failed authentication attempts did the host server receive? (time is in UTC)**

Using the auditbeat-* index, 

```
@timestamp: 2020-05-14 AND event.type:"authentication_failure"
```

**Q17: On the 13th and 14th of May, how many bytes were received by the source IP 159.89.203.214 (time is in UTC)**  

Try the query, 

```
source.ip: 159.89.203.214
```

Then create a visualisation, and sum the field "client.bytes".

**Q18: What username did they crack?**  

Build a visualisation using "event.type:\*" with the field "user.name.keyword" on the x-axis and count of records on the y-axis. Then breakdown by "event.outcome.keyword" to see usernames with both failed and successful attempts. Next, use "event.type:\* and user.name.keyword: johnny" for a visualisation using the x-axis "@timestamp" and y-axis "Count of records".

**Q22: What time did the attacker successfully login?**

```
user.name.keyword: johnny and agent.hostname: sshbox and event.outcome: success
```

Q24: What tool did the attacker use to get the exploit onto the machine? 

```
agent.hostname: sshbox and user.name: johnny and @timestamp > "2020-05-25T11:39:30Z"
```

