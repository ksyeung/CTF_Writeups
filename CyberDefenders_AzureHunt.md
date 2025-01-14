https://cyberdefenders.org/blueteam-ctf-challenges/azurehunt

Scenario:
>Anomalous activity has emerged from an unexpected country. Your job as a soc analyst is to Investigate the recent surge in the suspicious activity, Dive into the available logs and data sources to uncover the threats associated with it. Your analysis is crucial to ensure the security of our systems.  
Note: Your Azure environment has been configured to forward AD Logs, Activity Logs and Blob Logs to ELK which are required for this investigation.

This is my first ever cloud forensics lab on the Cyber Defenders BlueYard platform. It took some time to identify the fields, but it was very satisfying to finish! I really appreciate their work: not many platforms today have labs with cloud logs in a SIEM. At the time of writing this, here's what I've found so far:

Cyber Defenders: 1 Azure/M365 lab, 3 AWS lab, 1 GCP lab

ACE Responder: 2 Azure/M365

XINTRA: 1 Azure/M365

Anyway, let's proceed to the lab.

**Q1. As a US-based company, the security team has observed significant suspicious activity from an unusual country. What is the name of the country from which the attacker originated?**

To start, I took a circuitous route: I mistakenly used the field `azure.signinlogs.properties.authentication_details.succeeded`, which actually has two boolean values in some rows (ie, '\[true, false\]' for password authentication then MFA). This is helpful, but not precisely what we need.

I reviewed the fields that were available, and crafted a new query. I added the columns for the User Principal Name (UPN) and geographic location, then proceeded with the following search:

```
event.category: authentication AND event.outcome: failure
```

The question indicates the suspicious activity is non-US, and I was surprised to see that all 46 results are from the United States! The attacker didn't apparently use any credential stuffing, bruteforcing, or related attacks to gain access. Maybe they phished a user? Let's find out which successful logins originated from outside the US:

```
event.category: authentication AND NOT source.geo.country_name: "United States"
```

Here are the results:

| @timestamp                 | azure.signinlogs.properties.user_principal_name | source.ip     | source.geo.country_name | event.category | event.outcome |
|----------------------------|-------------------------------------------------|--------------|-------------------------|----------------|---------------|
| Oct 5, 2023 @ 15:09:57.010 | alice@cybercactus.onmicrosoft.com               | 85.203.15.6   | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:09:59.545 | alice@cybercactus.onmicrosoft.com               | 85.203.15.6   | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:13:58.915 | alice@cybercactus.onmicrosoft.com               | 85.203.15.6   | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:23:27.842 | it.admin1@cybercactus.onmicrosoft.com           | 84.247.59.224 | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:27:55.524 | it.admin1@cybercactus.onmicrosoft.com           | 84.247.59.224 | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:28:26.180 | it.admin1@cybercactus.onmicrosoft.com           | 84.247.59.224 | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:36:25.342 | it.admin1@cybercactus.onmicrosoft.com           | 20.19.30.14   | France                  | authentication | success       |
| Oct 5, 2023 @ 15:41:41.264 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.15  | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:42:01.775 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.15  | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:42:57.731 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.15  | Germany                 | authentication | success       |
| Oct 5, 2023 @ 15:42:59.363 | it.admin1@cybercactus.onmicrosoft.com           | 85.203.15.4   | Germany                 | authentication | success       |
| Oct 6, 2023 @ 07:30:43.113 | it_support@cybercactus.onmicrosoft.com          | 85.203.15.22  | Germany                 | authentication | success       |
| Oct 6, 2023 @ 07:31:59.626 | it_support@cybercactus.onmicrosoft.com          | 85.203.15.22  | Germany                 | authentication | success       |

All but one of fourteen results originate from Germany.

**Q2. To accurately track the activities carried out by the attacker within the environment, it is essential to identify the source of the attack. How many IPs were employed by the attacker?**



**Q3. In order to establish an accurate incident timeline, what is the timestamp of the initial activity originating from the country?**

We can answer this thanks to the query we ran in question one.

**Q4. To assess the scope of compromise, we must determine the attacker's entry point. What is the display name of the user account that was compromised?**

We can trivially learn this by reviewing the event for the first row in Q1. The answer is the value for the field `azure.signinlogs.properties.user_display_name`.

**Q5. To gain insights into the attacker's tactics and enumeration strategy, what is the name of the script file the attacker accessed within blob storage?**



**Q6. For a detailed analysis of the attacker's actions, what is the name of the storage account housing the script file?**



**Q7. Tracing the attacker's movements across our infrastructure, what is the user principal name (UPN) of the second user account the attacker compromised?**

We can infer this from the second account that was successfully logged in, shown in the results of the query for question one!

**Q8. Analyzing the attacker's impact on our environment, what is the name of the Virtual Machine (VM) the attacker started?**



**Q9. To assess the potential data exposure, what is the name of the database exported?**



**Q10. In your pursuit of uncovering persistence techniques, what is the display name associated with the user account you have discovered?**



**Q11. By knowing the attacker's intention. What role was added to the account created to persist in the environment?**



**Q12. For a comprehensive timeline and understanding of the breach progression, what's the timestamp of the first successful login recorded for this user account?**


