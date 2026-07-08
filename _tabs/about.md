---
icon: fas fa-info-circle
order: 4
layout: about
title: About
---

<style>
  #about-page {
    max-width: 980px;
  }

  #about-page section {
    margin-top: 3rem;
  }

  #about-page .about-section-title {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 1.3rem;
    font-weight: 600;
    color: var(--heading-color);
    margin-bottom: 1.25rem;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--main-border-color);
  }

  #about-page .about-section-title i {
    color: var(--link-color);
    font-size: 1.1rem;
  }

  /* Hero */
  #about-page .about-hero {
    display: flex;
    align-items: center;
    gap: 2rem;
    margin-top: 0.5rem;
  }

  #about-page .about-avatar {
    width: 148px;
    height: 148px;
    border-radius: 50%;
    object-fit: cover;
    border: 4px solid var(--avatar-border-color);
    box-shadow: var(--card-shadow);
    flex-shrink: 0;
  }

  #about-page .about-greeting {
    display: block;
    font-size: 1rem;
    color: var(--text-muted-color);
    margin-bottom: 0.3rem;
  }

  #about-page .about-name {
    font-size: 2.1rem;
    font-weight: 700;
    color: var(--heading-color);
    margin: 0 0 0.2rem;
  }

  #about-page .about-tagline {
    font-size: 1.05rem;
    color: var(--text-muted-color);
    margin: 0 0 0.9rem;
    font-weight: 500;
  }

  #about-page .about-bio {
    color: var(--text-color);
    line-height: 1.7;
    max-width: 640px;
    margin: 0 0 1.1rem;
  }

  #about-page .about-cta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.7rem;
    align-items: center;
  }

  #about-page .about-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1.1rem;
    border-radius: 999px;
    font-size: 0.92rem;
    font-weight: 600;
    text-decoration: none !important;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }

  #about-page .about-btn:hover {
    transform: translateY(-2px);
  }

  #about-page .about-btn-primary {
    background: var(--link-color);
    color: #fff !important;
  }

  #about-page .about-btn-outline {
    background: transparent;
    color: var(--text-color) !important;
    border: 1px solid var(--btn-border-color);
  }

  #about-page .about-icon-row {
    display: flex;
    gap: 0.6rem;
    margin-left: 0.2rem;
  }

  #about-page .about-icon-btn {
    width: 38px;
    height: 38px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: var(--card-bg);
    color: var(--text-color) !important;
    box-shadow: var(--card-shadow);
    text-decoration: none !important;
    transition: transform 0.15s ease, color 0.15s ease;
  }

  #about-page .about-icon-btn:hover {
    transform: translateY(-2px);
    color: var(--link-color) !important;
  }

  /* Stats strip */
  #about-page .about-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
  }

  #about-page .about-stat {
    background: var(--card-bg);
    box-shadow: var(--card-shadow);
    border-radius: 10px;
    padding: 1.1rem 0.75rem;
    text-align: center;
  }

  #about-page .about-stat .num {
    display: block;
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--heading-color);
  }

  #about-page .about-stat .label {
    font-size: 0.8rem;
    color: var(--text-muted-color);
  }

  /* Services */
  #about-page .about-services-intro {
    color: var(--text-color);
    max-width: 700px;
    line-height: 1.6;
    margin: 0 0 1.25rem;
  }

  #about-page .service-card {
    background: var(--card-bg);
    box-shadow: var(--card-shadow);
    border-radius: 10px;
    padding: 1.4rem;
    transition: transform 0.15s ease;
  }

  #about-page .service-card:hover {
    transform: translateY(-3px);
  }

  #about-page .service-card i {
    width: 42px;
    height: 42px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: var(--sidebar-bg);
    color: var(--link-color);
    font-size: 1.1rem;
    margin-bottom: 0.8rem;
  }

  #about-page .service-card h3 {
    font-size: 1rem;
    margin: 0 0 0.4rem;
  }

  #about-page .service-card p {
    font-size: 0.88rem;
    color: var(--text-muted-color);
    line-height: 1.5;
    margin: 0;
  }

  /* Platform + certification cards */
  #about-page .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 1.25rem;
  }

  #about-page .cert-media {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    max-width: 220px;
    height: 170px;
    margin: 0 auto 1rem;
    border-radius: 8px;
    overflow: hidden;
    background: var(--card-bg);
    text-decoration: none !important;
  }

  #about-page .cert-media img {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
    border-radius: 8px;
  }

  #about-page .cert-media.icon-badge {
    font-size: 2.75rem;
    color: #fff;
  }

  #about-page .platform-card,
  #about-page .cert-card {
    background: var(--card-bg);
    box-shadow: var(--card-shadow);
    border-radius: 10px;
    padding: 1.5rem;
    text-align: center;
    transition: transform 0.15s ease, background 0.15s ease;
  }

  #about-page .platform-card img.badge {
    max-height: 90px;
    margin-bottom: 0.9rem;
  }

  #about-page .platform-card h3 a {
    color: var(--heading-color);
    text-decoration: none;
    font-size: 1.15rem;
  }

  #about-page .platform-card h3 a:hover {
    color: var(--link-color);
  }

  #about-page .platform-stats {
    list-style: none;
    padding: 0;
    margin: 1rem 0;
    text-align: left;
  }

  #about-page .platform-stats li {
    display: flex;
    justify-content: space-between;
    padding: 0.4rem 0;
    border-bottom: 1px dashed var(--main-border-color);
    color: var(--text-muted-color);
    font-size: 0.9rem;
  }

  #about-page .platform-stats li:last-child {
    border-bottom: 0;
  }

  #about-page .platform-stats li strong {
    color: var(--text-color);
    font-weight: 600;
  }

  #about-page .cert-card:hover,
  #about-page .platform-card:hover {
    transform: translateY(-3px);
  }

  #about-page .cert-card a.cert-title {
    display: block;
    color: var(--heading-color);
    font-weight: 600;
    text-decoration: none;
    margin-bottom: 0.3rem;
  }

  #about-page .cert-card a.cert-title:hover {
    color: var(--link-color);
  }

  #about-page .cert-card .cert-date {
    color: var(--text-muted-color);
    font-size: 0.85rem;
  }

  /* Tournament cards */
  #about-page .tournament-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1.25rem;
  }

  #about-page .tournament-card {
    position: relative;
    display: block;
    aspect-ratio: 4 / 3;
    border-radius: 10px;
    overflow: hidden;
    background-size: cover;
    background-position: center;
    box-shadow: var(--card-shadow);
    text-decoration: none !important;
    transition: transform 0.25s ease;
  }

  #about-page .tournament-card:hover {
    transform: scale(1.03);
  }

  #about-page .tournament-card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(to top, rgb(0 0 0 / 92%) 0%, rgb(0 0 0 / 90%) 55%, rgb(0 0 0 / 0%) 100%);
    z-index: 1;
  }

  #about-page .tournament-card .tournament-content {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    padding: 1rem;
    color: #fff;
    text-shadow: 0 1px 4px rgb(0 0 0 / 80%);
    z-index: 2;
  }

  #about-page .tournament-card h3 {
    font-size: 1rem;
    margin: 0 0 0.2rem;
    color: #fff;
  }

  #about-page .tournament-card p {
    font-size: 0.85rem;
    margin: 0;
    opacity: 0.9;
  }


  /* Timeline */
  #about-page .timeline {
    position: relative;
    padding-left: 1.75rem;
    border-left: 2px solid var(--main-border-color);
  }

  #about-page .timeline-item {
    position: relative;
    padding-bottom: 1.6rem;
  }

  #about-page .timeline-item:last-child {
    padding-bottom: 0;
  }

  #about-page .timeline-item::before {
    content: "";
    position: absolute;
    left: -2.28rem;
    top: 0.25rem;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--link-color);
    border: 3px solid var(--card-bg);
  }

  #about-page .timeline-item .role {
    font-weight: 600;
    color: var(--heading-color);
  }

  #about-page .timeline-item .period {
    font-size: 0.85rem;
    color: var(--text-muted-color);
  }

  /* Contact CTA */
  #about-page .about-contact-cta {
    background: var(--card-bg);
    box-shadow: var(--card-shadow);
    border-radius: 10px;
    padding: 2rem;
    text-align: center;
  }

  #about-page .about-contact-cta h2 {
    color: var(--heading-color);
    font-size: 1.4rem;
    margin-bottom: 0.5rem;
  }

  #about-page .about-contact-cta p {
    color: var(--text-muted-color);
    margin-bottom: 1.2rem;
  }

  @media (max-width: 600px) {
    #about-page .about-hero {
      flex-direction: column;
      text-align: center;
    }

    #about-page .about-bio {
      max-width: 100%;
    }

    #about-page .about-cta {
      justify-content: center;
    }
  }
</style>

<section class="about-hero">
  <img src="{{ '/assets/img/favicons/profilepic.png' | relative_url }}" alt="Raimundas Maciulis" class="about-avatar">
  <div>
    <span class="about-greeting">Hi, I'm</span>
    <h1 class="about-name">Raimundas Maciulis</h1>
    <p class="about-tagline">aka <strong>Riminux</strong> &mdash; Penetration Tester &amp; Security Consultant</p>
    <p class="about-bio">
      I'm a cybersecurity engineer and penetration tester specializing in offensive security —
      identifying, exploiting, and clearly documenting vulnerabilities across web applications,
      networks, and wireless environments for organizations across Lithuania and the Baltics.
      Outside of client work, I rank in the <strong>top 1% worldwide</strong> on both TryHackMe and
      HackTheBox, and I write in-depth walkthroughs of the machines and challenges I work through
      on this blog.
    </p>
    <div class="about-cta">
      <a href="#contact" class="about-btn about-btn-primary"><i class="fas fa-paper-plane"></i> Get in Touch</a>
      <a href="/" class="about-btn about-btn-outline"><i class="fas fa-book"></i> Read the Blog</a>
      <div class="about-icon-row">
        <a href="https://github.com/riminux" target="_blank" rel="noopener" class="about-icon-btn" aria-label="GitHub"><i class="fab fa-github"></i></a>
        <a href="https://www.linkedin.com/in/riminux" target="_blank" rel="noopener" class="about-icon-btn" aria-label="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
      </div>
    </div>
  </div>
</section>

<section class="about-stats">
  <div class="about-stat">
    <span class="num">100+</span>
    <span class="label">Pentests Delivered</span>
  </div>
  <div class="about-stat">
    <span class="num">1000+</span>
    <span class="label">Vulnerabilities Found</span>
  </div>
  <div class="about-stat">
    <span class="num">3</span>
    <span class="label">Certifications</span>
  </div>
  <div class="about-stat">
    <span class="num">Top 1%</span>
    <span class="label">CTF Worldwide Ranking</span>
  </div>
</section>

<section>
  <div class="about-section-title"><i class="fas fa-shield-halved"></i> Services</div>
  <p class="about-services-intro">
    I provide independent penetration testing and security consulting for organizations across
    Lithuania and the Baltics, covering web, network, wireless, and mobile environments.
    Available for consulting and private engagements &mdash; <a href="#contact">get in touch</a>.
  </p>
  <div class="card-grid">
    <div class="service-card">
      <i class="fas fa-globe"></i>
      <h3>External Perimeter Testing</h3>
      <p>Assessing internet-facing infrastructure and external network perimeters for exploitable weaknesses.</p>
    </div>
    <div class="service-card">
      <i class="fas fa-network-wired"></i>
      <h3>Internal Network Testing</h3>
      <p>Simulating an attacker with internal access to uncover privilege escalation and lateral movement paths.</p>
    </div>
    <div class="service-card">
      <i class="fas fa-window-maximize"></i>
      <h3>Web Application Testing</h3>
      <p>Identifying and validating vulnerabilities in web applications, tested against the OWASP Testing Guide.</p>
    </div>
    <div class="service-card">
      <i class="fas fa-plug"></i>
      <h3>API Security Testing</h3>
      <p>Reviewing APIs and web services for authentication, authorization, and input-handling flaws.</p>
    </div>
    <div class="service-card">
      <i class="fas fa-mobile-screen-button"></i>
      <h3>Mobile Application Testing</h3>
      <p>Assessing mobile apps against the OWASP Mobile Top 10.</p>
    </div>
  </div>
</section>

<section>
  <div class="about-section-title"><i class="fas fa-certificate"></i> Certifications</div>
  <div class="card-grid">
    <div class="cert-card">
      <a href="https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist" target="_blank" rel="noopener" class="cert-media">
        <img src="{{ '/assets/img/about/htbcpts.jpg' | relative_url }}" alt="HTB CPTS">
      </a>
      <a href="https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist" target="_blank" rel="noopener" class="cert-title">HTB Certified Penetration Testing Specialist</a>
      <span class="cert-date">Obtained November 2024</span>
    </div>
    <div class="cert-card">
      <a href="https://www.offsec.com/products/oscp-plus/" target="_blank" rel="noopener" class="cert-media">
        <img src="{{ '/assets/img/about/oscptitle.jpg' | relative_url }}" alt="OSCP">
      </a>
      <a href="https://www.offsec.com/products/oscp-plus/" target="_blank" rel="noopener" class="cert-title">Offensive Security Certified Professional</a>
      <span class="cert-date">Obtained December 2025</span>
    </div>
    <div class="cert-card">
      <a href="https://www.offsec.com/courses/pen-210/" target="_blank" rel="noopener" class="cert-media icon-badge" style="background: linear-gradient(135deg, #0a2540, #1a4a7a);">
        <i class="fas fa-wifi"></i>
      </a>
      <a href="https://www.offsec.com/courses/pen-210/" target="_blank" rel="noopener" class="cert-title">OffSec Wireless Professional (OSWP)</a>
      <span class="cert-date">Obtained May 2026</span>
    </div>
  </div>
</section>

<section>
  <div class="about-section-title"><i class="fas fa-flag-checkered"></i> CTF Platforms</div>
  <div class="card-grid">
    <div class="platform-card">
      <img src="https://tryhackme-badges.s3.amazonaws.com/Riminux.png" alt="TryHackMe Badge" class="badge">
      <h3><a href="https://tryhackme.com/r/p/Riminux" target="_blank" rel="noopener">TryHackMe</a></h3>
      <ul class="platform-stats">
        <li>Rooms completed <strong>306</strong></li>
        <li>Badges earned <strong>33</strong></li>
        <li>Rating <strong>Top 1% Worldwide</strong></li>
        <li>Completed networks <strong>Wreath &amp; Throwback</strong></li>
      </ul>
    </div>
    <div class="platform-card">
      <img src="{{ '/assets/img/about/RiminuxHTB.png' | relative_url }}" alt="HackTheBox Badge" class="badge">
      <h3><a href="https://profile.hackthebox.com/profile/019db023-4363-7292-a7d6-56add1245c7a" target="_blank" rel="noopener">HackTheBox</a></h3>
      <ul class="platform-stats">
        <li>System flags <strong>107</strong></li>
        <li>User flags <strong>110</strong></li>
        <li>Rank <strong>Pro Hacker</strong></li>
        <li>Rating <strong>Top 1% Worldwide</strong></li>
      </ul>
      <a href="{{ '/assets/downloads/htbtranscript1.pdf' | relative_url }}" target="_blank" class="about-btn about-btn-outline"><i class="fas fa-file-arrow-down"></i> Academy Transcript</a>
    </div>
  </div>
</section>

<section>
  <div class="about-section-title"><i class="fas fa-trophy"></i> CTF Tournaments</div>
  <div class="tournament-grid">
    <a href="https://www.facebook.com/events/700533171484257" target="_blank" rel="noopener" class="tournament-card" style="background-image: url('{{ '/assets/img/about/flamingshield2023.png' | relative_url }}');">
      <div class="tournament-content">
        <h3>The Flaming Shield 2023</h3>
        <p>2nd Place &middot; Team</p>
      </div>
    </a>
    <a href="https://www.facebook.com/events/1219680082500173" target="_blank" rel="noopener" class="tournament-card" style="background-image: url('{{ '/assets/img/about/flamingshield2024.jpg' | relative_url }}');">
      <div class="tournament-content">
        <h3>The Flaming Shield 2024</h3>
        <p>2nd Place &middot; Team</p>
      </div>
    </a>
    <a href="https://cybersprint.lt/" target="_blank" rel="noopener" class="tournament-card" style="background-image: url('{{ '/assets/img/about/cybersprint.jpg' | relative_url }}');">
      <div class="tournament-content">
        <h3>Cybersprint 2025</h3>
        <p>2nd Place &middot; Individual</p>
      </div>
    </a>
  </div>
</section>

<section>
  <div class="about-section-title"><i class="fas fa-briefcase"></i> Experience</div>
  <div class="timeline">
    <div class="timeline-item">
      <div class="role">Cyber Security Engineer / Penetration Tester</div>
      <div class="period">February 2025 &ndash; Present</div>
    </div>
    <div class="timeline-item">
      <div class="role">Generative AI Researcher, CISO Operations</div>
      <div class="period">November 2024 &ndash; Present</div>
    </div>
    <div class="timeline-item">
      <div class="role">System Administrator, Vilnius University</div>
      <div class="period">December 2023 &ndash; February 2025</div>
    </div>
    <div class="timeline-item">
      <div class="role">Cyber Security Laboratory Assistant</div>
      <div class="period">April 2024 &ndash; July 2024</div>
    </div>
  </div>
</section>

<section>
  <div class="about-section-title"><i class="fas fa-graduation-cap"></i> Education</div>
  <div class="timeline">
    <div class="timeline-item">
      <div class="role">BA, Information Systems &amp; Cyber Security &mdash; Vilnius University</div>
      <div class="period">2023 &ndash; 2027</div>
    </div>
  </div>
</section>

<section id="contact">
  <div class="about-contact-cta">
    <h2>Let's Connect</h2>
    <p>Have a question, need consulting or pentesting services, or just want to talk security? Reach out.</p>
    <div class="about-cta" style="justify-content: center;">
      <a href="mailto:raimundas.maciul@gmail.com" class="about-btn about-btn-primary"><i class="fas fa-envelope"></i> raimundas.maciul@gmail.com</a>
      <div class="about-icon-row">
        <a href="https://www.linkedin.com/in/riminux" target="_blank" rel="noopener" class="about-icon-btn" aria-label="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
      </div>
    </div>
  </div>
</section>
