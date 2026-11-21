---
order: 3
title: "Junior Penetration Tester"
code: "eJPT"
issuer: "INE Security"
issued: "Dec 2025"
earned: "26 Dec 2025"
badge: "/images/certs/ejpt-badge.png"
verify: "https://certs.ine.com/28e2828b-0150-4eb3-93ff-d71e9110a55c#acc.G0XAWH9M"
verify_label: "Verify on INE"
certificate: "/images/certs/ejpt-certificate.jpg"
credential_id: "170205875"
description: "What the INE Security eJPT (Junior Penetration Tester) certification proves: hands-on reconnaissance, exploitation, pivoting and web testing in a live lab network."

lede: >-
  An entry-level penetration testing exam with no multiple-choice shortcuts. Every answer comes
  from the lab itself, so you have to actually find the hosts, exploit them, pivot through
  them and pull out the data.

facts:
  - label: "Format"
    value: "Hands-on exam in a live lab network, auto-graded"
  - label: "Pass mark"
    value: "70% overall, plus a minimum in every domain"
  - label: "Focus"
    value: "Real-world engagement skills, entry-level red team"

domains:
  - title: "Assessment methodologies"
    weight: 25
    points:
      - "Find live hosts, open ports, services and operating systems"
      - "OSINT: company details, email addresses and technical footprint from public sources"
      - "Identify vulnerable services and rate how critical each finding is"
  - title: "Host and network auditing"
    weight: 25
    points:
      - "Enumerate system, user and network information on a compromised host"
      - "Pull credentials and password hashes from targets"
      - "Move files to and from targets"
  - title: "Host and network penetration testing"
    weight: 35
    points:
      - "Find, adapt and fix public exploits so they actually work"
      - "Exploitation and post-exploitation with Metasploit"
      - "Pivot into unreachable networks with routes and port forwarding"
      - "Brute-force services and crack password hashes"
  - title: "Web application penetration testing"
    weight: 15
    points:
      - "Web reconnaissance and discovery of hidden files and directories"
      - "Identify common web vulnerabilities"
      - "Brute-force web logins"

on_the_job:
  - "Run the full internal test loop: discover, enumerate, exploit, escalate, pivot"
  - "Rate findings by real impact instead of scanner severity"
  - "Read an attack from the defender's side, because I have run it myself"

tools: ["Nmap", "Metasploit", "Hydra", "John the Ripper", "Hashcat", "Gobuster"]
---
