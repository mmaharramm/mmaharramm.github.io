---
order: 1
title: "CrowdStrike Certified Falcon Hunter"
code: "CCFH"
issuer: "CrowdStrike"
issued: "Nov 2026"
earned: "16 Nov 2026"
valid_until: "Nov 2029"
badge: "/images/certs/ccfh-badge.png"
verify: "https://www.credly.com/badges/de8aa793-05e7-4d69-841f-c9dac27b790f/public_url"
verify_label: "Verify on Credly"
certificate: "/images/certs/ccfh-certificate.jpg"
credential_id: "de8aa793-05e7-4d69-841f-c9dac27b790f"
description: "What the CrowdStrike Certified Falcon Hunter (CCFH) certification proves: detection analysis, CQL event search and hypothesis-driven threat hunting in CrowdStrike Falcon."

lede: >-
  Proves I can take a Falcon detection from first alert to root cause, and go looking for
  the intrusions that never raised one. That means reading process trees and timelines,
  querying raw endpoint telemetry with CQL, and telling an admin's script apart from an attacker's.

facts:
  - label: "Format"
    value: "60 questions, 90 minutes, proctored"
  - label: "Expects"
    value: "About 6 months of hands-on Falcon in production"
  - label: "Result"
    value: "Passed on the first attempt"
  - label: "Valid"
    value: "3 years, until Nov 2029"

domains:
  - title: "MITRE ATT&CK and the kill chain"
    points:
      - "Map observed behaviour to tactics and techniques, and spot gaps in what the intelligence covers"
      - "Model a threat actor's TTPs and pivot from one technique to related activity"
      - "Explain an intrusion to people who don't read process trees"
  - title: "Detection analysis"
    points:
      - "Read the Host and Process timelines to reconstruct what happened, in order"
      - "Pivot from a detection into the right investigative tool instead of guessing"
  - title: "Search and investigation tools"
    points:
      - "Interpret the file and process metadata Falcon records"
      - "Pick the right search for the question: host, user, hash, IP address or bulk domains"
      - "Read result dashboards and decide whether to dig further or act"
  - title: "Event search with CQL"
    points:
      - "Write, filter and format CrowdStrike Query Language searches over raw telemetry"
      - "Follow Target, Parent and Context process IDs to rebuild process lineage"
      - "Know the key event types (ProcessRollup2, DnsRequest, NetworkConnectIP4 and others)"
      - "Convert Unix timestamps to readable UTC and turn searches into custom dashboards"
  - title: "Reports and references"
    points:
      - "Use the built-in Hunt and Visibility reports to narrow an investigation"
      - "Look up unfamiliar events and fields in the Events Data Dictionary"
  - title: "Hunting analytics"
    points:
      - "Recognise malicious behaviour, including encoded PowerShell and CMD activity"
      - "Separate testing, DevOps and normal user activity from adversary behaviour"
      - "Weigh evidence for reliability and consider other explanations before calling it, which keeps false positives down"
      - "Trace an enterprise-wide infection back to its source and the vulnerability that let it in"
  - title: "Hunting methodology"
    points:
      - "Run routine hunts to answer one question: has this environment already been breached?"
      - "Turn a hypothesis into hunting leads and prove or disprove it with data"
      - "Find outliers by stacking and counting what is rare across the fleet"
      - "Investigate a process tree from the suspicious leaf back to its root"

on_the_job:
  - "Triage Falcon detections quickly and explain the verdict with evidence"
  - "Write CQL hunts from a threat report or an ATT&CK technique, not only from alerts"
  - "Cut alert noise by recognising legitimate admin and DevOps patterns"
  - "Hand incident responders a clean timeline: entry point, spread and affected hosts"

tools: ["CrowdStrike Falcon Insight", "Falcon Investigate", "Advanced Event Search (CQL)", "MITRE ATT&CK"]
---
