import html
import importlib.util
import json
import random
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

# ------------------------------------------------------------
# Suricata Analyst Trainer
# Run the training app with app
# Run: python -m streamlit run .\suricata_web.py
# ------------------------------------------------------------

APP_VERSION = "0.21.0-web-beta"
TRAINER_FILE = Path(__file__).with_name("suricata_trainer_shippable_v7.py")
PROGRESS_FILE = Path(__file__).with_name("suricata_web_progress.json")

if not TRAINER_FILE.exists():
    st.error("Required training content could not be loaded. Please contact the trainer owner.")
    st.stop()

spec = importlib.util.spec_from_file_location("trainer", TRAINER_FILE)
trainer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trainer)

Question = trainer.Question

# ------------------------------------------------------------
# Advanced scenarios. These are ET PRO-style/realistic-inspired,
# not copied ET PRO rules.
# ------------------------------------------------------------

ADVANCED_SCENARIOS = [
    Question(
        id="adv001", category="Advanced Realistic Tuning", mode="repair", difficulty=4,
        rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible PowerShell download cradle over HTTP"; flow:established,to_server; http.uri; content:"powershell"; nocase; http.uri; content:"downloadstring"; nocase; sid:900001; rev:1;)',
        prompt="This rule attempts to detect PowerShell download cradle behavior but may miss common encoded/parameterized variants. How would you improve it while avoiding broad raw-content matching?",
        answer_points=["scope to http.uri or http.request_body", "encodedcommand or -enc", "iex", "downloadstring", "nocase", "flow to_server", "multiple indicators"],
        required_terms=[],
        accepted_terms=["http.uri", "http.request_body", "encodedcommand", "-enc", "iex", "downloadstring", "nocase", "to_server", "pcre"],
        hints=[
            "Think about where command strings appear in exploit traffic: URI parameters or POST body.",
            "PowerShell abuse often uses -enc, EncodedCommand, IEX, DownloadString, or WebClient patterns.",
            "Avoid scanning the entire payload if HTTP buffers can scope the inspection."
        ],
        explanation="A stronger approach would keep flow:established,to_server, scope matches to http.uri and/or http.request_body, and include stronger PowerShell indicators such as -enc, EncodedCommand, IEX, DownloadString, or WebClient. Avoid broad raw content unless there is a specific reason.",
        skills=["advanced_tuning", "http_buffers", "powershell", "false_positive_reduction"]
    ),
    Question(
        id="adv002", category="Advanced Realistic Tuning", mode="optimize", difficulty=4,
        rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible DNS tunneling long label"; dns.query; pcre:"/[a-z0-9]{20,}\\./i"; sid:900002; rev:1;)',
        prompt="This DNS rule catches long labels but may create false positives on CDNs and tracking domains. What extra logic or operational handling would improve it?",
        answer_points=["threshold", "track by source", "allowlist", "entropy", "baseline", "multiple queries"],
        required_terms=[],
        accepted_terms=["threshold", "detection_filter", "by_src", "allowlist", "baseline", "entropy", "rate", "known domains", "repeated"],
        hints=[
            "Long DNS labels alone are not always malicious.",
            "DNS tunneling is usually behavioral: repeated long/high-entropy queries from a source.",
            "Consider source tracking, rate logic, entropy, and allowlisting known benign services."
        ],
        explanation="Long-label DNS rules should usually include behavior context such as repeated queries over time, tracking by source, entropy/label-count logic, and allowlists for known CDNs or business services.",
        skills=["dns", "advanced_tuning", "thresholding", "false_positive_reduction"]
    ),
    Question(
        id="adv003", category="Advanced Realistic Repair", mode="repair", difficulty=4,
        rule='alert http any any -> any any (msg:"Possible SQL injection"; http.uri; content:"id="; nocase; sid:900003; rev:1;)',
        prompt="Repair this SQL injection rule so it detects more meaningful suspicious URI patterns instead of normal id= parameters.",
        answer_points=["union", "select", "or 1=1", "quotes", "comments", "pcre", "nocase", "http.uri"],
        required_terms=[],
        accepted_terms=["union", "select", "or 1=1", "--", "%27", "'", "pcre", "nocase", "http.uri", "sql"],
        hints=[
            "id= is extremely common and not suspicious by itself.",
            "Look for SQL operators, comments, quotes, or keyword combinations.",
            "A useful repair should keep the match scoped to http.uri."
        ],
        explanation="id= alone is too generic. A better rule would keep http.uri scoping and look for SQLi-specific combinations such as union/select, OR 1=1, quotes, encoded quotes, comments, or a controlled PCRE pattern.",
        skills=["advanced_repair", "http_buffers", "sqli", "tuning"]
    ),
    Question(
        id="adv004", category="Advanced Realistic Tuning", mode="optimize", difficulty=4,
        rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious TLS SNI"; tls.sni; content:"cdn"; nocase; sid:900004; rev:1;)',
        prompt="This TLS SNI rule is too generic for production. How would you make it operationally useful?",
        answer_points=["specific fqdn", "suspicious domain", "allowlist", "baseline", "endswith", "environment context"],
        required_terms=[],
        accepted_terms=["specific", "fqdn", "domain", "allowlist", "baseline", "endswith", "sni", "known good", "ioc"],
        hints=[
            "cdn is common in legitimate traffic.",
            "Host/SNI detections usually need specific domains, suffix logic, or known-bad indicators.",
            "Environmental allowlists and baselining matter."
        ],
        explanation="Generic SNI values like cdn are noisy. Make the detection specific to known suspicious FQDNs, controlled suffixes, newly observed domains, or environment-specific anomalies, and use allowlists/baselines where appropriate.",
        skills=["tls", "advanced_tuning", "false_positive_reduction"]
    ),
    Question(
        id="adv005", category="Advanced Realistic Repair", mode="repair", difficulty=4,
        rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible webshell access"; content:"cmd="; sid:900005; rev:1;)',
        prompt="Repair this possible webshell rule so it is more precise and less likely to match random payload text.",
        answer_points=["http.uri", "http.request_body", "cmd=", "whoami", "ipconfig", "powershell", "flow established to_server", "nocase"],
        required_terms=[],
        accepted_terms=["http.uri", "http.request_body", "cmd=", "whoami", "ipconfig", "powershell", "flow", "to_server", "nocase", "content"],
        hints=[
            "Raw content can match anywhere in request/response payloads.",
            "Webshell commands often appear in URI parameters or POST body.",
            "Pair cmd= with stronger command indicators and client-to-server flow."
        ],
        explanation="A stronger rule would use flow:established,to_server, scope cmd= to http.uri or http.request_body, and optionally pair it with command indicators such as whoami, ipconfig, cmd.exe, powershell, or other environment-relevant webshell patterns.",
        skills=["advanced_repair", "http_buffers", "webshell", "tuning"]
    ),
    Question(
        id="adv006", category="Advanced Capstone Scenario", mode="capstone", difficulty=4,
        rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound suspicious automation"; http.user_agent; content:"python"; nocase; sid:900006; rev:1;)',
        prompt="Scenario: Use the asset role, destination, frequency, and User-Agent evidence to decide whether this automation should be tuned, escalated, or narrowly allowlisted.",
        answer_points=["baseline", "asset role", "known automation", "specific user-agent", "destination", "allowlist", "threshold", "context"],
        required_terms=[],
        accepted_terms=["baseline", "asset", "allowlist", "known", "destination", "specific", "threshold", "context", "owner", "false positive"],
        hints=[
            "Do not just remove the rule because it is noisy.",
            "Find which hosts/scripts legitimately use automation/scripted and where they connect.",
            "Tune by asset role, destination, specific User-Agent string, known-good automation, and behavior context."
        ],
        explanation="Good tuning starts with triage: identify source hosts, owners, destinations, frequency, and whether automation/scripted automation is expected. Then tune with allowlists, specific User-Agent strings, destinations, asset role, and rate/context logic while keeping suspicious unknown automation/scripted automation visible.",
        skills=["capstone", "triage", "tuning", "false_positive_reduction"]
    ),
]


# ------------------------------------------------------------
# Supplemental scenario practice. These reduce repetition by moving learners
# from definition recall into analyst decision-making.
# ------------------------------------------------------------

SUPPLEMENTAL_SCENARIOS = [
    Question(
        id="scn001", category="Scenario Practice - Buffers", mode="read", difficulty=2,
        rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible admin portal access"; flow:established,to_server; http.uri; content:"/admin"; sid:910001; rev:1;)',
        prompt="Analyst scenario: This fires against an internal web server. What specific part of the HTTP request caused the alert, and why is the URI buffer useful here?",
        answer_points=["/admin in uri", "http.uri", "request path", "scoped match reduces noise"],
        required_terms=[],
        accepted_terms=["http.uri", "uri", "path", "/admin", "scoped", "noise"],
        hints=["Focus on the buffer before the content match.", "The rule is not scanning the whole payload.", "Admin access normally appears in the request path/URI."],
        explanation="The alert is caused by /admin inside the http.uri buffer. That is useful because the rule is looking at the requested path, not arbitrary text anywhere in the packet.",
        skills=["http_buffers", "triage", "rule_reading"]
    ),
    Question(
        id="scn002", category="Scenario Practice - Direction", mode="read", difficulty=2,
        rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound suspicious SNI"; tls.sni; content:"pastebin"; nocase; sid:910002; rev:1;)',
        prompt="Analyst scenario: What traffic direction does this describe, and what would you check before deciding it is suspicious?",
        answer_points=["home net outbound", "internal host connecting out", "baseline", "destination", "asset role"],
        required_terms=[],
        accepted_terms=["outbound", "home_net", "internal", "sni", "baseline", "asset", "destination"],
        hints=["Look at which side of the arrow $HOME_NET is on.", "A single SNI string may not be enough by itself.", "Think source host, business purpose, and destination."],
        explanation="This describes an internal/protected host connecting outbound with an SNI containing pastebin. Before escalating, check host role, user/process context if available, frequency, and whether that destination is expected.",
        skills=["rule_structure", "tls", "triage"]
    ),
    Question(
        id="scn003", category="Scenario Practice - Tuning", mode="optimize", difficulty=2,
        rule='alert http any any -> any any (msg:"Login observed"; content:"login"; sid:910003; rev:1;)',
        prompt="This rule fires constantly. Give a practical tuning plan that keeps the login detection intent but reduces false positives.",
        answer_points=["scope to http.uri", "match /login", "add method post", "flow to_server", "network variables"],
        required_terms=[],
        accepted_terms=["http.uri", "/login", "post", "http.method", "flow", "to_server", "home_net", "external_net"],
        hints=["Do not just disable the rule.", "Where should login appear if it is a path?", "Login submissions often use POST."],
        explanation="A good tuning plan would scope login path matching to http.uri, use /login instead of bare login, add POST via http.method if appropriate, and set flow/network direction to match the intended traffic.",
        skills=["tuning", "http_buffers", "false_positive_reduction"]
    ),
    Question(
        id="scn004", category="Scenario Practice - Repair", mode="repair", difficulty=2,
        rule='alert dns any any -> any any (msg:"Possible malicious domain"; content:"bad-domain.com"; sid:910004; rev:1;)',
        prompt="Repair this rule so an analyst can trust that the match is against the queried DNS name.",
        answer_points=["dns.query", "bad-domain.com", "content scoped to dns query"],
        required_terms=["dns.query", "bad-domain.com"],
        accepted_terms=["query", "domain", "scoped", "sid", "rev"],
        hints=["The domain should be matched in the DNS query buffer.", "Raw content is too broad.", "Keep the content value, but place it in the right buffer."],
        explanation='A repaired version would look like: alert dns any any -> any any (msg:"DNS query for bad-domain.com"; dns.query; content:"bad-domain.com"; sid:910004; rev:2;).',
        skills=["dns", "repair", "content_matching"]
    ),
    Question(
        id="scn005", category="Scenario Practice - Analyst Decision", mode="optimize", difficulty=3,
        rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Python User-Agent observed"; http.user_agent; content:"python"; nocase; sid:910005; rev:1;)',
        prompt="This alert appears on a known automation server and one workstation. What would you tune, and what would you keep visible?",
        answer_points=["allowlist known automation", "investigate workstation", "asset role", "destination", "specific user agent"],
        required_terms=[],
        accepted_terms=["allowlist", "automation", "workstation", "asset", "destination", "specific", "baseline", "owner"],
        hints=["Do not suppress everything just because one host is expected.", "Asset role matters.", "Known automation and unknown workstation behavior should be handled differently."],
        explanation="Tune known-good automation by source asset, destination, or specific User-Agent where justified, but keep unknown workstation Python automation visible until it is explained.",
        skills=["triage", "tuning", "asset_context"]
    ),
    Question(
        id="scn006", category="Scenario Practice - Thresholding", mode="optimize", difficulty=3,
        rule='alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound SYN"; flags:S; sid:910006; rev:1;)',
        prompt="Why is alerting on every inbound SYN usually weak, and what behavior would make it more useful?",
        answer_points=["single syn is normal", "track by source", "rate", "detection_filter", "many destinations or ports"],
        required_terms=[],
        accepted_terms=["normal", "threshold", "detection_filter", "by_src", "rate", "count", "seconds", "scan"],
        hints=["A connection attempt starts with SYN.", "Scanning is behavior over time, not one packet.", "Think count, seconds, and source tracking."],
        explanation="A single SYN is normal. For scan-like behavior, use rate logic such as detection_filter/thresholding, track by source, and consider port/destination spread.",
        skills=["tcp_flow", "thresholding", "tuning"]
    ),
    Question(
        id="scn007", category="Scenario Practice - Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a practical rule that detects curl in the User-Agent from protected hosts going outbound, case-insensitive.",
        answer_points=["alert http", "$HOME_NET", "$EXTERNAL_NET", "http.user_agent", "curl", "nocase", "sid"],
        required_terms=["alert", "http", "http.user_agent", "curl", "nocase", "sid"],
        accepted_terms=["home_net", "external_net", "flow", "to_server"],
        hints=["Use HTTP, not TCP, because you care about an HTTP header.", "User-Agent has its own buffer.", "Outbound means HOME_NET is on the source side."],
        explanation='Example: alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound curl User-Agent"; flow:established,to_server; http.user_agent; content:"curl"; nocase; sid:910007; rev:1;).',
        skills=["writing", "http_buffers", "rule_structure"]
    ),
    Question(
        id="scn008", category="Scenario Practice - Capstone", mode="capstone", difficulty=3,
        rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible web exploitation"; flow:established,to_server; http.uri; content:"cmd.exe"; nocase; sid:910008; rev:1;)',
        prompt="Scenario: Review the public web-server alert context and choose what evidence increases confidence before tuning or escalation.",
        answer_points=["uri parameter", "source reputation", "follow-on traffic", "server response", "legitimate testing", "status code"],
        required_terms=[],
        accepted_terms=["parameter", "source", "reputation", "response", "status", "follow-on", "testing", "web server", "context"],
        hints=["One alert is a starting point, not the conclusion.", "Think source, target, response, and follow-on activity.", "Consider whether vulnerability testing or admin activity explains it."],
        explanation="More concerning evidence includes exploit-like parameters, suspicious source, successful server response, follow-on callbacks, or repeated attempts. Less concerning evidence could include approved testing, blocked/404 responses, or benign scanner behavior.",
        skills=["capstone", "triage", "web_exploitation"]
    ),
    Question(
        id="scn009", category="Scenario Practice - Variables", mode="read", difficulty=1,
        rule='alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Inbound web request to protected server"; http.uri; content:"/login"; sid:910009; rev:1;)',
        prompt="In analyst terms, what does this rule describe?",
        answer_points=["external traffic inbound", "protected server", "port 80", "/login uri"],
        required_terms=[],
        accepted_terms=["external", "inbound", "home_net", "protected", "80", "login", "uri"],
        hints=["Read left side to right side.", "The destination is HOME_NET port 80.", "The content is scoped to the URI."],
        explanation="The rule describes external traffic going inbound to a protected web server on port 80 where the HTTP URI contains /login.",
        skills=["rule_structure", "network_variables"]
    ),
    Question(
        id="scn010", category="Scenario Practice - Buffers", mode="repair", difficulty=2,
        rule='alert tls any any -> any any (msg:"Bad hostname"; http.host; content:"evil.example"; sid:910010; rev:1;)',
        prompt="This is meant to detect a TLS hostname. Repair the buffer mistake and explain why it matters.",
        answer_points=["tls.sni", "http.host is wrong", "tls handshake", "hostname"],
        required_terms=["tls.sni"],
        accepted_terms=["http.host", "sni", "handshake", "hostname", "tls"],
        hints=["HTTP Host and TLS SNI are not the same field.", "TLS hostname is in SNI.", "Keep protocol and buffer aligned."],
        explanation="For TLS hostname matching, use tls.sni. http.host is an HTTP header and is not the right field for TLS SNI inspection.",
        skills=["tls", "repair", "buffers"]
    ),
    Question(
        id="scn011", category="Scenario Practice - Tuning", mode="optimize", difficulty=3,
        rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious TLD"; dns.query; content:".ru"; sid:910011; rev:1;)',
        prompt="This rule catches any query containing .ru. How would you improve it as a suffix-style detection and reduce noise?",
        answer_points=["endswith", "dns.query", "baseline", "allowlist", "specific domains"],
        required_terms=[],
        accepted_terms=["endswith", "suffix", "allowlist", "baseline", "specific", "domain", "dns.query"],
        hints=["A suffix match is different from appearing anywhere.", "Use endswith for true domain-ending logic.", "Business-approved destinations may need allowlisting."],
        explanation="Use dns.query with content:\".ru\"; endswith; for suffix logic, then tune with baselines/allowlists or more specific domain intelligence where appropriate.",
        skills=["dns", "tuning", "suffix_matching"]
    ),
    Question(
        id="scn012", category="Scenario Practice - Advanced Repair", mode="repair", difficulty=4,
        rule='alert http any any -> any any (msg:"Possible API key exposure"; http.header; content:"token"; sid:910012; rev:1;)',
        prompt="Repair this into something an analyst could actually defend in production.",
        answer_points=["specific header", "x-api-key", "authorization", "value pattern", "host", "uri", "nocase"],
        required_terms=[],
        accepted_terms=["specific", "x-api-key", "authorization", "pattern", "pcre", "host", "uri", "nocase", "header"],
        hints=["token is too generic.", "Think specific header names or value patterns.", "App-specific host or URI context may be needed."],
        explanation="A defensible production rule should target a specific header name/value pattern, such as X-Api-Key or Authorization behavior, use nocase where appropriate, and add host/URI context if the detection is app-specific.",
        skills=["advanced_repair", "http_headers", "tuning"]
    ),
]


# ------------------------------------------------------------
# Investigation capstones. These add alert metadata and next-step thinking
# so the app teaches operational workflow, not just rule syntax.
# ------------------------------------------------------------

INVESTIGATION_CAPSTONES = [
    Question(
        id="cap001", category="Investigation Capstone", mode="capstone", difficulty=4,
        rule="""Alert: ET WEB_SERVER Possible cmd.exe in URI
Time: 2026-05-18 14:22:31Z
src_ip: 203.0.113.45
src_port: 49221
dest_ip: 10.25.8.14
dest_port: 80
http_method: GET
host: portal.example.internal
uri: /admin.php?exec=cmd.exe+/c+whoami
status: 200
rule: alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible cmd.exe in URI"; flow:established,to_server; http.uri; content:"cmd.exe"; nocase; sid:920001; rev:1;)""",
        prompt="Scenario: Correlate the web request, response status, source behavior, and rule logic to decide how to repair and triage the detection.",
        answer_points=["cmd.exe in uri", "status 200", "server response", "source reputation", "follow-on activity", "web logs", "scope to uri", "approved testing"],
        required_terms=[],
        accepted_terms=["uri", "status", "200", "response", "source", "reputation", "follow-on", "web logs", "testing", "tune", "scope"],
        hints=[
            "A 200 response is more concerning than a blocked or 404 response, but it is not proof by itself.",
            "Check web server logs, follow-on callbacks, source history, and whether this was authorized testing.",
            "Tuning should preserve the URI-scoped exploitation signal rather than suppressing all cmd.exe alerts."
        ],
        explanation="This is concerning because cmd.exe appears in a URI parameter and the server returned 200. Next steps include checking web logs, response size/body if available, source reputation, repeated attempts, follow-on connections, and authorized testing windows. Tune with URI/body scoping, destination/app context, and approved scanner allowlists rather than blanket suppression.",
        skills=["capstone", "web_exploitation", "triage", "tuning"]
    ),
    Question(
        id="cap002", category="Investigation Capstone", mode="capstone", difficulty=4,
        rule="""Alert: Possible DNS tunneling long label
Time: 2026-05-18 15:04:09Z
src_ip: 10.44.12.88
asset_role: user workstation
dns_query: q9a7f2b3c8d1e4f6a9b2c0d3e5f7.example-cdn.net
count_last_10_min: 312
unique_domains_last_10_min: 1
rule: alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible DNS tunneling long label"; dns.query; pcre:"/[a-z0-9]{20,}\\./i"; sid:920002; rev:1;)""",
        prompt="Explain what makes this more or less suspicious, and what tuning or enrichment would make the detection stronger.",
        answer_points=["long labels", "high rate", "track by source", "entropy", "allowlist", "baseline", "asset role", "known cdn"],
        required_terms=[],
        accepted_terms=["long", "rate", "count", "by_src", "threshold", "entropy", "allowlist", "baseline", "asset", "cdn", "known"],
        hints=[
            "Long labels alone are weak, but repeated long-label queries from one workstation are more interesting.",
            "Consider rate, entropy, domain reputation, asset role, and known-good CDN behavior.",
            "The better detection is behavioral, not just string length."
        ],
        explanation="This becomes more suspicious because one workstation made many long-label queries in a short period. Stronger logic would track by source, include rate/threshold behavior, consider entropy/label count, baseline known services, and allowlist known benign CDN/tracking domains only after validation.",
        skills=["capstone", "dns", "thresholding", "triage"]
    ),
    Question(
        id="cap003", category="Investigation Capstone", mode="capstone", difficulty=4,
        rule="""Alert: Outbound Python User-Agent
Time: 2026-05-18 16:18:44Z
src_ip: 10.10.5.21
asset_role: domain controller
dest_host: files-update.example.net
http_user_agent: python-requests/2.31.0
frequency: 48 requests in 5 minutes
rule: alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound Python User-Agent"; flow:established,to_server; http.user_agent; content:"python"; nocase; sid:920003; rev:1;)""",
        prompt="Triage and tune this alert. What context matters most, and what should remain visible?",
        answer_points=["asset role", "domain controller", "destination", "frequency", "owner", "known automation", "allowlist", "keep unknown visible"],
        required_terms=[],
        accepted_terms=["asset", "domain controller", "destination", "frequency", "owner", "automation", "allowlist", "unknown", "visible", "baseline"],
        hints=[
            "automation/scripted from a known automation host is different from automation/scripted from a domain controller or workstation.",
            "Do not allowlist the whole rule just because some automation/scripted traffic is legitimate.",
            "Tune known-good sources/destinations, but keep unusual asset roles visible."
        ],
        explanation="Important context includes source asset role, owner, destination, frequency, process/user context if available, and whether the traffic is expected automation. Tune known-good automation narrowly by source/destination/specific UA, but keep unusual Python traffic from high-value assets visible.",
        skills=["capstone", "asset_context", "tuning", "triage"]
    ),
]


# ------------------------------------------------------------
# Traffic-driven scenario labs. These are structured analyst workflows:
# read evidence -> map fields -> choose/tune/write a rule -> decide next action.
# They avoid sentence-only answers and use scenario tasks instead.
# ------------------------------------------------------------

def make_lab_question(
    id,
    category,
    mode,
    difficulty,
    title,
    evidence,
    starting_rule,
    prompt,
    tasks,
    explanation,
    answer_points,
    skills,
):
    q = Question(
        id=id,
        category=category,
        mode=mode,
        difficulty=difficulty,
        rule=starting_rule,
        prompt=prompt,
        answer_points=answer_points,
        required_terms=[],
        accepted_terms=answer_points,
        hints=[
            "Start with the traffic evidence. Identify direction, protocol, and the exact field that contains the suspicious value.",
            "Then decide whether the existing rule reads the right buffer, is too broad, or needs tuning context.",
            "For production tuning, preserve the detection intent while reducing noise with direction, buffer scope, specificity, and context.",
        ],
        explanation=explanation,
        skills=skills,
    )
    q.lab = {
        "title": title,
        "evidence": evidence,
        "starting_rule": starting_rule,
        "tasks": tasks,
    }
    return q

TRAFFIC_DRIVEN_LABS = [
    make_lab_question(
        id="lab001",
        category="Traffic Scenario Lab - Rule Reading",
        mode="scenario_lab",
        difficulty=2,
        title="Inbound admin path: prove what fired and what context matters",
        evidence="""# tshark -r inbound_admin.pcap -Y "http.request" -V
Frame 1042: 742 bytes on wire (5936 bits), 742 bytes captured
    Arrival Time: May 18, 2026 14:22:31.004000000 UTC
    Epoch Time: 1779114151.004000000

Ethernet II
    Src: 00:50:56:aa:21:19
    Dst: 00:50:56:bb:31:44

Internet Protocol Version 4
    Source Address: 203.0.113.45
    Destination Address: 10.25.8.14

Transmission Control Protocol
    Source Port: 49221
    Destination Port: 80
    Stream index: 18
    Flags: 0x018 (PSH, ACK)

Hypertext Transfer Protocol
    GET /admin/login.php HTTP/1.1\r\n
    Host: portal.example.internal\r\n
    User-Agent: Mozilla/5.0\r\n
    Accept: */*\r\n
    \r\n
    [Full request URI: http://portal.example.internal/admin/login.php]
    [Request Method: GET]
    [Request URI: /admin/login.php]
    [Request Version: HTTP/1.1]

# Follow TCP Stream 18
GET /admin/login.php HTTP/1.1
Host: portal.example.internal
User-Agent: Mozilla/5.0
Accept: */*

HTTP/1.1 200 OK
Server: nginx
Content-Length: 4821

""",
        starting_rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound admin path access"; flow:established,to_server; http.uri; content:"/admin"; sid:930001; rev:1;)',
        prompt="Work the alert like a junior analyst: identify the field that matched, confirm direction, and choose useful follow-up checks.",
        tasks=[
            {
                "type": "single",
                "label": "Which field caused the content match?",
                "options": ["HTTP URI/path", "HTTP Host header", "HTTP request body", "TLS SNI"],
                "answer": 0,
                "explain": "The matched value is /admin in the request path. Because the rule uses http.uri, the match is scoped to the URI/path, not the whole payload.",
            },
            {
                "type": "single",
                "label": "What does the rule direction mean?",
                "options": ["External client to protected web server", "Protected host to external server", "DNS client to resolver", "Server response to client only"],
                "answer": 0,
                "explain": "$EXTERNAL_NET -> $HOME_NET describes inbound traffic toward protected networks.",
            },
            {
                "type": "multi",
                "label": "Which checks help decide whether this is suspicious or expected?",
                "options": ["Review web server access logs", "Check whether /admin/login.php is a normal endpoint", "Look for repeated attempts from the same source", "Look for follow-on alerts from the destination", "Close immediately because /admin is always benign"],
                "answers": [0, 1, 2, 3],
                "explain": "The alert tells you what matched. Triage decides meaning: expected endpoint, repeated behavior, response code, and follow-on activity matter.",
            },
        ],
        explanation="This lab teaches evidence-backed rule reading. The rule fired because /admin appeared in http.uri during inbound HTTP traffic. The next analyst move is not to panic or suppress; it is to validate endpoint legitimacy, source behavior, response, and related activity.",
        answer_points=["http.uri", "/admin", "$EXTERNAL_NET", "$HOME_NET", "web logs", "follow-on activity"],
        skills=["traffic_reading", "http_buffers", "rule_reading", "triage"],
    ),
    make_lab_question(
        id="lab002",
        category="Traffic Scenario Lab - Rule Repair",
        mode="scenario_lab",
        difficulty=3,
        title="Login submission: repair a noisy raw-content rule",
        evidence="""# tshark -r login_submission.pcap -Y "http.request.method == POST" -V
Frame 2218: 894 bytes on wire (7152 bits), 894 bytes captured
    Arrival Time: May 18, 2026 15:08:06.712000000 UTC

Internet Protocol Version 4
    Source Address: 198.51.100.22
    Destination Address: 10.25.8.20

Transmission Control Protocol
    Source Port: 50114
    Destination Port: 443
    Stream index: 31
    Flags: 0x018 (PSH, ACK)

Hypertext Transfer Protocol
    POST /login HTTP/1.1\r\n
    Host: vpn.example.internal\r\n
    User-Agent: curl/8.0\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    Content-Length: 36\r\n
    \r\n
    [Request Method: POST]
    [Request URI: /login]
    [Request Version: HTTP/1.1]

Line-based text data: application/x-www-form-urlencoded
    username=jsmith&password=Summer2026!

""",
        starting_rule='alert http any any -> any any (msg:"Login observed"; content:"login"; sid:930002; rev:1;)',
        prompt="Repair the weak rule so it detects the login submission shown in the traffic without matching random uses of the word login.",
        tasks=[
            {
                "type": "multi",
                "label": "Which improvements should be in the repaired rule?",
                "options": ["Use $EXTERNAL_NET -> $HOME_NET direction", "Use flow:established,to_server", "Match POST in http.method", "Match /login in http.uri", "Keep only raw content:\"login\"", "Optionally match submitted fields in http.request_body"],
                "answers": [0, 1, 2, 3, 5],
                "explain": "The evidence gives you direction, method, URI, and request body. A good repair scopes each condition to the correct field.",
            },
            {
                "type": "rule",
                "label": "Write the repaired Suricata rule.",
                "required": ["alert http", "$EXTERNAL_NET", "$HOME_NET", "flow:established,to_server", "http.method", "POST", "http.uri", "/login", "sid", "rev"],
                "bonus": ["http.request_body", "username=", "password="],
                "explain": "A strong answer uses operational direction, client-to-server flow, http.method for POST, and http.uri for /login. Body fields can be added when the detection objective is credential submission.",
            },
        ],
        explanation='One acceptable repair: alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP POST to login endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/login"; sid:930002; rev:2;). The important concept is scoping, not memorizing an exact rule.',
        answer_points=["$EXTERNAL_NET", "$HOME_NET", "flow:established,to_server", "http.method", "POST", "http.uri", "/login"],
        skills=["rule_repair", "http_buffers", "rule_writing", "tuning"],
    ),
    make_lab_question(
        id="lab003",
        category="Traffic Scenario Lab - DNS Tuning",
        mode="scenario_lab",
        difficulty=4,
        title="Long-label DNS: tune weak matching into behavioral detection",
        evidence="""# tshark -r dns_long_labels.pcap -Y "dns.flags.response == 0" -T fields -e frame.number -e ip.src -e dns.qry.name
2811    10.44.12.88    q9a7f2b3c8d1e4f6a9b2c0d3e5f7.example-cdn.net
2819    10.44.12.88    b8d2a1f9c4e7a0d5b3c6a8f1e9.example-cdn.net
2827    10.44.12.88    z1x2c3v4b5n6m7a8s9d0f1g2h3.example-cdn.net
2836    10.44.12.88    a0d9f8e7c6b5a4d3e2f1a9b8c7.example-cdn.net

# Zeek-style dns.log sample
uid             id.orig_h     id.resp_h     query
Cx9n2a          10.44.12.88   10.10.10.53   q9a7f2b3c8d1e4f6a9b2c0d3e5f7.example-cdn.net
Cq4k8b          10.44.12.88   10.10.10.53   b8d2a1f9c4e7a0d5b3c6a8f1e9.example-cdn.net
Cv7s1m          10.44.12.88   10.10.10.53   z1x2c3v4b5n6m7a8s9d0f1g2h3.example-cdn.net

# Analyst notes from capture window
observation_window: 10 minutes
source_host: 10.44.12.88
asset_role: user workstation
resolver: 10.10.10.53
query_count_last_10_min: 312
unique_base_domain_count: 1
known_business_service: unknown
label_pattern: long pseudo-random labels

""",
        starting_rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible DNS tunneling long label"; dns.query; pcre:"/[a-z0-9]{20,}\\./i"; sid:930003; rev:1;)',
        prompt="Use the DNS evidence to decide what makes the activity suspicious and how the detection should be tuned for production.",
        tasks=[
            {
                "type": "multi",
                "label": "Which evidence is stronger than a single long DNS label?",
                "options": ["High query count from one source", "Repeated long labels under one base domain", "Unknown business service", "A query contains a dot", "The source is a normal workstation"],
                "answers": [0, 1, 2, 4],
                "explain": "Long labels alone can be benign. Repetition, rate, unknown service, and workstation context make it more suspicious.",
            },
            {
                "type": "multi",
                "label": "Which production tuning actions make sense?",
                "options": ["Track by source over a time window", "Baseline known CDN/business domains", "Consider entropy or label-count logic", "Suppress all long-label DNS", "Allowlist only after validation"],
                "answers": [0, 1, 2, 4],
                "explain": "Good tuning keeps behavior visible while reducing known-good noise. Blanket suppression hides actual tunneling.",
            },
            {
                "type": "decision",
                "label": "Best immediate analyst decision?",
                "options": ["Escalate as confirmed malware immediately", "Investigate source host, process/user context, domain reputation, and related DNS volume", "Disable the rule permanently", "Ignore because CDNs always use long labels"],
                "answer": 1,
                "explain": "This is suspicious enough to investigate, but not enough by itself to call confirmed compromise.",
            },
        ],
        explanation="This lab teaches that production DNS detection is behavioral. Long-label matching should be supported by rate, source tracking, base-domain analysis, entropy or label characteristics, and business-service baselining.",
        answer_points=["track by source", "threshold", "entropy", "allowlist", "baseline", "asset role"],
        skills=["dns", "thresholding", "traffic_analysis", "production_tuning"],
    ),
    make_lab_question(
        id="lab004",
        category="Traffic Scenario Lab - Web Exploitation Capstone",
        mode="scenario_lab",
        difficulty=4,
        title="Web exploitation: build a better detection from packet evidence",
        evidence="""# tshark -r web_exploit_attempt.pcap -Y "http.request.uri contains \"cmd.exe\"" -V
Frame 5521: 815 bytes on wire (6520 bits), 815 bytes captured
    Arrival Time: May 18, 2026 16:33:12.117000000 UTC

Internet Protocol Version 4
    Source Address: 203.0.113.77
    Destination Address: 10.25.8.14

Transmission Control Protocol
    Source Port: 51514
    Destination Port: 80
    Stream index: 44
    Flags: 0x018 (PSH, ACK)

Hypertext Transfer Protocol
    GET /admin.php?exec=cmd.exe+/c+whoami HTTP/1.1\r\n
    Host: portal.example.internal\r\n
    User-Agent: python-requests/2.31.0\r\n
    Accept: */*\r\n
    \r\n
    [Request Method: GET]
    [Request URI: /admin.php?exec=cmd.exe+/c+whoami]
    [Request URI Path: /admin.php]
    [Request URI Query: exec=cmd.exe+/c+whoami]

# Follow TCP Stream 44
GET /admin.php?exec=cmd.exe+/c+whoami HTTP/1.1
Host: portal.example.internal
User-Agent: python-requests/2.31.0
Accept: */*

HTTP/1.1 200 OK
Server: nginx
Content-Length: 912

# Correlated observations
same_source_attempts_last_hour: 17
follow_on_outbound_connection_from_server: yes
outbound_destination: 198.51.100.99:443
web_server_process_telemetry: not yet reviewed
approved_testing_window: unknown

""",
        starting_rule='alert http any any -> any any (msg:"Possible command execution"; content:"cmd.exe"; sid:930004; rev:1;)',
        prompt="Complete the workflow: identify the suspicious fields, repair the rule, and choose next triage actions based on the traffic.",
        tasks=[
            {
                "type": "multi",
                "label": "Which evidence makes this more concerning?",
                "options": ["cmd.exe appears in a URI parameter", "The response is 200 OK", "The User-Agent looks like automation", "The server made a follow-on outbound connection", "There were repeated attempts", "The request uses HTTP"],
                "answers": [0, 1, 2, 3, 4],
                "explain": "The concern is not one field alone. It is command execution syntax, successful response, automation-like client, repeated attempts, and follow-on activity.",
            },
            {
                "type": "multi",
                "label": "Which Suricata buffers or rule elements should the improved rule use?",
                "options": ["http.uri", "http.user_agent", "http.request_body", "dns.query", "tls.sni", "flow:established,to_server"],
                "answers": [0, 1, 5],
                "explain": "cmd.exe and whoami are in the URI, python-requests is in User-Agent, and flow should scope client-to-server traffic.",
            },
            {
                "type": "rule",
                "label": "Write an improved rule for this evidence. Include direction, flow, URI scoping, cmd.exe, and nocase. User-Agent is optional context.",
                "required": ["alert http", "$EXTERNAL_NET", "$HOME_NET", "flow:established,to_server", "http.uri", "cmd.exe", "nocase", "sid", "rev"],
                "bonus": ["whoami", "http.user_agent", "python-requests", "python"],
                "explain": "The core detection should be inbound HTTP, client-to-server flow, and URI-scoped command execution indicators. User-Agent can add context but should not be the only detection condition.",
            },
            {
                "type": "multi",
                "label": "Which triage actions should happen before tuning or closing?",
                "options": ["Review web/app logs for the request", "Inspect response body or server status details", "Check host telemetry for spawned shell/process activity", "Investigate the follow-on outbound connection", "Check whether authorized testing was occurring", "Suppress all cmd.exe URI alerts"],
                "answers": [0, 1, 2, 3, 4],
                "explain": "This is a high-value alert. Suppressing all cmd.exe URI alerts would hide true exploitation; validate first, then tune carefully.",
            },
        ],
        explanation="This capstone ties together rule reading, buffer selection, rule writing, and triage. A good analyst can point to exactly why the alert fired, improve the rule without making it overly broad, and identify the next evidence sources needed to validate compromise.",
        answer_points=["http.uri", "cmd.exe", "flow", "$EXTERNAL_NET", "$HOME_NET", "triage", "follow-on", "web logs"],
        skills=["capstone", "http_buffers", "rule_repair", "triage", "traffic_analysis"],
    ),
    make_lab_question(
        id="lab005",
        category="Traffic Scenario Lab - TLS/SNI Tuning",
        mode="scenario_lab",
        difficulty=4,
        title="Suspicious SNI: avoid generic matches and preserve IOC value",
        evidence="""# tshark -r suspicious_sni.pcap -Y "tls.handshake.extensions_server_name" -V
Frame 8801: 571 bytes on wire (4568 bits), 571 bytes captured
    Arrival Time: May 18, 2026 17:41:50.229000000 UTC

Internet Protocol Version 4
    Source Address: 10.44.21.19
    Destination Address: 198.51.100.44

Transmission Control Protocol
    Source Port: 49722
    Destination Port: 443
    Stream index: 62

Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Handshake Protocol: Client Hello
            Extension: server_name (len=40)
                Server Name Indication extension
                    Server Name Type: host_name (0)
                    Server Name: updates-login.security-check.example
            JA3: 72a589da586844d7f0818ce684948eea

# Certificate summary from same session
certificate_subject: CN=updates-login.security-check.example
certificate_age_days: 2

# Environment context
asset_role: finance workstation
first_seen_sni_in_environment: true
known_business_service: no
user_reported_issue: none

""",
        starting_rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious TLS SNI"; tls.sni; content:"login"; nocase; sid:930005; rev:1;)',
        prompt="Tune the TLS/SNI detection so it does not alert on every hostname containing login, while preserving useful suspicious-domain detection.",
        tasks=[
            {
                "type": "multi",
                "label": "Why is the starting rule noisy?",
                "options": ["login appears in many legitimate hostnames", "It uses tls.sni but the content is too generic", "It has no environment context", "SNI can never be useful", "Direction is outbound from a protected host"],
                "answers": [0, 1, 2],
                "explain": "tls.sni is useful, but matching a generic word like login creates noise without more context or specificity.",
            },
            {
                "type": "multi",
                "label": "Which changes improve this detection?",
                "options": ["Match the full suspicious FQDN or a controlled suspicious suffix", "Use first-seen/rare domain enrichment outside the rule", "Baseline or allowlist known business login services", "Change to raw content anywhere", "Keep $HOME_NET -> $EXTERNAL_NET direction"],
                "answers": [0, 1, 2, 4],
                "explain": "A production approach combines specific SNI matching with enrichment and baseline context. Raw content would be worse.",
            },
            {
                "type": "rule",
                "label": "Write a more specific SNI rule for the observed suspicious hostname.",
                "required": ["alert tls", "$HOME_NET", "$EXTERNAL_NET", "tls.sni", "updates-login.security-check.example", "sid", "rev"],
                "bonus": ["nocase", "flow:established,to_server"],
                "explain": "A focused SNI IOC rule should match the actual suspicious hostname instead of a generic word.",
            },
        ],
        explanation="This lab teaches that SNI detections should be specific or enriched. Generic strings create noise; full FQDNs, suspicious suffixes, first-seen rarity, certificate age, and asset context make the detection more useful.",
        answer_points=["tls.sni", "specific fqdn", "baseline", "first seen", "allowlist"],
        skills=["tls", "sni", "production_tuning", "triage"],
    ),
    make_lab_question(
        id="lab006",
        category="Traffic Scenario Lab - Exfil/HTTP Body Capstone",
        mode="scenario_lab",
        difficulty=4,
        title="Large outbound POST: decide whether size alone is enough and build better logic",
        evidence="""# tshark -r outbound_upload.pcap -Y "http.request.method == POST && ip.src == 10.44.12.33" -V
Frame 12044: 1514 bytes on wire (12112 bits), 1514 bytes captured
    Arrival Time: May 18, 2026 19:05:44.602000000 UTC

Internet Protocol Version 4
    Source Address: 10.44.12.33
    Destination Address: 203.0.113.200

Transmission Control Protocol
    Source Port: 50611
    Destination Port: 8080
    Stream index: 91
    Flags: 0x018 (PSH, ACK)

Hypertext Transfer Protocol
    POST /upload.php HTTP/1.1\r\n
    Host: files-sync.example.net\r\n
    User-Agent: python-requests/2.31.0\r\n
    Content-Type: application/octet-stream\r\n
    Content-Length: 7340032\r\n
    \r\n
    [Request Method: POST]
    [Request URI: /upload.php]
    [Full request URI: http://files-sync.example.net:8080/upload.php]

# Follow TCP Stream 91 - payload preview
00000000  42 45 47 49 4e 5f 41 52 43 48 49 56 45 0a 70 61   BEGIN_ARCHIVE.pa
00000010  79 72 6f 6c 6c 5f 65 78 70 6f 72 74 5f 71 32 2e   yroll_export_q2.
00000020  78 6c 73 78 0a 65 6d 70 6c 6f 79 65 65 5f 72 6f   xlsx.employee_ro
00000030  73 74 65 72 2e 63 73 76 0a                         ster.csv.

# Analyst notes from capture window
asset_role: HR workstation
approved_file_sync_domain: no
same_destination_seen_before: no
number_of_large_posts_last_hour: 4
body_bytes_observed: 7340032

""",
        starting_rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Large HTTP POST"; http.method; content:"POST"; dsize:>1000; sid:930006; rev:1;)',
        prompt="Work the possible exfiltration scenario: decide what is weak about size-only detection, choose useful context, and write a better starting rule.",
        tasks=[
            {
                "type": "multi",
                "label": "Which evidence makes this worth investigating?",
                "options": ["Large outbound POST from HR workstation", "Unknown external destination", "Python User-Agent", "Multiple large POSTs in one hour", "Possible sensitive filenames in body strings", "The destination port is not 80"],
                "answers": [0, 1, 2, 3, 4],
                "explain": "Size alone is weak, but size plus asset role, unknown destination, automation, repetition, and sensitive-looking strings is meaningful.",
            },
            {
                "type": "multi",
                "label": "Which detection improvements are better than dsize alone?",
                "options": ["Use flow:established,to_server", "Keep outbound direction", "Match POST in http.method", "Add context such as User-Agent or URI when appropriate", "Threshold/rate repeated large uploads", "Alert on every packet over 1000 bytes"],
                "answers": [0, 1, 2, 3, 4],
                "explain": "A useful rule combines direction, method, flow, context, and behavior. Alerting on every packet size is noisy.",
            },
            {
                "type": "rule",
                "label": "Write a better starting rule for suspicious automated outbound upload behavior.",
                "required": ["alert http", "$HOME_NET", "$EXTERNAL_NET", "flow:established,to_server", "http.method", "POST", "http.user_agent", "python", "sid", "rev"],
                "bonus": ["http.uri", "/upload", "dsize", "detection_filter", "threshold"],
                "explain": "For this exercise, the stronger starting point is outbound HTTP POST plus automation context. Size/rate logic can be added, but should be tuned carefully.",
            },
        ],
        explanation="This capstone teaches that exfil-style detection is context-driven. Size alone is weak; direction, asset role, destination reputation, User-Agent, repeated uploads, URI, and body clues make the scenario stronger.",
        answer_points=["http.method", "POST", "http.user_agent", "python", "outbound", "threshold", "triage"],
        skills=["capstone", "http_buffers", "exfiltration", "tuning", "triage"],
    ),
]


# ------------------------------------------------------------
# Release-candidate capstones.
# These replace earlier sentence-only capstones with structured SOC workflows:
# evidence review -> field mapping -> rule writing/repair -> tuning -> triage.
# ------------------------------------------------------------

# Remove early prototype capstone prompts so the learner only sees structured labs.
ADVANCED_SCENARIOS = [q for q in ADVANCED_SCENARIOS if getattr(q, "id", "") not in {"adv006"}]
SUPPLEMENTAL_SCENARIOS = [q for q in SUPPLEMENTAL_SCENARIOS if getattr(q, "id", "") not in {"scn008"}]

INVESTIGATION_CAPSTONES = [
    make_lab_question(
        id="cap_web_001",
        category="Investigation Capstone - Web Exploitation",
        mode="capstone_lab",
        difficulty=4,
        title="Public web server command-execution attempt",
        evidence="""Wireshark-style HTTP transaction
Frame: 1042
Time: 2026-05-18 14:22:31Z
Source: 203.0.113.45:49221
Destination: 10.25.8.14:80
Protocol: HTTP
Direction: external client -> protected web server

HTTP request
GET /admin.php?exec=cmd.exe+/c+whoami HTTP/1.1
Host: portal.example.internal
User-Agent: curl/8.0
Accept: */*

HTTP response summary
Status: 200 OK
Bytes out: 4821
Server: nginx

Related observations
- Same source requested /admin.php three times in 90 seconds
- Response size increased on the cmd.exe request
- No approved scanner window is listed for this asset""",
        starting_rule='alert http any any -> any any (msg:"cmd.exe observed"; content:"cmd.exe"; sid:940001; rev:1;)',
        prompt="Use the traffic evidence to repair the weak rule, decide whether the alert is meaningful, and choose the next triage steps.",
        tasks=[
            {
                "type": "single",
                "label": "Which traffic field should the command indicator be scoped to first?",
                "options": ["HTTP URI/path", "HTTP Host header", "HTTP response status only", "TLS SNI"],
                "answer": 0,
                "explain": "cmd.exe appears in the request URI parameter. Scoping to http.uri is more precise than raw payload matching.",
            },
            {
                "type": "multi",
                "label": "Which evidence makes this more concerning?",
                "options": ["cmd.exe appears in a URI parameter", "The request targets a public web server", "The server returned 200 OK", "curl User-Agent was used", "Same source repeated the admin request", "The destination port is 80"],
                "answers": [0, 1, 2, 3, 4],
                "explain": "The destination port alone is normal. The combination of command content, public web app, 200 response, curl, and repeat behavior is the meaningful pattern.",
            },
            {
                "type": "rule",
                "label": "Write a repaired rule that preserves the detection intent but avoids broad raw-content matching.",
                "required": ["alert http", "$EXTERNAL_NET", "$HOME_NET", "flow:established,to_server", "http.uri", "cmd.exe", "nocase", "sid", "rev"],
                "bonus": ["/admin.php", "whoami", "curl", "http.user_agent"],
                "explain": "A good repair uses inbound direction, client-to-server flow, URI scoping, and case-insensitive command matching. Extra context like /admin.php, whoami, or curl can strengthen the rule if appropriate.",
            },
            {
                "type": "multi",
                "label": "Which triage actions should the analyst take next?",
                "options": ["Check web server access/error logs", "Look for follow-on outbound callbacks from the server", "Validate whether this source is an approved scanner", "Immediately suppress all cmd.exe URI alerts", "Review response body or captured payload if available"],
                "answers": [0, 1, 2, 4],
                "explain": "Do not suppress the whole detection. Confirm logs, response behavior, scanner context, and follow-on activity first.",
            },
        ],
        explanation="This capstone ties together URI buffers, inbound network direction, flow, realistic triage, and safe tuning. The goal is not to silence noisy command strings; the goal is to scope the detection to the correct field and preserve meaningful exploitation signals.",
        answer_points=["http.uri", "cmd.exe", "flow:established,to_server", "$EXTERNAL_NET", "$HOME_NET", "triage", "web logs"],
        skills=["capstone", "web_exploitation", "http_buffers", "rule_repair", "triage", "tuning"],
    ),
    make_lab_question(
        id="cap_dns_001",
        category="Investigation Capstone - DNS Tunneling",
        mode="capstone_lab",
        difficulty=4,
        title="Workstation generating repeated long-label DNS queries",
        evidence="""Wireshark-style DNS summary
Time window: 2026-05-18 15:00:00Z to 15:10:00Z
Source: 10.44.12.88
Asset role: user workstation
Resolver: 10.44.0.53
Protocol: DNS

Observed queries
q9a7f2b3c8d1e4f6a9b2c0d3e5f7.example-cdn.net
b64x9k2m4p8q1r7s6t3v0w5y8z1.example-cdn.net
m2n8b5v1c9x4z7a0s3d6f9g1h2.example-cdn.net

Behavior summary
count_last_10_min: 312
unique_base_domains: 1
average_label_length: 34
known_business_service: not confirmed
other_hosts_querying_same_domain: 0""",
        starting_rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Long DNS label"; dns.query; pcre:"/[a-z0-9]{20,}\\./i"; sid:940002; rev:1;)',
        prompt="Use the DNS evidence to turn a weak long-label rule into behavior-based tuning logic.",
        tasks=[
            {
                "type": "single",
                "label": "What makes this stronger than a single long DNS label?",
                "options": ["Repeated long-label queries from one source", "The domain contains .net", "The resolver is internal", "DNS uses UDP"],
                "answer": 0,
                "explain": "Long labels alone can be benign. Repeated long-label behavior from one source is much stronger.",
            },
            {
                "type": "multi",
                "label": "Which additions improve the detection without overfitting?",
                "options": ["Track by source over a time window", "Add rate/count logic", "Baseline or allowlist known business services", "Immediately block every .net query", "Consider entropy/label length"],
                "answers": [0, 1, 2, 4],
                "explain": "Behavioral context improves DNS tunneling detection. Blocking all .net traffic is not realistic tuning.",
            },
            {
                "type": "rule",
                "label": "Write a better starting rule that keeps dns.query scoping and adds rate behavior.",
                "required": ["alert dns", "$HOME_NET", "$EXTERNAL_NET", "dns.query", "pcre", "detection_filter", "track by_src", "count", "seconds", "sid", "rev"],
                "bonus": ["nocase", "metadata", "classtype"],
                "explain": "A stronger training answer keeps dns.query scoping, uses a controlled long-label pattern, and adds source-based rate logic.",
            },
            {
                "type": "multi",
                "label": "Which enrichment should be checked before tuning or closing?",
                "options": ["Domain reputation and registration age", "Whether other hosts query the same base domain", "Asset owner and expected software", "Whether the domain is on a known-good allowlist", "Whether the DNS label is exactly 20 characters every time"],
                "answers": [0, 1, 2, 3],
                "explain": "The exact length alone is less important than reputation, prevalence, asset context, and known-good validation.",
            },
        ],
        explanation="This capstone teaches DNS detection as behavior, not string matching. A production-quality approach combines dns.query scoping, repeated activity, source tracking, baselining, and enrichment.",
        answer_points=["dns.query", "long labels", "detection_filter", "track by_src", "baseline", "allowlist", "entropy"],
        skills=["capstone", "dns", "thresholding", "behavioral_detection", "tuning"],
    ),
    make_lab_question(
        id="cap_exfil_001",
        category="Investigation Capstone - Outbound Upload",
        mode="capstone_lab",
        difficulty=4,
        title="Unusual outbound upload from a workstation",
        evidence="""Wireshark-style HTTP transaction
Frame: 8812
Time: 2026-05-18 16:42:12Z
Source: 10.12.7.55:51512
Source asset role: finance workstation
Destination: 198.51.100.77:80
Protocol: HTTP
Direction: protected host -> external server

HTTP request
POST /upload.php HTTP/1.1
Host: files-sync.example.net
User-Agent: python-requests/2.31.0
Content-Type: application/octet-stream
Content-Length: 7340032

HTTP body summary
body_bytes: 7340032
filename_hint: payroll_export.zip

Behavior summary
similar_posts_last_15_min: 9
approved_backup_host: no
known_business_destination: not confirmed""",
        starting_rule='alert ip any any -> any any (msg:"Large packet"; dsize:>1000; sid:940003; rev:1;)',
        prompt="Use the traffic evidence to replace a weak size-only rule with a more defensible outbound upload detection.",
        tasks=[
            {
                "type": "single",
                "label": "What is the biggest problem with the starting rule?",
                "options": ["It uses only packet size without protocol, direction, or context", "It uses $HOME_NET", "It has a msg", "It has a SID"],
                "answer": 0,
                "explain": "Size by itself is noisy. The evidence supports HTTP POST, outbound direction, automation User-Agent, and repeated upload behavior.",
            },
            {
                "type": "multi",
                "label": "Which evidence should shape the improved detection?",
                "options": ["Outbound $HOME_NET to $EXTERNAL_NET direction", "HTTP POST method", "python-requests User-Agent", "Large Content-Length / repeated uploads", "Finance workstation asset role", "Any packet over 1000 bytes"],
                "answers": [0, 1, 2, 3, 4],
                "explain": "The packet-size threshold alone is weak. The combination of direction, method, automation, size/repetition, and asset role is useful.",
            },
            {
                "type": "rule",
                "label": "Write a better starting rule for suspicious automated outbound upload behavior.",
                "required": ["alert http", "$HOME_NET", "$EXTERNAL_NET", "flow:established,to_server", "http.method", "POST", "http.user_agent", "python", "sid", "rev"],
                "bonus": ["http.uri", "/upload", "detection_filter", "count", "seconds", "nocase"],
                "explain": "A better first rule uses HTTP context and outbound direction. Rate/threshold logic can be added after baselining.",
            },
            {
                "type": "multi",
                "label": "Which actions are appropriate before escalating or tuning?",
                "options": ["Confirm whether this host should upload payroll exports", "Check destination reputation and ownership", "Look for repeated POSTs and related alerts", "Suppress all python-requests traffic", "Correlate with endpoint/process telemetry"],
                "answers": [0, 1, 2, 4],
                "explain": "Suppressing all python-requests would hide too much. Validate business purpose, destination, repetition, and endpoint context.",
            },
        ],
        explanation="This capstone teaches that exfil-style detection needs context. A better rule starts with HTTP method, outbound direction, automation indicators, and repetition/size context, then analysts validate business purpose before tuning.",
        answer_points=["http.method", "POST", "http.user_agent", "python", "$HOME_NET", "$EXTERNAL_NET", "threshold", "triage"],
        skills=["capstone", "exfiltration", "http_buffers", "tuning", "triage"],
    ),
    make_lab_question(
        id="cap_tls_001",
        category="Investigation Capstone - TLS/SNI Tuning",
        mode="capstone_lab",
        difficulty=4,
        title="Generic SNI rule flooding on normal CDN traffic",
        evidence="""Wireshark-style TLS session summary
Time window: 2026-05-18 13:00:00Z to 14:00:00Z
Sources: multiple internal workstations
Destinations: multiple external CDN IPs
Protocol: TLS
Direction: protected hosts -> external services

Observed SNI values
cdn.accounts.example-app.com
assets.cdn.vendor-support.net
images.cdn.business-platform.example
malware-update-cdn.example.bad

Alert behavior
rule_match: tls.sni contains "cdn"
alert_count_1h: 18,421
known_business_services_present: yes
one suspicious newly observed SNI: malware-update-cdn.example.bad""",
        starting_rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious CDN SNI"; tls.sni; content:"cdn"; nocase; sid:940004; rev:1;)',
        prompt="Use the SNI evidence to tune a generic, noisy TLS rule without losing the one suspicious hostname.",
        tasks=[
            {
                "type": "single",
                "label": "Why is the starting rule noisy?",
                "options": ["cdn is a generic substring in many legitimate services", "tls.sni is never useful", "Outbound TLS is always malicious", "The SID is too low"],
                "answer": 0,
                "explain": "Generic substrings like cdn create huge false positive volume in TLS/SNI rules.",
            },
            {
                "type": "multi",
                "label": "Which tuning actions preserve useful detection?",
                "options": ["Replace generic cdn with specific suspicious FQDN/suffix logic", "Allowlist validated business SNI values", "Baseline newly observed domains", "Suppress every TLS alert", "Use destination/domain reputation enrichment"],
                "answers": [0, 1, 2, 4],
                "explain": "Tuning should narrow the match and validate known-good services, not suppress all TLS visibility.",
            },
            {
                "type": "rule",
                "label": "Write a better rule targeting the suspicious SNI from the evidence.",
                "required": ["alert tls", "$HOME_NET", "$EXTERNAL_NET", "tls.sni", "malware-update-cdn.example.bad", "sid", "rev"],
                "bonus": ["nocase", "flow:established,to_server", "metadata", "reference"],
                "explain": "A precise SNI rule targets the suspicious hostname or controlled suffix instead of the generic string cdn.",
            },
        ],
        explanation="This capstone teaches SNI tuning: generic substrings are usually noisy, while specific FQDN/suffix logic plus allowlists, baselines, and enrichment preserve useful signal.",
        answer_points=["tls.sni", "specific FQDN", "allowlist", "baseline", "reputation", "tuning"],
        skills=["capstone", "tls", "sni", "false_positive_reduction", "tuning"],
    ),
]

# Use structured capstones everywhere instead of earlier sentence-only prototypes.
ADVANCED_SCENARIOS.extend(INVESTIGATION_CAPSTONES)
TRAFFIC_DRIVEN_LABS.extend(INVESTIGATION_CAPSTONES)


# ------------------------------------------------------------
# Page setup
# ------------------------------------------------------------

st.set_page_config(page_title="Suricata Analyst Trainer", page_icon="🛡️", layout="wide")

# ------------------------------------------------------------
# Navigation UX helpers
# ------------------------------------------------------------

def request_scroll_to_top():
    """Force the next render to jump to the top of the app."""
    st.session_state["_scroll_to_top_next_render"] = True
    st.session_state["_scroll_to_top_nonce"] = st.session_state.get("_scroll_to_top_nonce", 0) + 1


def scroll_to_top_once():
    """Reset scroll position after navigation.

    Streamlit preserves scroll across reruns. For a training app, that makes new
    pages/scenarios feel broken. This runs a small script on flagged renders and
    tries the common Streamlit scroll containers plus the parent window.
    """
    if not st.session_state.pop("_scroll_to_top_next_render", False):
        return

    nonce = st.session_state.get("_scroll_to_top_nonce", 0)
    components.html(
        f"""
        <script>
        (function() {{
            const nonce = {nonce};
            function scrollAll() {{
                try {{ window.parent.scrollTo(0, 0); }} catch(e) {{}}
                try {{ window.scrollTo(0, 0); }} catch(e) {{}}

                const selectors = [
                    '[data-testid="stAppViewContainer"]',
                    '[data-testid="stMain"]',
                    '[data-testid="stMainBlockContainer"]',
                    'section.main',
                    '.main',
                    'main',
                    'body',
                    'html'
                ];

                selectors.forEach(function(sel) {{
                    try {{
                        const el = window.parent.document.querySelector(sel);
                        if (el) {{
                            el.scrollTop = 0;
                            if (el.scrollTo) el.scrollTo(0, 0);
                        }}
                    }} catch(e) {{}}
                }});

                try {{
                    const all = window.parent.document.querySelectorAll('div, section, main');
                    all.forEach(function(el) {{
                        if (el && el.scrollHeight > el.clientHeight) {{
                            el.scrollTop = 0;
                            if (el.scrollTo) el.scrollTo(0, 0);
                        }}
                    }});
                }} catch(e) {{}}
            }}

            scrollAll();
            setTimeout(scrollAll, 50);
            setTimeout(scrollAll, 150);
            setTimeout(scrollAll, 350);
        }})();
        </script>
        """,
        height=0,
    )


def rerun_top():
    """Navigate/rerun and force the next page to start at the top."""
    request_scroll_to_top()
    st.rerun()


def rerun_top():
    """Rerun the app and place the learner at the top of the next view."""
    request_scroll_to_top()
    st.rerun()


# ------------------------------------------------------------
# Visual polish / consistent layout
# ------------------------------------------------------------

st.markdown("""
<style>
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        max-width: 1180px;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
    }

    [data-testid="stSidebar"] * {
        color: #e5e7eb !important;
    }

    [data-testid="stSidebar"] .stSelectbox label,
    [data-testid="stSidebar"] .stRadio label,
    [data-testid="stSidebar"] .stToggle label {
        color: #cbd5e1 !important;
    }

    h1, h2, h3 {
        letter-spacing: -0.02em;
    }

    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.04);
        border: 1px solid rgba(148, 163, 184, 0.25);
        border-radius: 16px;
        padding: 0.8rem 1rem;
    }

    .hero-card {
        border: 1px solid rgba(148, 163, 184, 0.28);
        border-radius: 20px;
        padding: 1.25rem 1.35rem;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.06), rgba(14, 165, 233, 0.05));
        margin-bottom: 1rem;
    }

    .lesson-card {
        min-height: 205px;
        border: 1px solid rgba(148, 163, 184, 0.30);
        border-radius: 18px;
        padding: 1rem;
        background: #ffffff;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
        margin-bottom: 0.75rem;
    }

    .lesson-card-title {
        font-weight: 750;
        font-size: 1.02rem;
        margin-bottom: 0.45rem;
        color: #0f172a;
    }

    .lesson-card-body {
        font-size: 0.88rem;
        color: #475569;
        line-height: 1.35rem;
    }

    .section-card {
        border: 1px solid rgba(148, 163, 184, 0.28);
        border-radius: 18px;
        padding: 1rem 1.1rem;
        background: #ffffff;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
        margin: 0.7rem 0 1rem 0;
    }

    .compare-card {
        min-height: 180px;
        border: 1px solid rgba(148, 163, 184, 0.30);
        border-radius: 18px;
        padding: 0.95rem 1rem;
        background: #ffffff;
        margin-bottom: 0.75rem;
    }

    .compare-title {
        font-size: 0.86rem;
        font-weight: 750;
        color: #0f172a;
        margin-bottom: 0.35rem;
    }

    .compare-body {
        font-size: 0.88rem;
        color: #475569;
        line-height: 1.35rem;
        margin-top: 0.55rem;
    }

    .muted-note {
        color: #64748b;
        font-size: 0.92rem;
        line-height: 1.45rem;
    }

    .pill {
        display: inline-block;
        padding: 0.15rem 0.55rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        background: #e0f2fe;
        color: #075985;
        margin-bottom: 0.6rem;
    }

    .stButton > button, .stDownloadButton > button {
        border-radius: 12px;
        min-height: 2.65rem;
        font-weight: 650;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.4rem;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 999px;
        padding: 0.55rem 1rem;
        background: rgba(148, 163, 184, 0.12);
    }


    .rule-code {
        background: #07110b !important;
        color: #7CFF9B !important;
        border: 1px solid rgba(34, 197, 94, 0.45);
        border-radius: 14px;
        padding: 0.95rem 1rem;
        font-family: Consolas, Monaco, "Courier New", monospace;
        font-size: 0.92rem;
        line-height: 1.45rem;
        white-space: pre-wrap;
        word-break: break-word;
        overflow-x: auto;
        box-shadow: inset 0 0 0 1px rgba(34, 197, 94, 0.06);
        margin: 0.45rem 0 0.9rem 0;
    }

    .rule-label {
        font-size: 0.78rem;
        font-weight: 750;
        color: #166534;
        margin: 0.35rem 0 0.2rem 0;
        text-transform: uppercase;
        letter-spacing: 0.02em;
    }

    .check-card {
        border: 1px solid rgba(148, 163, 184, 0.30);
        border-radius: 18px;
        padding: 1rem 1.1rem;
        background: #ffffff;
        margin-bottom: 0.9rem;
    }

    .check-title {
        font-weight: 750;
        color: #0f172a;
        margin-bottom: 0.25rem;
    }

    .check-scenario {
        color: #475569;
        line-height: 1.4rem;
        margin-bottom: 0.6rem;
    }


    .workflow-card {
        border-left: 5px solid #0ea5e9;
        border-radius: 14px;
        padding: 0.9rem 1rem;
        background: #f8fafc;
        border-top: 1px solid rgba(148, 163, 184, 0.25);
        border-right: 1px solid rgba(148, 163, 184, 0.25);
        border-bottom: 1px solid rgba(148, 163, 184, 0.25);
        margin: 0.6rem 0 0.9rem 0;
    }

    .workflow-card strong {
        color: #0f172a;
    }

    .small-list {
        margin-top: 0.35rem;
        color: #475569;
        line-height: 1.45rem;
    }

    div[data-testid="stCodeBlock"] pre {
        background: #07110b !important;
        color: #7CFF9B !important;
        border: 1px solid rgba(34, 197, 94, 0.45) !important;
        border-radius: 14px !important;
        padding: 0.85rem 1rem !important;
        white-space: pre-wrap !important;
        word-break: break-word !important;
    }


    .pcap-label {
        font-size: 0.78rem;
        font-weight: 750;
        color: #166534;
        margin: 0.35rem 0 0.2rem 0;
        text-transform: uppercase;
        letter-spacing: 0.02em;
    }

    .pcap-code {
        background: #07110b !important;
        color: #7CFF9B !important;
        border: 1px solid rgba(34, 197, 94, 0.45);
        border-radius: 14px;
        padding: 0.95rem 1rem;
        font-family: Consolas, Monaco, "Courier New", monospace;
        font-size: 0.92rem;
        line-height: 1.45rem;
        white-space: pre-wrap;
        word-break: break-word;
        overflow-x: auto;
        box-shadow: inset 0 0 0 1px rgba(34, 197, 94, 0.06);
        margin: 0.45rem 0 0.9rem 0;
    }
    .rule-code code,
    .pcap-code code,
    div[data-testid="stCodeBlock"] code {
        color: #7CFF9B !important;
        background: transparent !important;
        font-family: Consolas, Monaco, "Courier New", monospace !important;
        white-space: pre-wrap !important;
        word-break: break-word !important;
    }

    .code-green, .code-green * {
        color: #7CFF9B !important;
    }


    .green-code-wrap {
        margin: 0.55rem 0 1rem 0;
    }
    .green-code-label {
        color: #22c55e !important;
        font-weight: 800;
        font-size: 0.78rem;
        letter-spacing: 0.045em;
        text-transform: uppercase;
        margin: 0.1rem 0 0.35rem 0;
    }
    .green-code-block {
        background: #07110b !important;
        color: #7CFF9B !important;
        border: 1px solid rgba(34,197,94,0.62) !important;
        border-radius: 14px !important;
        padding: 0.95rem 1rem !important;
        font-family: Consolas, Monaco, "Courier New", monospace !important;
        font-size: 0.92rem !important;
        line-height: 1.45rem !important;
        white-space: pre-wrap !important;
        word-break: break-word !important;
        overflow-x: auto !important;
        margin: 0 !important;
    }
    .green-code-block * {
        color: #7CFF9B !important;
        background: transparent !important;
    }

    /* Force every native Streamlit code block to use the same green terminal-style rendering. */
    div[data-testid="stCodeBlock"],
    div[data-testid="stCodeBlock"] pre,
    div[data-testid="stCodeBlock"] code {
        background: #07110b !important;
        color: #7CFF9B !important;
        border-color: rgba(34,197,94,0.62) !important;
        font-family: Consolas, Monaco, "Courier New", monospace !important;
        white-space: pre !important;
        overflow-x: auto !important;
        word-break: normal !important;
        overflow-wrap: normal !important;
    }
    div[data-testid="stCodeBlock"] pre {
        border: 1px solid rgba(34,197,94,0.62) !important;
        border-radius: 14px !important;
        padding: 0.95rem 1rem !important;
    }

    /* Keep inline rule fragments/variables visually consistent with full rule blocks. */
    div[data-testid="stMarkdownContainer"] code,
    div[data-testid="stMarkdownContainer"] p code,
    div[data-testid="stMarkdownContainer"] li code,
    div[data-testid="stMarkdownContainer"] span code {
        background: #07110b !important;
        color: #7CFF9B !important;
        border: 1px solid rgba(34,197,94,0.40) !important;
        border-radius: 6px !important;
        padding: 0.08rem 0.32rem !important;
        font-family: Consolas, Monaco, "Courier New", monospace !important;
        font-size: 0.92em !important;
        white-space: nowrap !important;
    }

    .syntax-chip {
        display: inline-block;
        background: #07110b !important;
        color: #7CFF9B !important;
        border: 1px solid rgba(34,197,94,0.40) !important;
        border-radius: 6px !important;
        padding: 0.08rem 0.32rem !important;
        font-family: Consolas, Monaco, "Courier New", monospace !important;
        font-size: 0.92em !important;
        white-space: nowrap !important;
    }

</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------
# Release candidate scenario evidence refresh.
# This section replaces earlier flattened lab evidence with cleaner,
# packet-style analyst output. Each scenario contains one evidence block,
# then structured tasks for field mapping, rule work, tuning, and triage.
# ------------------------------------------------------------

TRAFFIC_DRIVEN_LABS = [
    make_lab_question(
        id="lab_web_cmd_001",
        category="Traffic Scenario Lab - HTTP Command Execution",
        mode="scenario_lab",
        difficulty=4,
        title="HTTP command execution attempt against a protected web server",
        evidence=r"""Wireshark Packet View: web_cmd_exec.pcap
Display Filter: http.request.uri contains "cmd.exe"

PACKET LIST
No.     Time          Source          Destination     Protocol Length Info
5521    0.000000000   203.0.113.77    10.25.8.14     HTTP     815    GET /admin.php?exec=cmd.exe+/c+whoami HTTP/1.1
5522    0.047000000   10.25.8.14      203.0.113.77   HTTP     912    HTTP/1.1 200 OK  (text/plain)
5528    2.712000000   10.25.8.14      198.51.100.99  TCP      74     49822 > 443 [SYN]

PACKET DETAILS - Frame 5521
Frame 5521: 815 bytes on wire (6520 bits), 815 bytes captured
    Arrival Time: May 18, 2026 16:33:12.117000000 UTC
    Epoch Time: 1779121992.117000000
    Frame Number: 5521
    Frame Length: 815 bytes
    Capture Length: 815 bytes

Ethernet II
    Destination: 00:50:56:aa:10:14
    Source: 00:50:56:bb:20:45
    Type: IPv4 (0x0800)

Internet Protocol Version 4
    0100 .... = Version: 4
    Header Length: 20 bytes
    Total Length: 801
    Time to Live: 52
    Protocol: TCP (6)
    Source Address: 203.0.113.77
    Destination Address: 10.25.8.14

Transmission Control Protocol
    Source Port: 51514
    Destination Port: 80
    Stream index: 44
    Sequence Number: 1    (relative sequence number)
    Acknowledgment Number: 1
    Header Length: 32 bytes
    Flags: 0x018 (PSH, ACK)
        .... .... .... 1000 = PSH: Set
        .... .... .... 0001 = ACK: Set
    Window: 64240
    TCP payload (222 bytes)

Hypertext Transfer Protocol
    GET /admin.php?exec=cmd.exe+/c+whoami HTTP/1.1\r\n
    Host: portal.example.internal\r\n
    User-Agent: python-requests/2.31.0\r\n
    Accept: */*\r\n
    \r\n
    [Request Method: GET]
    [Request URI: /admin.php?exec=cmd.exe+/c+whoami]
    [Request URI Path: /admin.php]
    [Request URI Query: exec=cmd.exe+/c+whoami]
    [Full request URI: http://portal.example.internal/admin.php?exec=cmd.exe+/c+whoami]

FOLLOW TCP STREAM - tcp.stream eq 44 - ASCII
Client 203.0.113.77:51514 -> Server 10.25.8.14:80
GET /admin.php?exec=cmd.exe+/c+whoami HTTP/1.1
Host: portal.example.internal
User-Agent: python-requests/2.31.0
Accept: */*

Server 10.25.8.14:80 -> Client 203.0.113.77:51514
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/plain
Content-Length: 912

nt authority\system

PACKET BYTES - Frame 5521 payload preview
0000  47 45 54 20 2f 61 64 6d 69 6e 2e 70 68 70 3f 65   GET /admin.php?e
0010  78 65 63 3d 63 6d 64 2e 65 78 65 2b 2f 63 2b 77   xec=cmd.exe+/c+w
0020  68 6f 61 6d 69 20 48 54 54 50 2f 31 2e 31 0d 0a   hoami HTTP/1.1..
0030  48 6f 73 74 3a 20 70 6f 72 74 61 6c 2e 65 78 61   Host: portal.exa

Analyst note: the command indicator is in the HTTP request URI query, and the response appears to contain command output.""",
        starting_rule='alert http any any -> any any (msg:"cmd.exe observed"; content:"cmd.exe"; sid:940001; rev:1;)',
        prompt="Use the packet evidence to identify the right HTTP fields, repair the weak rule, and choose appropriate follow-up actions.",
        tasks=[
            {"type": "single", "label": "Where should the cmd.exe indicator be scoped first?", "options": ["http.uri", "http.host", "http.response_body", "tls.sni"], "answer": 0, "explain": "The command appears in the request URI query string, so http.uri is the best first scope."},
            {"type": "multi", "label": "Which evidence makes this higher concern?", "options": ["cmd.exe and whoami are in the URI", "The response is 200 OK and returns command output", "The client User-Agent looks automated", "The protected server opens a follow-on outbound TLS connection", "The destination port is 80"], "answers": [0, 1, 2, 3], "explain": "The concern is the combination of command syntax, apparent command output, automation-like client, and follow-on outbound activity."},
            {"type": "rule", "label": "Write a better Suricata rule for this evidence.", "required": ["alert http", "$EXTERNAL_NET", "$HOME_NET", "flow:established,to_server", "http.uri", "cmd.exe", "nocase", "sid", "rev"], "bonus": ["whoami", "python-requests", "http.user_agent"], "explain": "A better rule scopes the command indicator to http.uri, limits direction to inbound client-to-server traffic, and uses nocase. User-Agent or whoami can add context."},
            {"type": "multi", "label": "What should the analyst check next?", "options": ["Web server process logs around 16:33:12Z", "Whether nt authority/system-like output appeared in the response", "Outbound connection from 10.25.8.14 to 198.51.100.99:443", "Approved scanner/test window", "Disable the rule because curl/python tools are common"], "answers": [0, 1, 2, 3], "explain": "Do not suppress this blindly. Validate exploitation, response content, process activity, follow-on outbound behavior, and whether testing was approved."},
        ],
        explanation="This scenario teaches how to move from packet evidence to rule scoping. The key is not just matching cmd.exe; it is tying the indicator to the HTTP URI, direction, response behavior, and follow-on activity.",
        answer_points=["http.uri", "flow:established,to_server", "cmd.exe", "nocase", "triage", "follow-on connection"],
        skills=["http", "web_exploitation", "rule_repair", "triage"],
    ),
    make_lab_question(
        id="lab_dns_tunnel_001",
        category="Traffic Scenario Lab - DNS Tunneling",
        mode="scenario_lab",
        difficulty=4,
        title="Repeated high-entropy DNS labels from one workstation",
        evidence=r"""Wireshark Packet View: dns_tunnel_suspected.pcap
Display Filter: dns && ip.src == 10.44.12.33

PACKET LIST
No.     Time          Source        Destination   Protocol Length Info
8310    0.000000000   10.44.12.33   10.20.0.53    DNS      105    Standard query 0xb041 A kJ4a9sd82Jkslqwe9ASD0a.exfil.example.net
8311    0.296000000   10.44.12.33   10.20.0.53    DNS      105    Standard query 0xb042 A L0p9zXq11293sdfAA0p9z.exfil.example.net
8312    0.593000000   10.44.12.33   10.20.0.53    DNS      105    Standard query 0xb043 A qwe8ASD90asdlkJQW8123.exfil.example.net
8313    0.895000000   10.44.12.33   10.20.0.53    DNS      105    Standard query 0xb044 A Zx91lskd0AA91kLmPq112.exfil.example.net

PACKET DETAILS - Frame 8310
Frame 8310: 105 bytes on wire (840 bits), 105 bytes captured
    Arrival Time: May 18, 2026 18:02:10.443000000 UTC
    Frame Number: 8310
    Frame Length: 105 bytes

Ethernet II
    Destination: 00:50:56:aa:00:53
    Source: 00:50:56:cc:12:33
    Type: IPv4 (0x0800)

Internet Protocol Version 4
    Source Address: 10.44.12.33
    Destination Address: 10.20.0.53
    Protocol: UDP (17)

User Datagram Protocol
    Source Port: 53531
    Destination Port: 53
    Length: 71

Domain Name System (query)
    Transaction ID: 0xb041
    Flags: 0x0100 Standard query
        0... .... .... .... = Response: Message is a query
        .... .0.. .... .... = Truncated: Message is not truncated
        .... ..0. .... .... = Recursion desired: Do query recursively
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        kJ4a9sd82Jkslqwe9ASD0a.exfil.example.net: type A, class IN
            Name: kJ4a9sd82Jkslqwe9ASD0a.exfil.example.net
            [Name Length: 47]
            [Label Count: 4]
            Type: A (Host Address) (1)
            Class: IN (0x0001)

WIRESHARK CUSTOM COLUMNS / FIELD EXPORT
frame.time_epoch      ip.src        dns.qry.name                                      dns.qry.type
1779127330.443000     10.44.12.33   kJ4a9sd82Jkslqwe9ASD0a.exfil.example.net          A
1779127330.739000     10.44.12.33   L0p9zXq11293sdfAA0p9z.exfil.example.net          A
1779127331.036000     10.44.12.33   qwe8ASD90asdlkJQW8123.exfil.example.net          A
1779127331.338000     10.44.12.33   Zx91lskd0AA91kLmPq112.exfil.example.net          A

PACKET BYTES - DNS query name preview
0000  0c 6b 4a 34 61 39 73 64 38 32 4a 6b 73 6c 71 77   .kJ4a9sd82Jkslqw
0010  65 39 41 53 44 30 61 05 65 78 66 69 6c 07 65 78   e9ASD0a.exfil.ex
0020  61 6d 70 6c 65 03 6e 65 74 00 00 01 00 01         ample.net.....

Analyst note: one long label is weak evidence by itself; repeated high-entropy labels from the same source to the same base domain are stronger.""",
        starting_rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible DNS tunneling long label"; dns.query; pcre:"/[a-z0-9]{20,}\\./i"; sid:940002; rev:1;)',
        prompt="Use the DNS evidence to separate a weak long-label match from a stronger behavior-based detection.",
        tasks=[
            {"type": "multi", "label": "Which observations are stronger than matching one long label?", "options": ["Multiple high-entropy labels", "Same source host repeats the behavior", "Same base domain appears repeatedly", "All traffic uses UDP", "The queried names appear unrelated to known business services"], "answers": [0, 1, 2, 4], "explain": "Long labels can be benign. Rate, repetition, entropy, base-domain clustering, and business context make the behavior more meaningful."},
            {"type": "multi", "label": "Which tuning improvements make sense?", "options": ["Track by source over a short time window", "Baseline/allowlist known CDN and business domains", "Consider entropy or label-count logic", "Suppress all long-label DNS queries", "Correlate with host/process telemetry"], "answers": [0, 1, 2, 4], "explain": "Good tuning adds behavior and context. Blanket suppression would hide real tunneling."},
            {"type": "rule", "label": "Write a better detection concept as a Suricata-style rule or pseudo-rule.", "required": ["alert dns", "dns.query", "detection_filter", "track by_src", "sid", "rev"], "bonus": ["pcre", "count", "seconds", "exfil.example.net"], "explain": "The key improvement is moving from a single label match toward source-tracked behavior over time."},
        ],
        explanation="This scenario teaches that DNS tunneling detection should be behavior-oriented. The evidence is not just one long query; it is repeated high-entropy labels from one workstation under the same base domain.",
        answer_points=["dns.query", "detection_filter", "track by_src", "baseline", "entropy", "triage"],
        skills=["dns", "tunneling", "thresholding", "tuning"],
    ),
    make_lab_question(
        id="lab_tls_sni_001",
        category="Traffic Scenario Lab - TLS SNI Tuning",
        mode="scenario_lab",
        difficulty=4,
        title="Suspicious outbound TLS SNI from a protected workstation",
        evidence=r"""Wireshark Packet View: tls_sni_suspect.pcap
Display Filter: tls.handshake.type == 1 && ip.src == 10.44.12.33

PACKET LIST
No.     Time          Source        Destination     Protocol Length Info
4401    0.000000000   10.44.12.33   198.51.100.77   TCP      74     51422 > 443 [SYN]
4402    0.045000000   198.51.100.77 10.44.12.33     TCP      74     443 > 51422 [SYN, ACK]
4403    0.051000000   10.44.12.33   198.51.100.77   TLSv1.2  589    Client Hello (SNI=cdn-update-sync.example)

PACKET DETAILS - Frame 4403
Frame 4403: 589 bytes on wire (4712 bits), 589 bytes captured
    Arrival Time: May 18, 2026 19:18:41.051000000 UTC
    Frame Number: 4403
    Frame Length: 589 bytes

Internet Protocol Version 4
    Source Address: 10.44.12.33
    Destination Address: 198.51.100.77
    Protocol: TCP (6)

Transmission Control Protocol
    Source Port: 51422
    Destination Port: 443
    Stream index: 18
    Flags: 0x018 (PSH, ACK)

Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 512
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 508
            Version: TLS 1.2 (0x0303)
            Random: 8c 18 1f 23 9b 27 41 0e 1d 92 65 61 ...
            Session ID Length: 32
            Cipher Suites Length: 34
            Compression Methods Length: 1
            Extensions Length: 365
            Extension: server_name (len=25)
                Type: server_name (0)
                Length: 25
                Server Name Indication extension
                    Server Name list length: 23
                    Server Name Type: host_name (0)
                    Server Name length: 21
                    Server Name: cdn-update-sync.example
            Extension: supported_groups
            Extension: signature_algorithms
            Extension: application_layer_protocol_negotiation

WIRESHARK CUSTOM COLUMNS / FIELD EXPORT
frame.time_epoch      ip.src        ip.dst          tcp.dstport   tls.handshake.extensions_server_name
1779131921.051000     10.44.12.33   198.51.100.77  443           cdn-update-sync.example

ENVIRONMENT CONTEXT
asset_role: finance workstation
known_good_update_domains: update.microsoft.com, windowsupdate.com, vendor-approved.example
new_sni_seen_before: no
same_sni_count_last_24h: 1

Analyst note: SNI is visible in the TLS ClientHello; the weak rule should not match generic "cdn" across all TLS traffic.""",
        starting_rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious TLS SNI contains cdn"; tls.sni; content:"cdn"; nocase; sid:940003; rev:1;)',
        prompt="Use the TLS evidence to tune a generic SNI rule into something operationally useful.",
        tasks=[
            {"type": "single", "label": "Why is the starting rule weak?", "options": ["cdn is too generic", "tls.sni never works", "TLS traffic cannot be inspected at all", "The source is internal"], "answer": 0, "explain": "The generic string cdn appears in lots of benign hostnames. The issue is specificity, not the SNI field itself."},
            {"type": "multi", "label": "What context should drive tuning?", "options": ["Exact SNI/FQDN", "Whether the SNI is newly observed", "Asset role", "Known-good update domains", "Packet TTL only"], "answers": [0, 1, 2, 3], "explain": "SNI detections are stronger when exact hostname, newness, asset role, and allowlists are considered."},
            {"type": "rule", "label": "Write a narrower SNI rule for this suspicious host.", "required": ["alert tls", "$HOME_NET", "$EXTERNAL_NET", "tls.sni", "cdn-update-sync.example", "sid", "rev"], "bonus": ["nocase", "flow:established,to_server"], "explain": "A useful first repair is matching the exact suspicious SNI instead of the generic string cdn."},
        ],
        explanation="This scenario teaches why generic SNI substrings are noisy. Better TLS detections use exact suspicious domains, controlled suffix logic, new-domain context, and environment allowlists.",
        answer_points=["tls.sni", "specific fqdn", "baseline", "allowlist", "asset role"],
        skills=["tls", "sni", "tuning"],
    ),
    make_lab_question(
        id="lab_http_upload_001",
        category="Traffic Scenario Lab - HTTP Upload / Possible Exfiltration",
        mode="scenario_lab",
        difficulty=4,
        title="Large outbound HTTP POST from an HR workstation",
        evidence=r"""Wireshark Packet View: outbound_upload.pcap
Display Filter: http.request.method == "POST" && ip.src == 10.44.12.33

PACKET LIST
No.      Time          Source        Destination     Protocol Length Info
12044    0.000000000   10.44.12.33   203.0.113.200   HTTP     1514   POST /upload.php HTTP/1.1  (application/octet-stream)
12045    0.002000000   10.44.12.33   203.0.113.200   TCP      1514   50611 > 8080 [PSH, ACK] Seq=1461 Len=1460
12046    0.005000000   10.44.12.33   203.0.113.200   TCP      1514   50611 > 8080 [PSH, ACK] Seq=2921 Len=1460
12087    4.684000000   203.0.113.200 10.44.12.33     HTTP     227    HTTP/1.1 200 OK

PACKET DETAILS - Frame 12044
Frame 12044: 1514 bytes on wire (12112 bits), 1514 bytes captured
    Arrival Time: May 18, 2026 19:05:44.228000000 UTC
    Frame Number: 12044
    Frame Length: 1514 bytes

Internet Protocol Version 4
    Source Address: 10.44.12.33
    Destination Address: 203.0.113.200
    Protocol: TCP (6)

Transmission Control Protocol
    Source Port: 50611
    Destination Port: 8080
    Stream index: 77
    Flags: 0x018 (PSH, ACK)
    TCP payload (1460 bytes)

Hypertext Transfer Protocol
    POST /upload.php HTTP/1.1\r\n
    Host: files-sync.example.net\r\n
    User-Agent: python-requests/2.31.0\r\n
    Content-Type: application/octet-stream\r\n
    Content-Length: 7340032\r\n
    \r\n
    [Request Method: POST]
    [Request URI: /upload.php]
    [Full request URI: http://files-sync.example.net:8080/upload.php]
    [HTTP request 1/1]

FOLLOW TCP STREAM - tcp.stream eq 77 - ASCII
Client 10.44.12.33:50611 -> Server 203.0.113.200:8080
POST /upload.php HTTP/1.1
Host: files-sync.example.net
User-Agent: python-requests/2.31.0
Content-Type: application/octet-stream
Content-Length: 7340032

PK........BEGIN_ARCHIVE
payroll_export_q2.xlsx
employee_roster.csv

Server 203.0.113.200:8080 -> Client 10.44.12.33:50611
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 37

upload complete

PACKET BYTES - First 128 bytes of HTTP body
0000  50 4b 03 04 14 00 00 00 08 00 8a 9b b8 58 00 00   PK...........X..
0010  00 00 00 00 00 00 00 00 15 00 00 00 70 61 79 72   ............payr
0020  6f 6c 6c 5f 65 78 70 6f 72 74 5f 71 32 2e 78 6c   oll_export_q2.xl
0030  73 78 65 6d 70 6c 6f 79 65 65 5f 72 6f 73 74 65   sxemployee_roste
0040  72 2e 63 73 76 00 00 00 00 00 00 00 00 00 00 00   r.csv...........

ENVIRONMENT CONTEXT
asset_role: HR workstation
approved_file_sync_domain: no
same_destination_seen_before: no
large_posts_to_same_host_last_hour: 4

Analyst note: the HTTP method, destination, User-Agent, content length, asset role, and file-name strings all matter more than size alone.""",
        starting_rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Large HTTP POST"; http.method; content:"POST"; dsize:>1000; sid:940004; rev:1;)',
        prompt="Use the upload evidence to improve a noisy size-only rule and decide what to validate next.",
        tasks=[
            {"type": "multi", "label": "Which evidence makes this more suspicious than a normal upload?", "options": ["Large Content-Length", "HR workstation source", "Unknown external destination", "python-requests User-Agent", "Filenames look like HR data", "HTTP status 200"], "answers": [0, 1, 2, 3, 4], "explain": "The activity is concerning because of size, source role, unknown destination, automation-like UA, and payload clues. Status 200 means it likely succeeded but is not suspicious by itself."},
            {"type": "multi", "label": "What should a better detection include?", "options": ["Outbound HOME_NET to EXTERNAL_NET direction", "http.method POST", "http.user_agent python-requests", "Known-good destination allowlist", "dsize only with no other context"], "answers": [0, 1, 2, 3], "explain": "Size alone is noisy. Combine direction, method, User-Agent/context, and destination baselining."},
            {"type": "rule", "label": "Write a stronger rule or pseudo-rule for suspicious outbound automated upload.", "required": ["alert http", "$HOME_NET", "$EXTERNAL_NET", "http.method", "post", "http.user_agent", "python-requests", "sid", "rev"], "bonus": ["dsize", "flow:established,to_server", "upload.php"], "explain": "A better rule narrows the condition to outbound POST plus automation context rather than alerting on every large POST."},
        ],
        explanation="This scenario teaches that exfil-style detections should combine traffic direction, method, size, destination reputation/baseline, source asset role, and payload clues. A size-only alert is rarely enough.",
        answer_points=["http.method", "http.user_agent", "dsize", "baseline", "asset role", "triage"],
        skills=["http", "exfiltration", "tuning", "triage"],
    ),
]

INVESTIGATION_CAPSTONES = TRAFFIC_DRIVEN_LABS

# ------------------------------------------------------------
# Banks / lessons
# ------------------------------------------------------------

CORE_QUESTIONS = list(getattr(trainer, "ALL_QUESTIONS", []))


# ------------------------------------------------------------
# Real PCAP evidence labs - IceMaiden / Malware Traffic Analysis exercise
# These replace synthetic packet text with evidence modeled from the uploaded
# 2019-12-03 traffic analysis PCAP.
# ------------------------------------------------------------

REAL_PCAP_LABS = [
    make_lab_question(
        id="real_pcap_001",
        category="Real PCAP Lab - HTTP Object Download",
        mode="scenario_lab",
        difficulty=3,
        title="Suspicious HTTP object download from real packet evidence",
        evidence=r"""Source capture: 2019-12-03-traffic-analysis-exercise.pcap
Display filter: http.request || http.response

Packet List
No.     Time                 Source          Destination     Protocol  Length  Info
15971   22:50:40.713801     10.18.20.97     8.208.24.139    HTTP      179     GET /jvassets/xI/t64.dat HTTP/1.1
15973   22:50:41.014552     8.208.24.139    10.18.20.97     HTTP      1424    HTTP/1.1 200 OK  (application/octet-stream)

Packet Details - Frame 15971
Frame 15971: 179 bytes on wire, 179 bytes captured
Internet Protocol Version 4
    Source Address: 10.18.20.97
    Destination Address: 8.208.24.139
Transmission Control Protocol
    Source Port: 49598
    Destination Port: 80
Hypertext Transfer Protocol
    GET /jvassets/xI/t64.dat HTTP/1.1
    Cache-Control: no-cache
    Connection: Keep-Alive
    Pragma: no-cache
    Host: api2.casus.at

Follow TCP Stream - ASCII
GET /jvassets/xI/t64.dat HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Host: api2.casus.at

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 03 Dec 2019 22:50:40 GMT
Content-Type: application/octet-stream
Content-Length: 138820
Last-Modified: Mon, 28 Oct 2019 09:43:42 GMT
Connection: close
ETag: "5db6b84e-21e44"
Accept-Ranges: bytes

Packet Bytes - payload preview
0000  47 45 54 20 2f 6a 76 61 73 73 65 74 73 2f 78 49   GET /jvassets/xI
0010  2f 74 36 34 2e 64 61 74 20 48 54 54 50 2f 31 2e   /t64.dat HTTP/1.
0020  31 0d 0a 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c   1..Cache-Control
0030  3a 20 6e 6f 2d 63 61 63 68 65 0d 0a 43 6f 6e 6e   : no-cache..Conn

""",
        starting_rule='alert http any any -> any any (msg:"DAT download observed"; content:".dat"; sid:940001; rev:1;)',
        prompt="Use the packet evidence to decide which fields are useful and repair the weak .dat download rule.",
        tasks=[
            {"type": "single", "label": "Which field contains the suspicious object path?", "options": ["http.uri", "http.host", "http.user_agent", "dns.query"], "answer": 0, "explain": "The object path /jvassets/xI/t64.dat is in the HTTP URI."},
            {"type": "multi", "label": "Which evidence makes this more useful than matching only .dat?", "options": ["Host is api2.casus.at", "URI path is /jvassets/xI/t64.dat", "Response Content-Type is application/octet-stream", "Response Content-Length is 138820", "The traffic is HTTP"], "answers": [0,1,2,3], "explain": "The useful context is host, path, object type, and size. HTTP alone is not suspicious."},
            {"type": "rule", "label": "Write a better starting Suricata rule for this observed download.", "required": ["alert http", "$HOME_NET", "$EXTERNAL_NET", "flow:established,to_server", "http.host", "api2.casus.at", "http.uri", "t64.dat", "sid", "rev"], "bonus": ["/jvassets/xI/", "nocase"], "explain": "A stronger rule scopes host and URI instead of matching .dat anywhere in the payload."},
        ],
        explanation="This lab uses real HTTP evidence. The main lesson is field selection: use http.host for api2.casus.at and http.uri for the object path. A raw .dat content rule would be noisy and could match unrelated traffic.",
        answer_points=["http.host", "api2.casus.at", "http.uri", "t64.dat", "flow:established,to_server"],
        skills=["pcap_analysis", "http_buffers", "rule_repair", "traffic_reading"],
    ),

    make_lab_question(
        id="real_pcap_002",
        category="Real PCAP Lab - HTTP C2 Pattern",
        mode="scenario_lab",
        difficulty=4,
        title="Repeated encoded HTTP API paths to suspicious infrastructure",
        evidence=r"""Source capture: 2019-12-03-traffic-analysis-exercise.pcap
Display filter: http.request && ip.addr == 8.208.24.139

Packet List
No.     Time                 Source          Destination     Protocol  Length  Info
15956   22:50:34.456567     10.18.20.97     8.208.24.139    HTTP      626     GET /api1/yHuijzBzQc46MJ8Hh_2B3To/... HTTP/1.1
16153   22:50:55.515761     10.18.20.97     8.208.24.139    HTTP      602     GET /api1/QgPIxa1ctWDK/QU9lAhPb2iw/... HTTP/1.1
16164   22:50:56.606666     10.18.20.97     8.208.24.139    HTTP      651     POST /api1/NdyKQBz2bkQyWRjW/DQxAC7LX... HTTP/1.1
16183   22:50:57.706168     10.18.20.97     8.208.24.139    HTTP      692     POST /api1/4G0Wr6wO0HVb0ZSY2qm1/... HTTP/1.1
16200   22:51:08.944041     10.18.20.97     8.208.24.139    HTTP      692     POST /api1/vkxyxZ87Twi_2Fn1PHKp/... HTTP/1.1

Packet Details - Frame 16164
Frame 16164: 651 bytes on wire, 651 bytes captured
Internet Protocol Version 4
    Source Address: 10.18.20.97
    Destination Address: 8.208.24.139
Transmission Control Protocol
    Source Port: 49600
    Destination Port: 80
Hypertext Transfer Protocol
    POST /api1/NdyKQBz2bkQyWRjW/DQxAC7LXQQhux0L/.../E HTTP/1.1
    Cache-Control: no-cache
    Connection: Keep-Alive
    Pragma: no-cache
    Host: h1.wensa.at
    User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
    Content-Length: 2

Follow TCP Stream - ASCII
POST /api1/NdyKQBz2bkQyWRjW/DQxAC7LXQQhux0L/JG8Hy_2FKtggSPly52/OI_2Bww0d/.../E HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Host: h1.wensa.at
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Content-Length: 2

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 03 Dec 2019 22:50:57 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: close
Strict-Transport-Security: max-age=63072000; includeSubdomains
X-Content-Type-Options: nosniff

21
0xc41d3da7_5db44dadcf467|GET_MAIL
0

""",
        starting_rule='alert http any any -> any any (msg:"Suspicious API path"; content:"/api1/"; sid:940002; rev:1;)',
        prompt="Use the repeated HTTP evidence to turn a weak raw content match into a more defensible C2-style detection.",
        tasks=[
            {"type": "multi", "label": "Which evidence supports treating this as suspicious C2-style traffic?", "options": ["Multiple requests to 8.208.24.139", "Repeated /api1/ paths with long encoded-looking segments", "Host h1.wensa.at", "HTTP 200 response containing GET_MAIL-like tasking", "Any URL containing /api1/ is malicious"], "answers": [0,1,2,3], "explain": "The pattern is suspicious because of repeated encoded-looking API paths, suspicious host/IP, and tasking-like response content. /api1/ alone is not enough."},
            {"type": "multi", "label": "Which Suricata buffers are most useful here?", "options": ["http.host", "http.uri", "http.method", "dns.query", "tls.sni", "http.response_body"], "answers": [0,1,2], "explain": "The evidence gives host, URI, and method. Response-body inspection could be useful in some environments, but start with request-side scoping."},
            {"type": "rule", "label": "Write a better rule using host and URI scoping.", "required": ["alert http", "$HOME_NET", "$EXTERNAL_NET", "flow:established,to_server", "http.host", "h1.wensa.at", "http.uri", "/api1/", "sid", "rev"], "bonus": ["http.method", "POST", "nocase"], "explain": "The improved rule should scope /api1/ to http.uri and h1.wensa.at to http.host, with outbound direction from protected hosts."},
        ],
        explanation="This lab is based on real repeated HTTP traffic in the PCAP. The goal is to avoid matching a generic path in raw payload and instead tie the detection to host, URI, direction, and repeated behavior.",
        answer_points=["http.host", "h1.wensa.at", "http.uri", "/api1/", "flow:established,to_server", "$HOME_NET"],
        skills=["pcap_analysis", "http_c2", "rule_writing", "tuning"],
    ),

    make_lab_question(
        id="real_pcap_003",
        category="Real PCAP Lab - Multipart POST",
        mode="scenario_lab",
        difficulty=4,
        title="Multipart HTTP POST: identify method, body, and tuning opportunities",
        evidence=r"""Source capture: 2019-12-03-traffic-analysis-exercise.pcap
Display filter: http.request.method == "POST" && http.host == "h1.wensa.at"

Packet List
No.     Time                 Source          Destination     Protocol  Length  Info
16183   22:50:57.706168     10.18.20.97     8.208.24.139    HTTP      692     POST /api1/4G0Wr6wO0HVb0ZSY2qm1/... HTTP/1.1  (multipart/form-data)
16187   22:50:58.487919     8.208.24.139    10.18.20.97     HTTP      337     HTTP/1.1 200 OK

Packet Details - Frame 16183
Frame 16183: 692 bytes on wire, 692 bytes captured
Internet Protocol Version 4
    Source Address: 10.18.20.97
    Destination Address: 8.208.24.139
Transmission Control Protocol
    Source Port: 49601
    Destination Port: 80
Hypertext Transfer Protocol
    POST /api1/4G0Wr6wO0HVb0ZSY2qm1/K1Uti_2FLNMYqzVrRDZ/.../5p6 HTTP/1.1
    Cache-Control: no-cache
    Connection: Keep-Alive
    Pragma: no-cache
    Content-Type: multipart/form-data; boundary=37498497774264187347545117518
    Host: h1.wensa.at
    User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
    Content-Length: 204

Follow TCP Stream - ASCII
POST /api1/4G0Wr6wO0HVb0ZSY2qm1/K1Uti_2FLNMYqzVrRDZ/.../5p6 HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: multipart/form-data; boundary=37498497774264187347545117518
Host: h1.wensa.at
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Content-Length: 204

--37498497774264187347545117518
Content-Disposition: form-data; name="file"; filename="blob"
Content-Type: application/octet-stream

<204 bytes of binary/form data observed>
--37498497774264187347545117518--

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 03 Dec 2019 22:50:58 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: close

""",
        starting_rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP upload"; http.method; content:"POST"; sid:940003; rev:1;)',
        prompt="Use the POST evidence to build a better detection than simply alerting on every outbound HTTP POST.",
        tasks=[
            {"type": "multi", "label": "Which fields should shape a stronger rule?", "options": ["http.method POST", "http.host h1.wensa.at", "http.uri /api1/", "http.header Content-Type multipart/form-data", "Raw content anywhere", "Destination IP/asset context"], "answers": [0,1,2,3,5], "explain": "A production rule should combine method, host, URI, content type, direction, and environment context."},
            {"type": "single", "label": "Why is the starting rule noisy?", "options": ["POST is common in normal web traffic", "http.method never works", "The destination port is invalid", "multipart/form-data is always malicious"], "answer": 0, "explain": "POST alone is extremely common. The context around the POST matters."},
            {"type": "rule", "label": "Write a tuned rule for this observed POST pattern.", "required": ["alert http", "$HOME_NET", "$EXTERNAL_NET", "flow:established,to_server", "http.method", "POST", "http.host", "h1.wensa.at", "http.uri", "/api1/", "sid", "rev"], "bonus": ["http.header", "multipart/form-data", "Content-Type"], "explain": "The stronger rule targets the observed destination behavior instead of all POST requests."},
        ],
        explanation="This lab forces the analyst to distinguish between a common method and suspicious context. POST is normal; repeated POSTs to h1.wensa.at with long encoded API paths and multipart payloads are much more useful.",
        answer_points=["POST", "http.host", "h1.wensa.at", "http.uri", "/api1/", "multipart/form-data"],
        skills=["http_post", "rule_tuning", "http_buffers", "pcap_analysis"],
    ),

    make_lab_question(
        id="real_pcap_004",
        category="Real PCAP Lab - DNS to HTTP Pivot",
        mode="scenario_lab",
        difficulty=4,
        title="Pivot from DNS questions to HTTP sessions",
        evidence=r"""Source capture: 2019-12-03-traffic-analysis-exercise.pcap
Display filters:
  dns.qry.name contains "wensa" || dns.qry.name contains "casus"
  http.host contains "wensa" || http.host contains "casus"

DNS Packet List
No.     Time                 Source          Destination     Protocol  Info
15280   22:50:25.196289     10.18.20.97     193.183.98.66   DNS       Standard query A w8.wensa.at
15281   22:50:25.403718     193.183.98.66   10.18.20.97     DNS       Standard query response A w8.wensa.at
15966   22:50:40.200051     10.18.20.97     193.183.98.66   DNS       Standard query A api2.casus.at
15967   22:50:40.498835     193.183.98.66   10.18.20.97     DNS       Standard query response A api2.casus.at
16148   22:50:55.165434     10.18.20.97     193.183.98.66   DNS       Standard query A h1.wensa.at
16149   22:50:55.357740     193.183.98.66   10.18.20.97     DNS       Standard query response A h1.wensa.at

HTTP Packet List
No.     Time                 Source          Destination     Protocol  Info
15288   22:50:25.959473     10.18.20.97     8.208.24.139    HTTP      GET /api1/PUbKL64xdNDApQ_2FhOvR/... Host: w8.wensa.at
15971   22:50:40.713801     10.18.20.97     8.208.24.139    HTTP      GET /jvassets/xI/t64.dat Host: api2.casus.at
16164   22:50:56.606666     10.18.20.97     8.208.24.139    HTTP      POST /api1/NdyKQBz2bkQyWRjW/... Host: h1.wensa.at

Decoded DNS detail - Frame 16148
Domain Name System (query)
    Transaction ID: 0x????
    Flags: 0x0100 Standard query
    Questions: 1
    Queries
        h1.wensa.at: type A, class IN

Analyst pivot note
The same protected workstation resolves w8.wensa.at, api2.casus.at, and h1.wensa.at, then connects to 8.208.24.139 over HTTP within seconds.

""",
        starting_rule='alert dns any any -> any any (msg:"Suspicious domain"; content:"wensa"; sid:940004; rev:1;)',
        prompt="Use DNS and HTTP evidence together. Build detection logic that supports pivoting instead of matching one raw string anywhere.",
        tasks=[
            {"type": "multi", "label": "Which pivots would you perform from this evidence?", "options": ["Search DNS for related wensa/casus domains", "Pivot from domains to HTTP Host headers", "Check all traffic from 10.18.20.97 around 22:50 UTC", "Suppress the DNS rule because content matching is imperfect", "Look for repeated HTTP /api1/ paths"], "answers": [0,1,2,4], "explain": "DNS-to-HTTP pivoting helps connect resolution activity to actual network sessions."},
            {"type": "multi", "label": "Which rule-scoping improvements are better than raw content:wensa?", "options": ["Use dns.query for DNS rules", "Use http.host for HTTP host detections", "Use $HOME_NET -> $EXTERNAL_NET for outbound activity", "Use any any -> any any everywhere", "Use specific domain values or suffix logic"], "answers": [0,1,2,4], "explain": "The same indicator may appear in DNS and HTTP, but the correct buffers are different."},
            {"type": "rule", "label": "Write either a DNS or HTTP rule that is properly scoped for this evidence.", "required": ["alert", "sid", "rev"], "bonus": ["dns.query", "h1.wensa.at", "http.host", "api2.casus.at", "$HOME_NET", "$EXTERNAL_NET"], "explain": "A valid answer could target dns.query for h1.wensa.at or http.host for h1.wensa.at/api2.casus.at. The important part is correct buffer scoping."},
        ],
        explanation="This lab shows how analysts pivot from DNS to HTTP. Good detection content is not just the string; it is the right string in the right protocol field, with direction and context.",
        answer_points=["dns.query", "http.host", "wensa.at", "casus.at", "pivot", "$HOME_NET"],
        skills=["dns", "http_host", "pivoting", "pcap_analysis", "rule_scoping"],
    ),
]

TRAFFIC_DRIVEN_LABS = REAL_PCAP_LABS
INVESTIGATION_CAPSTONES = REAL_PCAP_LABS
# Keep the original advanced single-question scenarios, but remove older prototype lab objects from this bucket.
ADVANCED_SCENARIOS = [q for q in ADVANCED_SCENARIOS if not str(getattr(q, "mode", "")).endswith("lab")]

BASE_BANKS = {
    "Adaptive Mixed": CORE_QUESTIONS + SUPPLEMENTAL_SCENARIOS + ADVANCED_SCENARIOS + TRAFFIC_DRIVEN_LABS,
    "Beginner - Variables & Structure": list(getattr(trainer, "VARIABLES_AND_STRUCTURE", [])) + [q for q in SUPPLEMENTAL_SCENARIOS if "Variables" in q.category or "Direction" in q.category],
    "Rule Reading": list(getattr(trainer, "RULE_READING", [])) + [q for q in SUPPLEMENTAL_SCENARIOS if q.mode == "read"],
    "Optimization / Tuning": list(getattr(trainer, "OPTIMIZATION", [])) + [q for q in SUPPLEMENTAL_SCENARIOS if q.mode == "optimize"],
    "Rule Writing": list(getattr(trainer, "WRITING", [])) + [q for q in SUPPLEMENTAL_SCENARIOS if q.mode == "write"],
    "Rule Repair": list(getattr(trainer, "REPAIR", [])) + [q for q in SUPPLEMENTAL_SCENARIOS if q.mode == "repair"],
    "Scenario Practice - Analyst Decisions": SUPPLEMENTAL_SCENARIOS,
    "Advanced - Realistic Tuning & Repair": ADVANCED_SCENARIOS,
    "Investigation Capstones": INVESTIGATION_CAPSTONES,
    "Traffic Scenario Labs": TRAFFIC_DRIVEN_LABS,
}

LESSONS = {
    "Network Variables": getattr(trainer, "NETWORK_VARIABLES_LESSON", ""),
    "Rule Building": getattr(trainer, "RULE_BUILDING_LESSON", ""),
    "Buffers": getattr(trainer, "BUFFER_LESSON", ""),
    "Tuning": getattr(trainer, "TUNING_LESSON", ""),
}

LESSON_META = {
    "Network Variables": {
        "objective": "Understand how HOME_NET, EXTERNAL_NET, and directional scoping make rules more operational.",
        "why": "Network variables help analysts describe the direction and purpose of traffic. This is usually the first tuning step before adding more complicated detection logic.",
        "practice_module": "Beginner - Variables & Structure",
        "knowledge_terms": ["$HOME_NET", "$EXTERNAL_NET", "direction", "noise", "protected"],
        "takeaways": [
            "$HOME_NET usually represents the networks you defend.",
            "$EXTERNAL_NET usually represents networks outside the protected environment.",
            "Inbound and outbound rules answer different SOC questions, so direction should be intentional.",
            "Using any any -> any any is acceptable for early labs, but it is usually too broad for operational rules.",
        ],
        "analyst_note": "When reviewing a rule, first ask: who is the source, who is the destination, and is this meant to detect inbound, outbound, or lateral behavior?",
        "bad_good": [
            {
                "weak_label": "Lab-only broad direction",
                "weak_code": "alert http any any -> any any (...) ",
                "weak_reason": "This can be useful in a classroom because it avoids network assumptions, but in production it can fire in every direction and create unnecessary noise.",
                "better_label": "Operational inbound direction",
                "better_code": "alert http $EXTERNAL_NET any -> $HOME_NET any (...) ",
                "better_reason": "This clearly describes external traffic going toward protected networks, which is easier to triage and tune.",
            },
            {
                "weak_label": "No protected-network context",
                "weak_code": "alert dns any any -> any any (...) ",
                "weak_reason": "The rule does not say whether a protected host is asking the query or receiving it.",
                "better_label": "Operational outbound DNS direction",
                "better_code": "alert dns $HOME_NET any -> $EXTERNAL_NET any (...) ",
                "better_reason": "This describes an internal/protected host making an outbound DNS query, which is usually what the analyst cares about.",
            },
        ],
    },
    "Rule Building": {
        "objective": "Break a Suricata rule into action, protocol, source, destination, direction, and options.",
        "why": "Analysts need to read rules quickly during tuning, validation, alert triage, and peer review. Understanding the rule shape makes it easier to spot weak logic.",
        "practice_module": "Rule Writing",
        "knowledge_terms": ["alert", "protocol", "->", "msg", "sid", "rev"],
        "takeaways": [
            "The rule header defines traffic scope before the option block runs.",
            "The option block should explain what the rule detects and how it detects it.",
            "msg, sid, and rev make rules easier to review, maintain, and update.",
            "A rule can be syntactically valid but still operationally weak.",
        ],
        "analyst_note": "During peer review, separate syntax from detection value. A rule can run successfully and still be too broad, too noisy, or unclear.",
        "bad_good": [
            {
                "weak_label": "Valid shape, weak detection",
                "weak_code": "alert ip any any -> any any (sid:1;) ",
                "weak_reason": "This has a basic rule shape, but it has no meaningful condition, message, or operational context.",
                "better_label": "Scoped and explainable rule",
                "better_code": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Admin path access"; http.uri; content:"/admin"; sid:100001; rev:1;) ',
                "better_reason": "This tells the analyst what is being detected, where the match is scoped, and which direction the traffic is moving.",
            },
        ],
    },
    "Buffers": {
        "objective": "Choose the correct inspection buffer instead of relying on broad raw content matches.",
        "why": "Buffer scoping is one of the biggest differences between noisy rules and rules analysts can trust. It tells Suricata exactly where to look.",
        "practice_module": "Rule Reading",
        "knowledge_terms": ["http.uri", "http.method", "dns.query", "tls.sni", "buffer", "content"],
        "takeaways": [
            "http.uri is for request paths and parameters, not the entire payload.",
            "http.method is for GET, POST, PUT, DELETE, and similar request methods.",
            "dns.query is for the queried domain name, not DNS answers.",
            "tls.sni is visible during the TLS handshake and is different from HTTP Host.",
        ],
        "analyst_note": "Before writing content:\"something\", ask where that something should appear. If you can scope it to a buffer, you probably should.",
        "bad_good": [
            {
                "weak_label": "Unscoped content match",
                "weak_code": 'content:"admin"; ',
                "weak_reason": "This can match unrelated body text, comments, scripts, responses, or other data that is not actually an admin path.",
                "better_label": "URI-scoped match",
                "better_code": 'http.uri; content:"/admin"; ',
                "better_reason": "This searches the request URI/path, which is where admin page access is expected.",
            },
            {
                "weak_label": "Wrong protocol field",
                "weak_code": 'alert tls any any -> any any (http.host; content:"bad.example"; sid:1;) ',
                "weak_reason": "HTTP Host and TLS SNI are different fields. This mixes TLS traffic with an HTTP buffer.",
                "better_label": "Correct TLS hostname field",
                "better_code": 'alert tls any any -> any any (tls.sni; content:"bad.example"; sid:1;) ',
                "better_reason": "This checks the hostname exposed in the TLS ClientHello SNI field.",
            },
        ],
    },
    "Tuning": {
        "objective": "Reduce false positives while preserving detection value.",
        "why": "Tuning is where analysts turn signatures into useful operational detections instead of alert floods. The goal is not fewer alerts at all costs; the goal is better signal.",
        "practice_module": "Optimization / Tuning",
        "knowledge_terms": ["false positive", "scope", "specific", "threshold", "baseline", "flow"],
        "takeaways": [
            "Start with scope: buffer, direction, and network variables.",
            "Generic strings like login, cdn, Mozilla, or id= are rarely enough alone.",
            "Behavioral detections often need rate, repetition, asset context, or allowlists.",
            "Do not blindly suppress a noisy rule until you understand what is creating the noise.",
        ],
        "analyst_note": "Good tuning preserves the detection intent. Bad tuning simply hides alerts without understanding the behavior.",
        "bad_good": [
            {
                "weak_label": "Overly common User-Agent value",
                "weak_code": 'http.user_agent; content:"Mozilla"; ',
                "weak_reason": "Mozilla appears in huge amounts of normal browser traffic, so this rule would likely be noisy and low-value.",
                "better_label": "More targeted User-Agent logic",
                "better_code": 'flow:established,to_server; http.user_agent; content:"curl"; nocase; ',
                "better_reason": "This is still simple, but it is more explainable because it targets client-to-server traffic and a more specific automation tool string.",
            },
            {
                "weak_label": "Generic hostname fragment",
                "weak_code": 'tls.sni; content:"cdn"; nocase; ',
                "weak_reason": "CDN strings are common in legitimate traffic and will likely create avoidable false positives.",
                "better_label": "Specific hostname or controlled suffix",
                "better_code": 'tls.sni; content:"suspicious-example.com"; endswith; nocase; ',
                "better_reason": "Specific hostnames, controlled suffixes, or known-bad indicators are easier to justify and tune.",
            },
        ],
    },
}
LESSON_ORDER = list(LESSONS.keys())

# ------------------------------------------------------------
# Progress helpers
# ------------------------------------------------------------

def fresh_progress():
    return {
        "questions": {},
        "skills": {},
        "sessions": [],
        "web": {"version": APP_VERSION, "lessons_completed": [], "question_history": []},
    }


def load_web_progress():
    if PROGRESS_FILE.exists():
        try:
            data = json.loads(PROGRESS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "questions" in data:
                return data
        except Exception:
            pass
    return fresh_progress()


def save_web_progress():
    try:
        PROGRESS_FILE.write_text(json.dumps(st.session_state.progress, indent=2), encoding="utf-8")
    except Exception:
        # app Cloud or locked-down environments may not allow persistent writes.
        pass


def get_progress():
    if "progress" not in st.session_state:
        st.session_state.progress = load_web_progress()
    return st.session_state.progress


def global_summary(progress):
    if hasattr(trainer, "global_stats"):
        return trainer.global_stats(progress)
    qs = progress.get("questions", {})
    seen = sum(v.get("seen", 0) for v in qs.values())
    correct = sum(v.get("correct", 0) for v in qs.values())
    wrong = sum(v.get("wrong", 0) for v in qs.values())
    mastered = sum(1 for v in qs.values() if v.get("mastery", 0) >= 5)
    accuracy = round((correct / seen) * 100, 1) if seen else 0.0
    return {"seen": seen, "correct": correct, "wrong": wrong, "mastered": mastered, "accuracy": accuracy}


def all_questions_by_id():
    combined = []
    for bank in BASE_BANKS.values():
        combined.extend(bank)
    return {q.id: q for q in combined}


def filtered_bank():
    bank_name = st.session_state.get("bank_name", "Adaptive Mixed")
    if bank_name == "Review Missed / Remediation":
        qmap = all_questions_by_id()
        return [qmap[qid] for qid in st.session_state.get("missed_ids", []) if qid in qmap]

    bank = list(BASE_BANKS.get(bank_name, []))
    difficulty_filter = st.session_state.get("difficulty_filter", "All")
    if difficulty_filter != "All":
        try:
            diff = int(difficulty_filter)
            bank = [q for q in bank if int(getattr(q, "difficulty", 1)) == diff]
        except Exception:
            pass
    return bank


def select_question():
    bank = filtered_bank()
    if not bank:
        return None

    current_id = getattr(st.session_state.get("question", None), "id", None)
    bank_name = st.session_state.get("bank_name", "Adaptive Mixed")

    # Avoid immediate repeats and avoid cycling the same small set unless the selected
    # bank is intentionally remediation-only.
    if len(bank) > 1:
        bank = [q for q in bank if q.id != current_id] or bank

    recent_ids = st.session_state.get("recent_question_ids", [])[-8:]
    if bank_name != "Review Missed / Remediation" and len(bank) > len(recent_ids):
        reduced = [q for q in bank if q.id not in recent_ids]
        if reduced:
            bank = reduced

    # In remediation, prioritize missed questions that have not been reviewed recently,
    # but still allow movement instead of trapping the learner.
    if bank_name == "Review Missed / Remediation":
        reduced = [q for q in bank if q.id not in recent_ids]
        return random.choice(reduced or bank)

    adaptive = st.session_state.get("adaptive", True)
    if adaptive and hasattr(trainer, "pick_questions"):
        try:
            picked = trainer.pick_questions(bank, 1, True, get_progress())
            return picked[0] if picked else random.choice(bank)
        except Exception:
            return random.choice(bank)
    return random.choice(bank)


def reset_current_question():
    next_q = select_question()
    st.session_state.question = next_q
    if next_q is not None:
        recent = st.session_state.setdefault("recent_question_ids", [])
        recent.append(next_q.id)
        st.session_state.recent_question_ids = recent[-12:]
    st.session_state.answer_key_counter = st.session_state.get("answer_key_counter", 0) + 1
    st.session_state.feedback = None
    st.session_state.issues = []
    st.session_state.show_explanation = False
    st.session_state.hint_index = 0
    st.session_state.hints_used = 0
    st.session_state.current_hint = None
    st.session_state.revealed = False


def score_answer(answer, q):
    mode = st.session_state.get("grading_mode", "Standard")
    if mode == "Strict":
        a = answer.lower()
        missing = [term for term in getattr(q, "required_terms", []) if term.lower() not in a]
        accepted_hit = any(term.lower() in a for term in getattr(q, "accepted_terms", []))
        point_hit = any(point.lower() in a for point in getattr(q, "answer_points", []))
        ok = not missing and (point_hit or accepted_hit or bool(getattr(q, "required_terms", [])))
        issues = [f"Missing required element: {m}" for m in missing]
        if not ok and not issues:
            issues.append("Strict mode: answer did not hit enough expected concepts.")
        return ok, issues

    if hasattr(trainer, "score_answer"):
        return trainer.score_answer(answer, q)

    a = answer.lower()
    required = [x.lower() for x in getattr(q, "required_terms", [])]
    accepted = [x.lower() for x in getattr(q, "accepted_terms", [])]
    answer_points = [x.lower() for x in getattr(q, "answer_points", [])]
    missing = [term for term in required if term not in a]
    point_hit = any(p in a for p in answer_points)
    accepted_hit = any(t in a for t in accepted)
    ok = not missing and (point_hit or accepted_hit or bool(required))
    issues = [f"Missing required element: {m}" for m in missing]
    if not ok and not issues:
        issues.append("Your answer missed the main detection concept.")
    return ok, issues


def record_attempt(q, ok, skipped=False):
    progress = get_progress()
    if hasattr(trainer, "update_stats"):
        trainer.update_stats(progress, q, ok, st.session_state.hints_used)

    progress.setdefault("sessions", []).append({
        "time": datetime.now().isoformat(timespec="seconds"),
        "question_id": q.id,
        "category": q.category,
        "mode": q.mode,
        "difficulty": q.difficulty,
        "ok": ok,
        "skipped": skipped,
        "hints_used": st.session_state.hints_used,
        "module": st.session_state.get("bank_name", ""),
    })

    if not ok or skipped:
        missed = st.session_state.setdefault("missed_ids", [])
        if q.id not in missed:
            missed.append(q.id)
    elif q.id in st.session_state.get("missed_ids", []):
        st.session_state.missed_ids.remove(q.id)

    save_web_progress()


def progress_download_blob():
    return json.dumps(get_progress(), indent=2)


def completed_lessons():
    progress = get_progress()
    progress.setdefault("web", {}).setdefault("lessons_completed", [])
    return progress["web"]["lessons_completed"]


def mark_lesson_complete(lesson_name):
    lessons_done = completed_lessons()
    if lesson_name not in lessons_done:
        lessons_done.append(lesson_name)
    save_web_progress()


def lesson_progress_percent():
    total = len(LESSON_ORDER) or 1
    return round((len(completed_lessons()) / total) * 100)


def set_training_module(module_name, view="Train", lesson_context=None):
    request_scroll_to_top()
    st.session_state.bank_name = module_name
    st.session_state.view = view
    if lesson_context:
        st.session_state.return_lesson = lesson_context
        st.session_state.selected_lesson = lesson_context
    reset_current_question()


def normalize_code_text(value):
    """Normalize rule, traffic, and packet-like evidence into plain text for one green code block."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = "\n".join(normalize_code_text(v) for v in value)
    elif isinstance(value, dict):
        parts = []
        for k, v in value.items():
            if isinstance(v, (dict, list, tuple)):
                parts.append(f"{k}:")
                parts.append(normalize_code_text(v))
            else:
                parts.append(f"{k}: {v}")
        value = "\n".join(parts)
    else:
        value = str(value)

    clean = value.replace(",[object Object],", "\n")
    clean = clean.replace("[object Object]", "")
    clean = clean.replace("\r\n", "\n").replace("\r", "\n")

    lines = [line.rstrip() for line in clean.split("\n")]
    normalized = []
    blank_seen = False
    for line in lines:
        if not line.strip():
            if not blank_seen:
                normalized.append("")
            blank_seen = True
        else:
            normalized.append(line)
            blank_seen = False
    return "\n".join(normalized).strip("\n")

def render_code_box(content, label: str = "Evidence / syntax"):
    """Render code/packet evidence with preserved whitespace and one consistent green style."""
    clean = normalize_code_text(content)
    label_text = str(label or "Evidence / syntax")
    st.markdown(f"<div class='green-code-label'>{html.escape(label_text)}</div>", unsafe_allow_html=True)
    # Native st.code preserves tabs/newlines more reliably than custom markdown HTML.
    # CSS above forces all st.code blocks into the green terminal-style visual treatment.
    st.code(clean, language="text", wrap_lines=False)

def render_rule_box(code: str, label: str = "Rule / syntax"):
    render_code_box(code, label=label)


def render_pcap_box(snippet, label: str = "Traffic / packet evidence"):
    render_code_box(snippet, label=label)


def render_recovery_nav(context: str = ""):
    """Show a small navigation recovery panel so empty states never strand the learner."""
    if context:
        st.info(context)
    nav_cols = st.columns(3)
    with nav_cols[0]:
        if st.button("Return to Previous Section", key=f"recovery_prev_{context}", use_container_width=True):
            target = st.session_state.get("previous_view", "Lessons")
            st.session_state.view = target if target in ["Return to Main Menu", "Train", "Lessons", "Glossary", "Progress", "Feedback"] else "Lessons"
            rerun_top()
    with nav_cols[1]:
        if st.button("Continue Current Lesson", key=f"recovery_lesson_{context}", use_container_width=True):
            st.session_state.view = "Lessons"
            if st.session_state.get("return_lesson"):
                st.session_state.selected_lesson = st.session_state.return_lesson
            rerun_top()
def grade_lab_task(task, value):
    """Score a structured lab task. Returns (ok, message)."""
    if task.get("type") in ["single", "decision"]:
        ok = value == task.get("answer")
        return ok, task.get("explain", "")
    if task.get("type") == "multi":
        expected = set(task.get("answers", []))
        selected = set(value or [])
        ok = selected == expected
        missing = expected - selected
        extra = selected - expected
        details = []
        if missing:
            details.append("Missing: " + ", ".join(task["options"][i] for i in sorted(missing)))
        if extra:
            details.append("Extra: " + ", ".join(task["options"][i] for i in sorted(extra)))
        return ok, task.get("explain", "") + (("\n" + "\n".join(details)) if details else "")
    if task.get("type") == "rule":
        text = (value or "").lower()
        missing = [term for term in task.get("required", []) if term.lower() not in text]
        ok = not missing
        msg = task.get("explain", "")
        if missing:
            msg += "\nMissing required rule elements: " + ", ".join(missing)
        bonus_hits = [b for b in task.get("bonus", []) if b.lower() in text]
        if bonus_hits:
            msg += "\nBonus/context included: " + ", ".join(bonus_hits)
        return ok, msg
    return False, "Unsupported task type."


def clean_lab_evidence(value):
    """Keep traffic evidence as one clean text block and remove UI/object artifacts."""
    text = normalize_code_text(value)
    text = text.replace(",[object Object],", "")
    text = text.replace("[object Object]", "")
    return text.strip()


def render_lab_question(q):
    """Render a scenario lab with structured analyst tasks instead of sentence-only answers."""
    lab = getattr(q, "lab", {})
    st.markdown("### Scenario Lab")
    st.markdown(f"**{lab.get("title", q.prompt)}**")

    render_pcap_box(clean_lab_evidence(lab.get("evidence", "")), label="Wireshark Packet Evidence")
    render_rule_box(lab.get("starting_rule", q.rule), label="Rule under review")

    st.markdown("### Analyst Tasks")
    st.caption("Work through the evidence step by step: read the traffic, identify the right field, repair/tune the rule, and choose analyst follow-up actions.")

    task_values = {}
    for idx, task in enumerate(lab.get("tasks", [])):
        st.markdown(f"#### Step {idx + 1}: {task.get('label', 'Task')}")
        key = f"lab_{q.id}_{st.session_state.answer_key_counter}_{idx}"
        if task.get("type") in ["single", "decision"]:
            task_values[idx] = st.radio(
                "Choose one",
                list(range(len(task.get("options", [])))),
                format_func=lambda i, opts=task.get("options", []): opts[i],
                key=key,
                index=None,
            )
        elif task.get("type") == "multi":
            task_values[idx] = st.multiselect(
                "Select all that apply",
                list(range(len(task.get("options", [])))),
                format_func=lambda i, opts=task.get("options", []): opts[i],
                key=key,
            )
        elif task.get("type") == "rule":
            task_values[idx] = st.text_area(
                "Write the rule here",
                key=key,
                height=110,
                placeholder='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"..."; flow:established,to_server; http.uri; content:"..."; sid:930000; rev:1;)',
            )

    col_submit, col_hint, col_reveal, col_next = st.columns(4)
    with col_submit:
        if st.button("Submit Scenario", type="primary", use_container_width=True):
            task_results = []
            all_ok = True
            for idx, task in enumerate(lab.get("tasks", [])):
                ok, msg = grade_lab_task(task, task_values.get(idx))
                task_results.append({"step": idx + 1, "ok": ok, "message": msg})
                all_ok = all_ok and ok
            st.session_state.feedback = all_ok
            st.session_state.issues = [r["message"] for r in task_results if not r["ok"]]
            st.session_state.lab_results = task_results
            st.session_state.show_explanation = True
            st.session_state.revealed = False
            record_attempt(q, all_ok, skipped=False)
            rerun_top()
    with col_hint:
        hint_disabled = st.session_state.training_mode == "Challenge Mode" and st.session_state.feedback is None
        if st.button("Show Hint", use_container_width=True, disabled=hint_disabled):
            if q.hints:
                idx = min(st.session_state.hint_index, len(q.hints) - 1)
                st.session_state.current_hint = q.hints[idx]
                st.session_state.hint_index += 1
                st.session_state.hints_used += 1
            else:
                st.session_state.current_hint = "No hint available for this scenario."
            rerun_top()
    with col_reveal:
        if st.button("Reveal Walkthrough", use_container_width=True):
            st.session_state.feedback = False
            st.session_state.issues = ["Revealed walkthrough. Review the task explanations below."]
            st.session_state.lab_results = []
            for idx, task in enumerate(lab.get("tasks", [])):
                answer_text = ""
                if task.get("type") in ["single", "decision"]:
                    answer_text = task.get("options", [])[task.get("answer", 0)]
                elif task.get("type") == "multi":
                    answer_text = "; ".join(task.get("options", [])[i] for i in task.get("answers", []))
                elif task.get("type") == "rule":
                    answer_text = "Required elements: " + ", ".join(task.get("required", []))
                st.session_state.lab_results.append({"step": idx + 1, "ok": False, "message": answer_text + "\n" + task.get("explain", "")})
            st.session_state.show_explanation = True
            st.session_state.revealed = True
            record_attempt(q, ok=False, skipped=True)
            rerun_top()
    with col_next:
        st.empty()

    if st.session_state.get("current_hint"):
        st.warning(st.session_state.current_hint)

    if st.session_state.feedback is not None:
        if st.session_state.feedback:
            st.success("Scenario complete. Your selections/rule covered the expected analyst workflow.")
        elif st.session_state.get("revealed"):
            st.warning("Walkthrough revealed. This scenario was added to remediation, but you can continue anytime.")
        else:
            st.error("Some scenario steps need work. Review the step feedback and walkthrough below.")

    if st.session_state.get("lab_results"):
        st.markdown("### Step Feedback")
        for result in st.session_state.lab_results:
            icon = "✅" if result.get("ok") else "⚠️"
            st.markdown(f"**{icon} Step {result.get('step')}**")
            for line in str(result.get("message", "")).split("\n"):
                if line.strip():
                    st.write(line.strip())

    if st.session_state.show_explanation:
        st.markdown("### Walkthrough")
        st.write(q.explanation)
        render_soc_context(q)
        if getattr(q, "answer_points", None):
            with st.expander("Expected concepts", expanded=True):
                for point in q.answer_points:
                    st.write(f"- {point}")
        st.markdown("#### Analyst takeaway")
        st.write("Good analysts connect traffic evidence to rule logic. The goal is to identify the field that triggered, decide whether the logic is scoped correctly, then tune without hiding true malicious behavior.")

    st.markdown("---")
    st.caption("Use the top navigation to return to the lesson or open remediation.")
    next_cols = st.columns([1, 2, 1])
    with next_cols[1]:
        if st.button("Next Scenario", key=f"lab_continue_{q.id}", use_container_width=True):
            st.session_state.lab_results = []
            st.session_state.show_explanation = False
            st.session_state.feedback = None
            reset_current_question()
            rerun_top()


def is_guided_rule_build_question(q):
    """Return True for questions that expect a full Suricata rule from the learner."""
    if getattr(q, "mode", "") != "write":
        return False
    rule_text = str(getattr(q, "rule", "")).lower()
    prompt_text = str(getattr(q, "prompt", "")).lower()
    return "build full rule" in rule_text or "write a rule" in prompt_text or "write a tuned rule" in prompt_text


def expected_protocol(q):
    terms = " ".join(getattr(q, "required_terms", []) + getattr(q, "answer_points", [])).lower()
    for proto in ["http", "dns", "tls", "tcp", "ip"]:
        if f"alert {proto}" in terms or proto in getattr(q, "required_terms", []):
            return proto
    rule = str(getattr(q, "explanation", "") + " " + getattr(q, "prompt", "")).lower()
    for proto in ["http", "dns", "tls", "tcp", "ip"]:
        if proto in rule:
            return proto
    return "http"


def expected_buffers(q):
    text = " ".join(getattr(q, "required_terms", []) + getattr(q, "answer_points", []) + [getattr(q, "explanation", "")]).lower()
    candidates = [
        "http.method", "http.uri", "http.host", "http.user_agent", "http.request_body",
        "http.header", "http.cookie", "dns.query", "tls.sni", "flags:S", "dsize"
    ]
    hits = []
    for c in candidates:
        key = c.lower()
        if key in text or (c == "dsize" and "dsize:" in text):
            hits.append(c)
    return hits


def expected_content_terms(q):
    structural = {
        "alert", "http", "dns", "tls", "tcp", "ip", "sid", "rev", "msg", "nocase",
        "http.method", "http.uri", "http.host", "http.user_agent", "http.request_body",
        "http.header", "http.cookie", "dns.query", "tls.sni", "flags:s", "dsize:>1200",
        "flow:established,to_server", "startswith", "endswith", "detection_filter", "track by_src",
        "count 20", "seconds 60"
    }
    terms = []
    for t in getattr(q, "required_terms", []) + getattr(q, "answer_points", []):
        tl = str(t).lower()
        if tl not in structural and not tl.startswith("alert "):
            terms.append(str(t))
    # Keep order but remove duplicates/noise.
    cleaned = []
    for t in terms:
        if t and t not in cleaned:
            cleaned.append(t)
    return cleaned[:6]


def guided_example_rule(q):
    explanation = str(getattr(q, "explanation", ""))
    if "Example:" in explanation:
        return explanation.split("Example:", 1)[1].strip().strip("'").strip('"')
    if "Better rule:" in explanation:
        return explanation.split("Better rule:", 1)[1].strip().strip("'").strip('"')
    proto = expected_protocol(q)
    buffers = expected_buffers(q)
    content_terms = expected_content_terms(q)
    first_content = content_terms[0] if content_terms else "<match>"
    buffer_part = f"{buffers[0]}; content:\"{first_content}\"; " if buffers else f"content:\"{first_content}\"; "
    return f'alert {proto} $EXTERNAL_NET any -> $HOME_NET any (msg:"Training rule"; flow:established,to_server; {buffer_part}sid:300000; rev:1;)'


def guided_rule_template(protocol="http", src="$EXTERNAL_NET", sport="any", dst="$HOME_NET", dport="any"):
    """Return a safe rule-shape reminder for guided rule construction.

    This is intentionally local to the web app so guided mode works even if
    the backend trainer file changes or does not expose its helper.
    """
    protocol = str(protocol or "http").strip().lower()
    return (
        f'alert {protocol} {src} {sport} -> {dst} {dport} '
        f'(msg:"Describe what this detects"; <buffer>; content:"<thing to match>"; sid:1000001; rev:1;)'
    )

def render_guided_rule_builder(q):
    """Scaffold rule-writing questions so beginner analysts are not forced into a blank-text full rule immediately."""
    st.markdown("### Guided Rule Construction")
    st.caption("Build the rule in smaller steps first. You can still write the final rule, but this helps you learn the order and decisions behind it.")

    proto = expected_protocol(q)
    buffers = expected_buffers(q)
    content_terms = expected_content_terms(q)
    example = guided_example_rule(q)

    render_rule_box(guided_rule_template(proto), label="Rule shape reminder")

    step1_key = f"guided_order_{q.id}_{st.session_state.answer_key_counter}"
    step2_key = f"guided_proto_{q.id}_{st.session_state.answer_key_counter}"
    step3_key = f"guided_buffers_{q.id}_{st.session_state.answer_key_counter}"
    step4_key = f"guided_content_{q.id}_{st.session_state.answer_key_counter}"
    step5_key = f"guided_final_{q.id}_{st.session_state.answer_key_counter}"

    st.markdown("#### Step 1: Rule order")
    order_choice = st.radio(
        "Which part comes first in a Suricata rule?",
        [
            "action protocol source source_port direction destination destination_port (options;)",
            "msg sid rev content buffer action protocol",
            "content buffer alert sid rev direction",
            "destination source content msg sid rev",
        ],
        key=step1_key,
        index=None,
    )

    st.markdown("#### Step 2: Protocol / parser")
    proto_choice = st.radio(
        "Which protocol/parser best fits this task?",
        ["http", "dns", "tls", "tcp", "ip"],
        key=step2_key,
        index=None,
        horizontal=True,
    )

    st.markdown("#### Step 3: Field or buffer selection")
    buffer_options = ["http.method", "http.uri", "http.host", "http.user_agent", "http.request_body", "http.header", "dns.query", "tls.sni", "flags:S", "dsize"]
    buffer_choice = st.multiselect(
        "Select the buffer/keyword(s) that should appear in the rule.",
        buffer_options,
        key=step3_key,
    )

    st.markdown("#### Step 4: Match content / behavior")
    distractors = ["raw content anywhere", "any any -> any any", "Mozilla", "/", "com"]
    content_options = []
    for item in content_terms + distractors:
        if item and item not in content_options:
            content_options.append(item)
    if not content_options:
        content_options = ["sid", "rev", "msg", "specific content", "raw content anywhere"]
    content_choice = st.multiselect(
        "Which match values or behaviors are relevant?",
        content_options,
        key=step4_key,
    )

    st.markdown("#### Step 5: Final rule attempt")
    final_rule = st.text_area(
        "Write the final rule here. It does not have to be perfect; partial credit is shown below.",
        key=step5_key,
        height=120,
        placeholder=example,
    )

    col_submit, col_reveal, col_next = st.columns(3)
    with col_submit:
        if st.button("Submit Guided Rule", type="primary", use_container_width=True):
            checks = []
            checks.append((order_choice == "action protocol source source_port direction destination destination_port (options;)", "Rule starts with the correct header order."))
            checks.append((proto_choice == proto, f"Protocol/parser selected: expected {proto}."))
            if buffers:
                selected = set(buffer_choice or [])
                expected = set(buffers)
                checks.append((expected.issubset(selected), "Correct buffer/keyword selection: " + ", ".join(buffers)))
            else:
                checks.append((bool(buffer_choice), "At least one meaningful rule keyword/buffer selected."))
            if content_terms:
                selected_content = " ".join(content_choice or []).lower()
                checks.append((any(str(t).lower() in selected_content for t in content_terms), "Relevant match content/behavior selected."))
            text = (final_rule or "").lower()
            checks.append(("alert" in text and proto in text, "Final rule includes action and protocol."))
            checks.append(("sid" in text and "rev" in text, "Final rule includes sid and rev."))
            if buffers:
                checks.append((any(b.lower() in text for b in buffers), "Final rule uses the expected buffer/keyword."))
            if content_terms:
                checks.append((any(str(t).lower() in text for t in content_terms), "Final rule includes the expected match value/behavior."))

            passed = sum(1 for ok, _ in checks if ok)
            ok = passed >= max(4, int(len(checks) * 0.65))
            st.session_state.feedback = ok
            st.session_state.issues = [msg for ok_check, msg in checks if not ok_check]
            st.session_state.guided_checks = checks
            st.session_state.show_explanation = True
            st.session_state.revealed = False
            record_attempt(q, ok, skipped=False)
            rerun_top()

    with col_reveal:
        if st.button("Show Example Rule", use_container_width=True):
            st.session_state.feedback = False
            st.session_state.issues = ["Example revealed. Review the structure, then try a similar one again later."]
            st.session_state.guided_checks = []
            st.session_state.show_explanation = True
            st.session_state.revealed = True
            record_attempt(q, ok=False, skipped=True)
            rerun_top()

    with col_next:
        if st.button("Continue Investigation", use_container_width=True):
            reset_current_question()
            rerun_top()

    if st.session_state.feedback is not None:
        if st.session_state.feedback:
            st.success("Good guided build. Your rule covered enough of the expected structure and detection logic.")
        elif st.session_state.get("revealed"):
            st.warning("Example revealed. This was added to remediation so it can be practiced again.")
        else:
            st.error("Not quite yet. Review the partial-credit feedback below; you can still move on.")

    if st.session_state.get("guided_checks"):
        st.markdown("### Partial-credit feedback")
        for ok_check, msg in st.session_state.guided_checks:
            st.write(("✅ " if ok_check else "⚠️ ") + msg)

    if st.session_state.show_explanation:
        st.markdown("### Example / Walkthrough")
        render_rule_box(example, label="One acceptable rule")
        st.write(q.explanation)
        render_soc_context(q)
        if getattr(q, "answer_points", None):
            with st.expander("Expected concepts", expanded=True):
                for point in q.answer_points:
                    st.write(f"- {point}")
        st.markdown("#### Analyst takeaway")
        st.write("Rule writing gets easier when you think in order: header, direction, buffer, match value, metadata. Beginners should practice these pieces before being judged on a perfect full rule.")


def get_soc_context(q):
    """Return operational context tailored to the current question/rule."""
    text = f"{getattr(q, 'category', '')} {getattr(q, 'mode', '')} {getattr(q, 'rule', '')} {getattr(q, 'prompt', '')}".lower()
    if "dns" in text or "dns.query" in text:
        return {
            "fires_when": ["Internal hosts query suspicious domains", "DNS labels/domains match rule logic", "Repeated DNS behavior suggests tunneling or DGA-like activity"],
            "actions": ["Check source asset and user", "Review query count/frequency", "Pivot on domain reputation and related hosts", "Baseline known CDN or business-service domains"],
            "reality": "DNS detections are often behavioral. A single domain string may be weak; rate, repetition, entropy, and asset context make it stronger.",
        }
    if "tls" in text or "sni" in text:
        return {
            "fires_when": ["A TLS ClientHello exposes an SNI hostname matching the rule", "An internal host connects outbound to a suspicious or unexpected hostname"],
            "actions": ["Check source asset role", "Review destination reputation and certificate details", "Compare against known-good business services", "Look for repeated connections or follow-on activity"],
            "reality": "SNI is useful but not a verdict. Generic fragments like cdn or cloud are usually noisy unless paired with specific context.",
        }
    if "syn" in text or "flags:s" in text or "scan" in text:
        return {
            "fires_when": ["TCP SYN packets match the rule", "Rate or threshold logic may indicate scanning behavior"],
            "actions": ["Check count and time window", "Track by source", "Review target port spread", "Separate normal connection attempts from scan behavior"],
            "reality": "Single SYN packets are normal. Useful scan detection usually depends on rate, repetition, and destination/port spread.",
        }
    if "powershell" in text or "cmd.exe" in text or "webshell" in text or "sqli" in text or "sql" in text:
        return {
            "fires_when": ["HTTP requests contain command/exploitation indicators", "Suspicious strings appear in URI parameters or request bodies", "A public-facing app receives potentially malicious input"],
            "actions": ["Review HTTP method, URI, status code, and response size", "Check source reputation and repeat attempts", "Inspect web/app logs", "Look for follow-on callbacks or host alerts"],
            "reality": "Exploit strings are most useful when scoped to request direction and the right HTTP buffer. Avoid raw payload matching unless needed.",
        }
    if "user_agent" in text or "user-agent" in text or "curl" in text or "python" in text:
        return {
            "fires_when": ["An HTTP client identifies as automation/tooling", "A protected host makes outbound requests with a suspicious or unexpected User-Agent"],
            "actions": ["Check source asset role and owner", "Validate whether automation is expected", "Review destination and frequency", "Tune known-good automation without hiding unknown activity"],
            "reality": "Automation is not automatically malicious. Asset role, destination, and business purpose determine whether to tune or escalate.",
        }
    return {
        "fires_when": ["Traffic matches the rule header and detection options", "The selected buffer or behavior matches the rule logic"],
        "actions": ["Confirm source, destination, direction, and protocol", "Review the matched field or buffer", "Check frequency and related alerts", "Decide whether to escalate, tune, or document as expected"],
        "reality": "A Suricata alert is a starting point. Analysts need context before deciding whether it is malicious, benign, or poorly tuned.",
    }


def render_soc_context(q):
    ctx = get_soc_context(q)
    st.markdown("### SOC Context")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown('<div class="workflow-card"><strong>When this would usually fire</strong><div class="small-list">' + ''.join(f'• {html.escape(x)}<br>' for x in ctx["fires_when"]) + '</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="workflow-card"><strong>Analyst actions</strong><div class="small-list">' + ''.join(f'• {html.escape(x)}<br>' for x in ctx["actions"]) + '</div></div>', unsafe_allow_html=True)
    st.info(ctx["reality"])


def explain_weak_answer(q, issues):
    """Give remediation guidance that is more useful than simply 'wrong'."""
    text = f"{getattr(q, 'rule', '')} {getattr(q, 'prompt', '')}".lower()
    guidance = []
    if issues:
        guidance.extend(issues)
    if "http" in text and "uri" in text:
        guidance.append("Check whether your answer identified the correct HTTP buffer, especially http.uri for paths/parameters.")
    if "dns" in text:
        guidance.append("For DNS questions, make sure you distinguish the queried name from DNS answers or unrelated payload text.")
    if "tls" in text or "sni" in text:
        guidance.append("For TLS hostname questions, remember tls.sni is the handshake hostname; it is not the same as http.host.")
    if "tuning" in getattr(q, 'category', '').lower() or getattr(q, 'mode', '') in ["optimize", "repair", "capstone"]:
        guidance.append("A strong tuning answer usually mentions scope, specificity, direction, and what context should be checked before suppressing alerts.")
    out = []
    for item in guidance:
        if item and item not in out:
            out.append(item)
    return out[:5]


def render_learning_paths():
    st.markdown("### Progressive paths")
    cols = st.columns(3)
    paths = [
        ("Beginner Analyst", "Variables → Rule Building → Buffers", "Best for learning how to read rules and understand alert scope."),
        ("SOC Operator", "Rule Reading → Tuning → Remediation", "Best for analysts who triage alerts and need to explain why a rule fired."),
        ("Detection Engineer", "Repair → Advanced Tuning → Capstones", "Best for building, tuning, and defending production-style detections."),
    ]
    for col, (title, path, body) in zip(cols, paths):
        with col:
            st.markdown(f'<div class="section-card"><div class="lesson-card-title">{html.escape(title)}</div><div class="lesson-card-body"><strong>{html.escape(path)}</strong><br>{html.escape(body)}</div></div>', unsafe_allow_html=True)

def render_rule_breakdown():
    render_rule_box("""alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Example"; http.uri; content:"/login"; sid:100001; rev:1;)
│     │    │             │   │  │         │    └─ options: message, buffers, content, IDs
│     │    │             │   │  └─ destination network and port
│     │    │             │   └─ direction
│     │    └─ source network and port
│     └─ protocol / parser
└─ action""", label="Visual rule breakdown")


def render_lesson_code(code: str, label: str = "Rule / syntax"):
    """Render rule syntax in one consistent, readable green code box."""
    render_rule_box(code, label=label)


def render_lesson_content(lesson_name: str):
    """Structured lesson renderer.

    This intentionally does not dump the old terminal lessons into markdown. Markdown collapses
    spacing and can make Suricata examples unreadable. Each lesson is organized as:
    concept -> traffic snippet -> rule example -> analyst workflow -> common mistakes.
    """
    if lesson_name == "Network Variables":
        st.markdown("#### What this lesson teaches")
        st.write("Network variables tell Suricata which networks matter. They also help analysts understand whether a rule is intended to detect inbound, outbound, or overly broad lab traffic.")

        st.markdown("#### Common variables")
        render_lesson_code("""$HOME_NET      = networks you are protecting
$EXTERNAL_NET  = everything outside your protected networks
$HTTP_SERVERS  = internal web servers, if defined
$DNS_SERVERS   = DNS servers, if defined""", label="Common Suricata variables")

        st.markdown("#### traffic evidence context")
        render_pcap_box("""Frame summary:
  src_ip:   203.0.113.45
  src_port: 49221
  dst_ip:   10.25.8.14
  dst_port: 80
  protocol: HTTP
  method:   GET
  uri:      /admin

Analyst readout:
  External client -> protected web server
  This is inbound traffic toward $HOME_NET.""", label="Inbound HTTP request")

        st.markdown("#### Rule aligned to the traffic direction")
        render_lesson_code('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound HTTP admin path"; flow:established,to_server; http.uri; content:"/admin"; sid:100001; rev:1;)', label="Operational inbound direction")
        st.write("Plain English: alert on HTTP traffic from outside networks going toward protected networks when the URI contains `/admin`.")

        st.markdown("#### Bad vs better")
        st.write("Weak / lab-only pattern:")
        render_lesson_code('alert http any any -> any any (content:"admin"; sid:1; rev:1;)', label="Too broad for production")
        st.write("Why it is weak: it does not tell the analyst who initiated the traffic, where it went, or where `admin` appeared.")
        st.write("Better operational pattern:")
        render_lesson_code('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound HTTP admin path"; http.uri; content:"/admin"; sid:100001; rev:1;)', label="Scoped direction and buffer")
        st.write("Why it is better: it describes inbound traffic toward protected systems and scopes the match to the URI path.")

        st.markdown("#### Analyst workflow")
        st.write("1. Identify which side of the arrow contains `$HOME_NET`.")
        st.write("2. Decide whether the rule is inbound, outbound, lateral, or too broad.")
        st.write("3. Confirm the rule direction matches the behavior it claims to detect.")
        st.write("4. Tune broad lab-style rules before treating them as production detections.")
        return

    if lesson_name == "Rule Building":
        st.markdown("#### What this lesson teaches")
        st.write("A Suricata rule has a header and an options block. The header scopes traffic. The options block describes what must match inside that traffic.")

        st.markdown("#### Rule shape")
        render_lesson_code("""action protocol source_ip source_port direction destination_ip destination_port (options;)""", label="Rule header shape")

        st.markdown("#### Full example")
        render_lesson_code('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Example inbound login path"; flow:established,to_server; http.uri; content:"/login"; sid:100001; rev:1;)', label="Full Suricata rule")

        st.markdown("#### Component breakdown")
        render_lesson_code("""alert              = action: create an alert
http               = protocol / app-layer parser
$EXTERNAL_NET any  = source network and source port
->                 = traffic direction
$HOME_NET any      = destination network and destination port
msg                = analyst-facing alert name
flow               = session state and direction
http.uri           = inspect the request URI/path
content:"/login"  = match this string in the selected buffer
sid / rev          = unique rule ID and revision""", label="Rule components")

        st.markdown("#### traffic evidence context")
        render_pcap_box("""HTTP request reconstructed from traffic:
GET /login HTTP/1.1
Host: portal.example.internal
User-Agent: Mozilla/5.0

Relevant fields:
  protocol: HTTP
  direction: external client -> protected server
  uri: /login""", label="Traffic fields that map to rule components")

        st.markdown("#### Analyst workflow")
        st.write("1. Read the header first: action, protocol, source, direction, destination, and ports.")
        st.write("2. Read the options second: message, flow, buffers, content, SID, and revision.")
        st.write("3. Ask whether the rule explains why an analyst should care.")
        st.write("4. Remember: a rule can be syntactically valid but still operationally weak.")
        return

    if lesson_name == "Buffers":
        st.markdown("#### What this lesson teaches")
        st.write("A buffer is the specific part of traffic Suricata should inspect. Choosing the correct buffer is one of the fastest ways to reduce false positives.")

        st.markdown("#### Common beginner buffers")
        render_lesson_code("""http.method        = GET, POST, PUT, DELETE
http.uri           = path/URI, like /login or /admin
http.host          = HTTP Host header
http.user_agent    = User-Agent header
http.request_body  = submitted form/body data
dns.query          = queried domain name
tls.sni            = TLS hostname from the handshake""", label="Common buffers")

        st.markdown("#### Traffic evidence example")
        render_pcap_box("""HTTP request:
POST /login HTTP/1.1
Host: portal.example.internal
User-Agent: curl/8.0
Content-Type: application/x-www-form-urlencoded

username=jsmith&password=Summer2026!""", label="HTTP transaction with multiple buffers")

        st.markdown("#### Buffer mapping")
        render_lesson_code("""http.method        -> POST
http.uri           -> /login
http.host          -> portal.example.internal
http.user_agent    -> curl/8.0
http.request_body  -> username=jsmith&password=Summer2026!""", label="How Suricata sees the request")

        st.markdown("#### Bad vs better")
        st.write("Weak pattern: raw content can match almost anywhere in the payload.")
        render_lesson_code('content:"admin";', label="Weak raw content")
        st.write("Better pattern: scope the content to where the suspicious value should appear.")
        render_lesson_code('http.uri; content:"/admin";', label="Better URI-scoped content")

        st.markdown("#### Analyst workflow")
        st.write("1. Identify where the value appears in traffic.")
        st.write("2. Pick the matching Suricata buffer.")
        st.write("3. Avoid raw content unless there is a clear reason.")
        st.write("4. During triage, confirm whether the alert matched the field you expected.")
        return

    if lesson_name == "Tuning":
        st.markdown("#### What this lesson teaches")
        st.write("Tuning means reducing false positives while keeping useful detection. The goal is not fewer alerts at all costs. The goal is better signal.")

        st.markdown("#### Alert evidence example")
        render_pcap_box("""Repeated alerts observed:
  alert_count_24h: 14,552
  common_uri_values:
    /login
    /user/login
    /logout
    /static/login-helper.js
  common_sources:
    internal scanner
    external users
    monitoring checks

Analyst readout:
  The word login appears in many benign places.
  The rule needs better scope and intent.""", label="Noisy login alert pattern")

        st.markdown("#### Tuning checklist")
        render_lesson_code("""1. Is the match scoped to the right buffer?
2. Is the traffic direction right?
3. Can we use $EXTERNAL_NET -> $HOME_NET or $HOME_NET -> $EXTERNAL_NET?
4. Is the content too generic?
5. Should we add nocase?
6. Should repeated behavior use thresholding or detection_filter?""", label="Beginner tuning checklist")

        st.markdown("#### Bad vs better")
        render_lesson_code('alert http any any -> any any (content:"login"; sid:200001; rev:1;)', label="Noisy login rule")
        st.write("Why it is weak: `login` could appear in URIs, response bodies, scripts, comments, or benign application text.")
        render_lesson_code('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP POST to login endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/login"; sid:200001; rev:2;)', label="Better scoped login rule")
        st.write("Why it is better: it preserves the detection intent while adding direction, flow, method, and URI scope.")

        st.markdown("#### Analyst workflow")
        st.write("1. Do not suppress a noisy rule until you understand why it is noisy.")
        st.write("2. Check matched field, direction, asset role, alert volume, and repeated behavior.")
        st.write("3. Tune with scope and specificity first.")
        st.write("4. Use thresholds or detection_filter when the behavior is meaningful only at volume.")
        return

    st.write(LESSONS.get(lesson_name, "No lesson text found."))


# ------------------------------------------------------------
# Stronger lesson knowledge checks
# ------------------------------------------------------------

LESSON_CHECKS = {
    "Network Variables": [
        {
            "title": "Direction triage",
            "scenario": "PCAP context: src_ip 203.0.113.45 -> dst_ip 10.25.8.14, HTTP GET /admin. The rule is written as any any -> any any for inbound web detection. What is the most useful first improvement?",
            "options": [
                "Replace the direction with $EXTERNAL_NET any -> $HOME_NET any if the intent is inbound detection.",
                "Remove the msg field so the rule is shorter.",
                "Change the protocol to ip so it catches everything.",
                "Delete the sid and rev until the rule is finished.",
            ],
            "answer": 0,
            "why": "Direction and network scope are usually the first things an analyst checks. If the intent is inbound traffic against protected systems, $EXTERNAL_NET -> $HOME_NET is clearer and easier to tune than any any -> any any.",
        },
        {
            "title": "Outbound DNS interpretation",
            "scenario": "A DNS rule uses $HOME_NET any -> $EXTERNAL_NET any. What does that usually describe?",
            "options": [
                "A protected/internal host making an outbound DNS query.",
                "An external server attacking an internal DNS server.",
                "Only traffic inside the same subnet.",
                "A rule that has no direction.",
            ],
            "answer": 0,
            "why": "$HOME_NET on the left side means the protected host is the source. For DNS, that often means internal clients querying outward.",
        },
    ],
    "Rule Building": [
        {
            "title": "Rule header vs options",
            "scenario": "When reviewing a Suricata rule, which part tells you the traffic scope before the detection options run?",
            "options": [
                "The header: action, protocol, source, direction, destination, and ports.",
                "Only the msg field.",
                "Only the sid field.",
                "Only the content keyword.",
            ],
            "answer": 0,
            "why": "The header defines what traffic the rule applies to. The options define what must match inside that scoped traffic.",
        },
        {
            "title": "Operationally useful rule",
            "scenario": "Which rule is more useful for an analyst?",
            "options": [
                "alert ip any any -> any any (sid:1;)",
                "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"Admin path access\"; http.uri; content:\"/admin\"; sid:100001; rev:1;)",
                "alert ip any any -> any any (rev:1;)",
                "alert http any any -> any any (msg:\"traffic\"; sid:2;)",
            ],
            "answer": 1,
            "why": "The better rule has direction, protocol context, an analyst-readable message, a scoped HTTP URI buffer, content, SID, and revision.",
        },
    ],
    "Buffers": [
        {
            "title": "Buffer selection",
            "scenario": "Traffic snippet: GET /admin HTTP/1.1 with Host: portal.example.internal. You want to alert on requests to /admin. Which match is the better starting point?",
            "options": [
                "content:\"admin\";",
                "http.uri; content:\"/admin\";",
                "dns.query; content:\"/admin\";",
                "tls.sni; content:\"/admin\";",
            ],
            "answer": 1,
            "why": "/admin is expected in the HTTP request URI/path. Scoping to http.uri avoids matching random text elsewhere in the payload.",
        },
        {
            "title": "TLS hostname field",
            "scenario": "A rule is supposed to inspect a TLS ClientHello hostname. Which buffer should it use?",
            "options": [
                "http.host",
                "http.uri",
                "tls.sni",
                "http.request_body",
            ],
            "answer": 2,
            "why": "TLS SNI is the hostname field in the TLS handshake. HTTP Host is a different HTTP header.",
        },
    ],
    "Tuning": [
        {
            "title": "Noisy login rule",
            "scenario": "A rule matching content:\"login\" fires constantly. What is the best tuning direction?",
            "options": [
                "Immediately suppress every alert from the rule.",
                "Scope the match to http.uri, use /login, add direction/flow, and consider POST if that matches the detection intent.",
                "Change login to a shorter string so it matches faster.",
                "Remove sid and rev so it is easier to edit.",
            ],
            "answer": 1,
            "why": "Good tuning preserves the intent while improving scope: direction, buffer, specificity, and method/flow where appropriate.",
        },
        {
            "title": "Behavior vs single packet",
            "scenario": "A SYN rule fires on every connection attempt. What makes scan detection more operationally useful?",
            "options": [
                "Alert on every SYN forever.",
                "Use rate/threshold logic, track by source, and look for repeated behavior over time.",
                "Change the protocol to http.",
                "Remove flags:S.",
            ],
            "answer": 1,
            "why": "A single SYN is normal. Scan-like activity is usually about repeated behavior, rate, and source/destination spread.",
        },
    ],
}


def format_inline_syntax(text: str) -> str:
    """Wrap common Suricata variables/fragments in Markdown code spans so they render consistently.

    Streamlit treats unescaped dollar signs like math delimiters in some widget text.
    This helper prevents fragments such as $EXTERNAL_NET any -> $HOME_NET any
    from splitting into mixed green/white formatting.
    """
    if text is None:
        return ""
    text = str(text)

    # Avoid double-wrapping strings that already contain explicit code spans around the full phrase.
    replacements = [
        ("$EXTERNAL_NET any -> $HOME_NET any", "`$EXTERNAL_NET any -> $HOME_NET any`"),
        ("$HOME_NET any -> $EXTERNAL_NET any", "`$HOME_NET any -> $EXTERNAL_NET any`"),
        ("$EXTERNAL_NET -> $HOME_NET", "`$EXTERNAL_NET -> $HOME_NET`"),
        ("$HOME_NET -> $EXTERNAL_NET", "`$HOME_NET -> $EXTERNAL_NET`"),
        ("any any -> any any", "`any any -> any any`"),
        ("flow:established,to_server", "`flow:established,to_server`"),
        ("http.uri", "`http.uri`"),
        ("http.method", "`http.method`"),
        ("http.host", "`http.host`"),
        ("http.user_agent", "`http.user_agent`"),
        ("http.request_body", "`http.request_body`"),
        ("dns.query", "`dns.query`"),
        ("tls.sni", "`tls.sni`"),
        ("detection_filter", "`detection_filter`"),
        ("$EXTERNAL_NET", "`$EXTERNAL_NET`"),
        ("$HOME_NET", "`$HOME_NET`"),
        ("$HTTP_SERVERS", "`$HTTP_SERVERS`"),
        ("$DNS_SERVERS", "`$DNS_SERVERS`"),
    ]
    for old, new in replacements:
        # Only replace occurrences not already inside a Markdown code span.
        text = text.replace(f"`{old}`", f"@@CODE_{abs(hash(old))}@@")
        text = text.replace(old, new)
        text = text.replace(f"@@CODE_{abs(hash(old))}@@", f"`{old}`")

    # Clean up accidental nested backticks from overlapping replacements.
    text = text.replace("``", "`")
    text = text.replace("`$EXTERNAL_NET` any -> `$HOME_NET` any", "`$EXTERNAL_NET any -> $HOME_NET any`")
    text = text.replace("`$HOME_NET` any -> `$EXTERNAL_NET` any", "`$HOME_NET any -> $EXTERNAL_NET any`")
    text = text.replace("`$EXTERNAL_NET` -> `$HOME_NET`", "`$EXTERNAL_NET -> $HOME_NET`")
    text = text.replace("`$HOME_NET` -> `$EXTERNAL_NET`", "`$HOME_NET -> $EXTERNAL_NET`")
    return text

def render_knowledge_checks(lesson_name: str):
    checks = LESSON_CHECKS.get(lesson_name, [])
    if not checks:
        st.info("No knowledge checks are available for this lesson yet.")
        return

    st.caption("These checks focus on analyst decisions, not memorizing definitions. Review the explanation after each answer.")
    correct_count = 0

    for idx, check in enumerate(checks, start=1):
        key = f"lesson_check_{lesson_name}_{idx}"
        st.markdown(
            f"""
            <div class="check-card">
                <div class="check-title">Check {idx}: {html.escape(check['title'])}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(format_inline_syntax(check["scenario"]))

        display_options = [format_inline_syntax(option) for option in check["options"]]
        choice = st.radio(
            "Choose the best analyst answer:",
            display_options,
            key=key,
            index=None,
        )
        if choice is not None:
            selected = display_options.index(choice)
            if selected == check["answer"]:
                correct_count += 1
                st.success("Correct — this is the strongest analyst choice.")
            else:
                st.error("Not quite — review the reasoning below.")
            st.info(format_inline_syntax(check["why"]))

    if correct_count == len(checks):
        st.success("Knowledge check complete. You are ready for the related practice module.")
    elif correct_count > 0:
        st.warning(f"{correct_count}/{len(checks)} checks correct so far. You can still continue, but review the explanations first.")

# ------------------------------------------------------------
# Initialize state
# ------------------------------------------------------------

if "view" not in st.session_state:
    st.session_state.view = "Return to Main Menu"
if "previous_view" not in st.session_state:
    st.session_state.previous_view = "Return to Main Menu"
if "bank_name" not in st.session_state:
    st.session_state.bank_name = "Adaptive Mixed"
if "difficulty_filter" not in st.session_state:
    st.session_state.difficulty_filter = "All"
if "grading_mode" not in st.session_state:
    st.session_state.grading_mode = "Standard"
if "adaptive" not in st.session_state:
    st.session_state.adaptive = True
if "answer_key_counter" not in st.session_state:
    st.session_state.answer_key_counter = 0
if "missed_ids" not in st.session_state:
    st.session_state.missed_ids = []
if "training_mode" not in st.session_state:
    st.session_state.training_mode = "Learning Mode"
if "guided_rule_builder" not in st.session_state:
    st.session_state.guided_rule_builder = True
if "selected_lesson" not in st.session_state:
    st.session_state.selected_lesson = LESSON_ORDER[0] if LESSON_ORDER else ""
if "return_lesson" not in st.session_state:
    st.session_state.return_lesson = st.session_state.selected_lesson
if "recent_question_ids" not in st.session_state:
    st.session_state.recent_question_ids = []
if "lab_results" not in st.session_state:
    st.session_state.lab_results = []
if "question" not in st.session_state:
    reset_current_question()

progress = get_progress()
summary = global_summary(progress)

# Stable anchor used by the scroll reset helper. Keep this near the top of the
# rendered page so lesson/module transitions feel like a true page change.
st.markdown('<div id="top-of-app"></div>', unsafe_allow_html=True)
scroll_to_top_once()

# ------------------------------------------------------------
# Sidebar navigation
# ------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ Suricata Trainer")
    st.caption(f"Version {APP_VERSION}")

    view = st.radio(
        "Navigation",
        ["Return to Main Menu", "Train", "Lessons", "Glossary", "Progress", "Feedback"],
        index=["Return to Main Menu", "Train", "Lessons", "Glossary", "Progress", "Feedback"].index(st.session_state.view),
    )
    if view != st.session_state.view:
        st.session_state.previous_view = st.session_state.view
        st.session_state.view = view
        rerun_top()

    st.markdown("---")
    st.markdown("### Module")
    module_options = list(BASE_BANKS.keys()) + ["Review Missed / Remediation"]
    selected_bank = st.selectbox(
        "Choose module",
        module_options,
        index=module_options.index(st.session_state.bank_name) if st.session_state.bank_name in module_options else 0,
    )

    difficulty_filter = st.selectbox(
        "Difficulty",
        ["All", "1", "2", "3", "4"],
        index=["All", "1", "2", "3", "4"].index(st.session_state.difficulty_filter),
    )

    adaptive = st.toggle("Adaptive Practice", value=st.session_state.adaptive)
    training_mode = st.selectbox(
        "Training style",
        ["Learning Mode", "Challenge Mode"],
        index=["Learning Mode", "Challenge Mode"].index(st.session_state.training_mode),
        help="Learning Mode encourages hints and explanations. Challenge Mode hides hints until after answering and uses stricter expectations."
    )

    grading_mode = st.selectbox(
        "Grading",
        ["Standard", "Strict"],
        index=["Standard", "Strict"].index(st.session_state.grading_mode),
        help="Standard is forgiving. Strict requires more exact expected terms."
    )

    guided_rule_builder = st.toggle(
        "Guided Rule Builder",
        value=st.session_state.guided_rule_builder,
        help="When enabled, rule-writing questions are broken into smaller steps before asking for the final rule."
    )

    if training_mode == "Challenge Mode" and grading_mode != "Strict":
        grading_mode = "Strict"

    controls_changed = (
        selected_bank != st.session_state.bank_name or
        difficulty_filter != st.session_state.difficulty_filter or
        adaptive != st.session_state.adaptive or
        training_mode != st.session_state.training_mode or
        grading_mode != st.session_state.grading_mode or
        guided_rule_builder != st.session_state.guided_rule_builder
    )
    if controls_changed:
        st.session_state.bank_name = selected_bank
        st.session_state.difficulty_filter = difficulty_filter
        st.session_state.adaptive = adaptive
        st.session_state.training_mode = training_mode
        st.session_state.grading_mode = grading_mode
        st.session_state.guided_rule_builder = guided_rule_builder
        reset_current_question()
        rerun_top()

    if st.button("Start Module Practice", use_container_width=True):
        st.session_state.view = "Train"
        reset_current_question()
        rerun_top()

    st.markdown("---")
    st.markdown("### Session Progress")
    st.metric("Questions Seen", summary.get("seen", 0))
    st.metric("Accuracy", f"{summary.get('accuracy', 0)}%")
    st.metric("Missed Queue", len(st.session_state.get("missed_ids", [])))
    st.metric("Lessons Done", f"{len(completed_lessons())}/{len(LESSON_ORDER)}")


    if st.button("Reset Progress", use_container_width=True):
        st.session_state.progress = fresh_progress()
        st.session_state.missed_ids = []
        save_web_progress()
        reset_current_question()
        rerun_top()

# ------------------------------------------------------------
# Views
# ------------------------------------------------------------

st.title("Suricata Analyst Trainer")
st.caption("Operational SOC-focused rule reading, writing, tuning, repair, and advanced remediation practice.")

st.markdown(
    f"""
    <div class="hero-card">
        <strong>Training Preview {APP_VERSION}</strong><br>
        Build practical Suricata skill through guided lessons, scenario questions, tuning practice, rule repair, and remediation.
    </div>
    """,
    unsafe_allow_html=True,
)

if st.session_state.view == "Return to Main Menu":
    st.subheader("Return to Main Menu")
    st.write("Choose a learning path or training module from the sidebar. You can return here at any time without restarting the browser.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Questions Seen", summary.get("seen", 0))
    with col2:
        st.metric("Accuracy", f"{summary.get('accuracy', 0)}%")
    with col3:
        st.metric("Missed / Remediation", len(st.session_state.get("missed_ids", [])))
    with col4:
        st.metric("Lessons Complete", f"{len(completed_lessons())}/{len(LESSON_ORDER)}")

    render_learning_paths()

    st.markdown("### Recommended learning path")
    st.progress(lesson_progress_percent() / 100)

    path_cols = st.columns(4)
    for idx, lesson in enumerate(LESSON_ORDER):
        with path_cols[idx % 4]:
            done = lesson in completed_lessons()
            status = "Complete" if done else "Not complete"
            icon = "✅" if done else "📘"
            objective = LESSON_META.get(lesson, {}).get("objective", "")
            st.markdown(
                f"""
                <div class="lesson-card">
                    <div class="pill">Lesson {idx + 1} • {html.escape(status)}</div>
                    <div class="lesson-card-title">{icon} {html.escape(lesson)}</div>
                    <div class="lesson-card-body">{html.escape(objective)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button(f"Open Lesson {idx + 1}", key=f"open_lesson_{lesson}", use_container_width=True):
                st.session_state.selected_lesson = lesson
                st.session_state.view = "Lessons"
                rerun_top()

    st.markdown("### Practice flow")
    st.write("1. Complete the guided lesson cards")
    st.write("2. Launch the related practice module from the lesson")
    st.write("3. Answer, use hints, and review explanations")
    st.write("4. Use Review Missed / Remediation to revisit skipped or incorrect questions")
    st.write("5. Move into Traffic Scenario Labs and Investigation Capstones once the basics feel comfortable")

    st.markdown("### How practice works")
    st.write("- You do **not** have to answer correctly to continue. Wrong or skipped items go into remediation.")
    st.write("- Remediation is a review queue, not a punishment. Correct answers remove items from the queue.")
    st.write("- Some concepts repeat across reading, writing, repair, and tuning because analysts need to recognize the same idea in different operational contexts.")
    st.write("- Traffic Scenario Labs use Wireshark-style packet evidence and structured tasks so practice feels closer to SOC work, not paragraph writing.")

    st.markdown("### Production reality")
    st.write("- Noisy rules create alert fatigue and make real incidents easier to miss.")
    st.write("- Good tuning preserves detection intent; bad tuning just hides inconvenient alerts.")
    st.write("- The best answers explain traffic direction, matched field, expected behavior, and what the analyst would check next.")

    if summary.get("seen", 0) > 0:
        st.success("")

elif st.session_state.view == "Train":
    q = st.session_state.question
    if q is None:
        if st.session_state.bank_name == "Review Missed / Remediation":
            st.success("No missed or skipped questions are currently queued.")
            st.write("You are caught up. Continue the lesson path, choose another practice module, or return to the main menu.")
            render_recovery_nav("No remediation items available.")
        else:
            st.warning("No questions match the selected module/difficulty. Choose another module or set Difficulty to All.")
            render_recovery_nav("No questions available for this selection.")
        st.stop()

    top_cols = st.columns([2, 1, 1, 1])
    with top_cols[0]:
        st.subheader(q.category)
    with top_cols[1]:
        st.info(f"Mode: {q.mode}")
    with top_cols[2]:
        st.info(f"Difficulty: {q.difficulty}/4")
    with top_cols[3]:
        st.info(f"Module: {st.session_state.bank_name}")

    if st.session_state.bank_name == "Review Missed / Remediation":
        st.info("Remediation practice: this item came from a skipped or incorrect answer. You can move on anytime; answering correctly removes it from the remediation queue.")
    elif hasattr(trainer, "explain_selection_reason"):
        try:
            reason = trainer.explain_selection_reason(q, progress, filtered_bank())
            if reason:
                reason = reason.replace("Reviewing weak area", "Practice recommendation")
                st.caption(reason)
        except Exception:
            pass

    nav1, nav2, nav3, nav4 = st.columns(4)
    with nav4:
        st.caption("No lock-in: submit, reveal, or move on anytime.")

    if hasattr(q, "lab"):
        render_lab_question(q)
        st.stop()

    st.markdown("### Rule / Scenario")
    render_rule_box(q.rule, label="Rule / scenario")

    st.markdown("### Task")
    st.write(q.prompt)

    if is_guided_rule_build_question(q) and st.session_state.get("guided_rule_builder", True):
        render_guided_rule_builder(q)
        st.stop()

    answer_widget_key = f"answer_{st.session_state.answer_key_counter}"
    answer = st.text_area(
        "Your answer",
        key=answer_widget_key,
        height=150,
        placeholder="Type your answer, tuning recommendation, or repaired Suricata rule here..."
    )

    col_submit, col_hint, col_reveal, col_next = st.columns(4)

    with col_submit:
        if st.button("Submit Answer", type="primary", use_container_width=True):
            ok, issues = score_answer(answer, q)
            st.session_state.feedback = ok
            st.session_state.issues = issues
            st.session_state.show_explanation = True
            st.session_state.revealed = False
            record_attempt(q, ok, skipped=False)
            rerun_top()

    with col_hint:
        hint_disabled = st.session_state.training_mode == "Challenge Mode" and st.session_state.feedback is None
        if st.button("Show Another Hint", use_container_width=True, disabled=hint_disabled):
            if q.hints:
                idx = min(st.session_state.hint_index, len(q.hints) - 1)
                st.session_state.current_hint = q.hints[idx]
                st.session_state.hint_index += 1
                st.session_state.hints_used += 1
            else:
                st.session_state.current_hint = "No hint available for this question."
            rerun_top()
        if hint_disabled:
            st.caption("Challenge Mode: submit or reveal before viewing hints.")

    with col_reveal:
        if st.button("Skip / Reveal Answer", use_container_width=True):
            st.session_state.feedback = False
            st.session_state.issues = ["Skipped. Review the explanation and expected concepts below."]
            st.session_state.show_explanation = True
            st.session_state.revealed = True
            record_attempt(q, ok=False, skipped=True)
            rerun_top()

    with col_next:
        if st.button("Load Next Challenge", use_container_width=True):
            reset_current_question()
            rerun_top()

    if st.session_state.get("current_hint"):
        st.warning(st.session_state.current_hint)

    if st.session_state.feedback is not None:
        if st.session_state.feedback:
            st.success("Correct / reasonable answer. If this was in remediation, it has been cleared from the missed queue.")
        elif st.session_state.get("revealed"):
            st.warning("Skipped / revealed answer. This was added to remediation, but you can continue whenever ready.")
        else:
            st.error("Not quite. Added to remediation queue. You can review the explanation, try again mentally, or move to the next question.")

        feedback_items = explain_weak_answer(q, st.session_state.issues)
        if feedback_items:
            st.markdown("#### Why this answer may be weak")
            for issue in feedback_items:
                st.write(f"- {issue}")

    if st.session_state.show_explanation:
        st.markdown("### Explanation")
        st.write(q.explanation)

        render_soc_context(q)

        if getattr(q, "answer_points", None):
            with st.expander("Expected concepts / answer points", expanded=st.session_state.get("revealed", False)):
                for point in q.answer_points:
                    st.write(f"- {point}")

        if getattr(q, "skills", None):
            st.caption("Skills: " + ", ".join(q.skills))

        st.markdown("#### Analyst takeaway")
        st.write("The goal is not to memorize one exact sentence. The goal is to explain the detection intent, the scoped field or behavior, and what you would do next during triage or tuning.")

        post_cols = st.columns(3)
        with post_cols[2]:
            if st.button("Next Practice Item", key=f"continue_{q.id}", use_container_width=True):
                reset_current_question()
                rerun_top()

elif st.session_state.view == "Lessons":
    st.subheader("Guided Learning Path")
    st.write(
        "Read the lesson, review the operational comparison, complete the knowledge check, "
        "then launch the related practice module. You can switch lessons or return to training at any time."
    )

    lesson_name = st.selectbox(
        "Choose a lesson",
        LESSON_ORDER,
        index=LESSON_ORDER.index(st.session_state.selected_lesson) if st.session_state.selected_lesson in LESSON_ORDER else 0,
        key="lesson_selector",
    )
    if lesson_name != st.session_state.selected_lesson:
        st.session_state.selected_lesson = lesson_name
        rerun_top()
    meta = LESSON_META.get(lesson_name, {})

    done = lesson_name in completed_lessons()
    st.markdown(f"## {'✅' if done else '📘'} {lesson_name}")

    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### Objective")
        st.info(meta.get("objective", ""))
        st.markdown("### Why this matters in the SOC")
        st.write(meta.get("why", ""))
        if meta.get("analyst_note"):
            st.markdown("### Analyst note")
            st.write(meta.get("analyst_note"))
    with c2:
        st.metric("Lesson Progress", f"{len(completed_lessons())}/{len(LESSON_ORDER)}")
        st.progress(lesson_progress_percent() / 100)
        if done:
            st.success("Completed")
        else:
            st.warning("Not marked complete")

    st.markdown("### Full Lesson")
    with st.container(border=True):
        render_lesson_content(lesson_name)

    st.markdown("### Operational Comparison")
    st.caption("These examples are not saying the weak version never works. They show why the improved version is easier to defend, triage, and tune.")

    for idx, item in enumerate(meta.get("bad_good", []), start=1):
        st.markdown(f"#### Comparison {idx}")
        col_bad, col_better = st.columns(2)
        with col_bad:
            st.markdown(
                f"""
                <div class="compare-card">
                    <div class="pill">Weak / noisy</div>
                    <div class="compare-title">{html.escape(item.get('weak_label', 'Weak pattern'))}</div>
                    <div class="compare-body">{html.escape(item.get('weak_reason', ''))}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            render_rule_box(item.get("weak_code", "" ).strip(), label="Weak pattern")
        with col_better:
            st.markdown(
                f"""
                <div class="compare-card">
                    <div class="pill">Better</div>
                    <div class="compare-title">{html.escape(item.get('better_label', 'Better pattern'))}</div>
                    <div class="compare-body">{html.escape(item.get('better_reason', ''))}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            render_rule_box(item.get("better_code", "" ).strip(), label="Better pattern")

    if lesson_name == "Rule Building":
        st.markdown("### Visual Rule Breakdown")
        render_rule_breakdown()

    st.markdown("### Key Takeaways")
    with st.container(border=True):
        for item in meta.get("takeaways", []):
            st.write(f"- {item}")

    st.markdown("### Knowledge Check")
    render_knowledge_checks(lesson_name)

    st.markdown("### Next Step")
    col_done, col_practice, col_next_lesson = st.columns(3)
    with col_done:
        if st.button("Mark Lesson Complete", type="primary", use_container_width=True):
            mark_lesson_complete(lesson_name)
            st.success("Lesson marked complete.")
            rerun_top()
    with col_practice:
        practice_module = meta.get("practice_module", "Adaptive Mixed")
        if st.button(f"Start Practice: {practice_module}", use_container_width=True):
            set_training_module(practice_module, lesson_context=lesson_name)
            rerun_top()
    with col_next_lesson:
        idx = LESSON_ORDER.index(lesson_name)
        next_lesson = LESSON_ORDER[(idx + 1) % len(LESSON_ORDER)]
        if st.button(f"Next Lesson: {next_lesson}", use_container_width=True):
            st.session_state.selected_lesson = next_lesson
            rerun_top()

elif st.session_state.view == "Glossary":
    st.subheader("Glossary")
    query = st.text_input("Search glossary")
    glossary = getattr(trainer, "GLOSSARY", {})
    for term, definition in glossary.items():
        if not query or query.lower() in term.lower() or query.lower() in definition.lower():
            st.markdown(f"**{term}**")
            st.write(definition)
            st.markdown("---")

elif st.session_state.view == "Progress":
    st.subheader("Progress / Remediation")
    st.write("Progress is saved for the running app session and also written to a local file when the environment allows it. Use  before closing if you want a portable copy.")
    st.info("Remediation shows skipped or incorrect questions. You can start review anytime; you are never forced to stay on a question until it is correct.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Seen", summary.get("seen", 0))
    with col2:
        st.metric("Correct", summary.get("correct", 0))
    with col3:
        st.metric("Wrong", summary.get("wrong", 0))
    with col4:
        st.metric("Accuracy", f"{summary.get('accuracy', 0)}%")

    st.markdown("### Guided Lesson Progress")
    for lesson in LESSON_ORDER:
        status = "✅ Complete" if lesson in completed_lessons() else "⬜ Not complete"
        st.write(f"- **{lesson}** — {status}")

    missed_ids = st.session_state.get("missed_ids", [])
    st.markdown("### Remediation Queue")
    if not missed_ids:
        st.success("No missed/skipped questions currently queued.")
        st.write("You are caught up. Keep moving through the lesson path or jump back into practice.")
        nav_cols = st.columns(3)
        with nav_cols[0]:
            if st.button("Continue Lesson", key="empty_missed_continue_lesson", use_container_width=True):
                st.session_state.view = "Lessons"
                rerun_top()
        with nav_cols[1]:
            if st.button("Start Related Practice", key="empty_missed_start_practice", use_container_width=True):
                st.session_state.view = "Train"
                if st.session_state.bank_name == "Review Missed / Remediation":
                    st.session_state.bank_name = "Adaptive Mixed"
                reset_current_question()
                rerun_top()
    else:
        qmap = all_questions_by_id()
        for qid in missed_ids:
            mq = qmap.get(qid)
            if mq:
                st.write(f"- **{mq.id}** — {mq.category} / {mq.mode}: {mq.prompt}")

        if st.button("Start Review Missed / Remediation", type="primary"):
            st.session_state.bank_name = "Review Missed / Remediation"
            st.session_state.view = "Train"
            reset_current_question()
            rerun_top()

    with st.expander("Recent activity"):
        events = list(reversed(progress.get("sessions", [])[-25:]))
        if not events:
            st.write("No session events yet.")
        else:
            st.json(events)


elif st.session_state.view == "Feedback":
    st.subheader("Training Preview Feedback")
    st.write("Use this to collect learner feedback before sharing the trainer more broadly. You can download a copy for your notes.")

    usefulness = st.slider("How useful does this feel as a learning tool?", 1, 5, 4)
    realism = st.slider("How realistic are the scenarios/rules?", 1, 5, 3)
    clarity = st.slider("How clear is the flow/UI?", 1, 5, 4)
    confusing = st.text_area("What was confusing?", height=90)
    missing = st.text_area("What feels missing?", height=90)
    advanced = st.text_area("What would make the advanced/production-style content better?", height=90)
    would_use = st.radio("Would you use this again or recommend it to a junior analyst?", ["Yes", "Maybe", "No"], horizontal=True)

    feedback_blob = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "app_version": APP_VERSION,
        "usefulness": usefulness,
        "realism": realism,
        "clarity": clarity,
        "confusing": confusing,
        "missing": missing,
        "advanced_content_feedback": advanced,
        "would_use_again": would_use,
        "summary_at_feedback": global_summary(get_progress()),
    }
