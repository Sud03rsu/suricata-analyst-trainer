import os
import random
import re
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"

PROGRESS_FILE = "suricata_trainer_progress.json"

# ============================================================
# GUIDED LEARNING CONTENT
# ============================================================

NETWORK_VARIABLES_LESSON = """
Suricata rules normally use variables instead of hard-coded networks.

Common variables:
  $HOME_NET      = networks you are protecting
  $EXTERNAL_NET  = everything outside your protected networks
  $HTTP_SERVERS  = internal web servers, if defined
  $DNS_SERVERS   = DNS servers, if defined

Example direction:
  alert http $EXTERNAL_NET any -> $HOME_NET any (...)

Plain English:
  Alert on HTTP traffic from outside networks going to our protected network.

Why this matters:
  any any -> any any is easy for training, but noisy in real environments.
  $EXTERNAL_NET -> $HOME_NET makes the rule more operational.
"""

RULE_BUILDING_LESSON = """
Suricata rule shape:

  action protocol source_ip source_port direction dest_ip dest_port (options;)

Example:

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Example"; http.uri; content:"/login"; sid:100001; rev:1;)

Breakdown:
  alert              = action
  http               = protocol/app-layer parser
  $EXTERNAL_NET any  = source network and source port
  ->                 = traffic direction
  $HOME_NET any      = destination network and destination port
  msg                = alert name
  http.uri           = inspect the URI/path
  content:"/login"  = match this string
  sid/rev            = unique rule ID and revision
"""

BUFFER_LESSON = """
A buffer is the specific part of traffic Suricata should inspect.

Common beginner buffers:
  http.method        = GET, POST, PUT, DELETE
  http.uri           = path/URI, like /login or /admin
  http.host          = HTTP Host header
  http.user_agent    = User-Agent header
  http.request_body  = submitted form/body data
  dns.query          = queried domain name
  tls.sni            = TLS hostname from the handshake

Beginner rule of thumb:
  Do not use raw content unless you know why.
  Put content inside the correct buffer.
"""

TUNING_LESSON = """
Tuning means reducing false positives while keeping useful detection.

Beginner tuning checklist:
  1. Is the match scoped to the right buffer?
  2. Is the traffic direction right?
  3. Can we use $EXTERNAL_NET -> $HOME_NET or $HOME_NET -> $EXTERNAL_NET?
  4. Is the content too generic?
  5. Should we add nocase?
  6. Should repeated behavior use detection_filter instead of alerting once per packet?

Do not start beginners with detection_filter.
Start with:
  buffer scope + specific content + network variables + clear msg/sid/rev.
"""

def show_lesson(title: str, body: str):
    print_header(title)
    print(body.strip())
    pause()

def guided_rule_template(protocol="http", src="$EXTERNAL_NET", sport="any", dst="$HOME_NET", dport="any"):
    return f'alert {protocol} {src} {sport} -> {dst} {dport} (msg:"Describe what this detects"; <buffer>; content:"<thing to match>"; sid:1000001; rev:1;)'


# ============================================================
# POLISHED COURSE UI HELPERS
# ============================================================

def hr(width=74):
    print(CYAN + ("-" * width) + RESET)

def box(title: str, lines: List[str], color=CYAN):
    width = 74
    print(color + "┌" + "─" * (width - 2) + "┐" + RESET)
    clean_title = f" {title} "
    print(color + "│" + clean_title[:width-2].center(width - 2) + "│" + RESET)
    print(color + "├" + "─" * (width - 2) + "┤" + RESET)
    for line in lines:
        chunks = [line[i:i + width - 6] for i in range(0, len(line), width - 6)] or [""]
        for chunk in chunks:
            print(color + "│ " + RESET + chunk.ljust(width - 4) + color + " │" + RESET)
    print(color + "└" + "─" * (width - 2) + "┘" + RESET)

def soft_clear(title: str):
    print_header(title)

def menu_choice(prompt="Select an option"):
    print()
    return input(f"{prompt}> ").strip()

def lesson_card(title: str, objective: str, key_points: List[str], why: str):
    soft_clear(title)
    box("Objective", [objective], CYAN)
    print()
    print(BOLD + "Key points:" + RESET)
    for p in key_points:
        print("  " + GREEN + "• " + RESET + p)
    print()
    print(BOLD + "Why this matters in the SOC:" + RESET)
    print("  " + why)
    pause()

def recap_card(title: str, learned: List[str], next_step: str):
    soft_clear(title + " - Recap")
    print(BOLD + "You learned:" + RESET)
    for item in learned:
        print("  " + GREEN + "✓ " + RESET + item)
    print()
    print(BOLD + "Next:" + RESET)
    print("  " + next_step)
    pause()

def simple_success(msg: str):
    print(GREEN + "✓ " + msg + RESET)

def simple_warn(msg: str):
    print(YELLOW + "! " + msg + RESET)

def simple_fail(msg: str):
    print(RED + "✖ " + msg + RESET)


# ============================================================
# GLOSSARY / QUICK REFERENCE
# ============================================================

GLOSSARY = {
    "alert": "Rule action. Creates an alert when the rule matches.",
    "protocol": "The traffic parser/type Suricata should use, such as http, dns, tls, tcp, ip.",
    "$HOME_NET": "The protected/internal networks you care about defending.",
    "$EXTERNAL_NET": "Networks outside $HOME_NET. Often external/untrusted networks.",
    "any": "Any IP or port. Useful in training, but too broad if overused.",
    "->": "Traffic direction. Left side is source, right side is destination.",
    "msg": "Human-readable alert name shown to analysts.",
    "sid": "Signature ID. A unique number for the rule.",
    "rev": "Revision number. Increase it when the rule changes.",
    "content": "String Suricata should look for.",
    "nocase": "Makes a content match case-insensitive.",
    "buffer": "A specific part of traffic to inspect, such as http.uri or dns.query.",
    "http.method": "HTTP request method, such as GET or POST.",
    "http.uri": "HTTP URI/path, such as /login or /admin.",
    "http.host": "HTTP Host header.",
    "http.user_agent": "HTTP User-Agent header.",
    "http.request_body": "HTTP request body, such as submitted form data.",
    "dns.query": "The DNS domain name being queried.",
    "tls.sni": "TLS Server Name Indication hostname from the TLS handshake.",
    "flow": "Limits matching by session state or direction, such as established,to_server.",
    "flow:established,to_server": "Match established client-to-server traffic. Useful, but introduced after basics.",
    "detection_filter": "Rate-based alerting. Used later to avoid alerting on every single packet.",
    "false positive": "An alert that fires on benign activity.",
    "tuning": "Improving a rule so it is useful and less noisy.",
}

def show_glossary():
    while True:
        soft_clear("SURICATA TRAINER - GLOSSARY")
        print("Type a term to search, press Enter to show all, or type back.")
        query = input("\nTerm> ").strip().lower()
        if query in ["back", "exit", "quit"]:
            return

        items = []
        for k, v in GLOSSARY.items():
            if not query or query in k.lower() or query in v.lower():
                items.append((k, v))

        if not items:
            simple_warn("No match found.")
        else:
            for k, v in items:
                print(GREEN + f"\n{k}" + RESET)
                print("  " + v)
        pause()


# ============================================================
# UTILITY
# ============================================================

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input("\nPress Enter to continue...")

def norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())

def tokens(text: str) -> set:
    return set(re.findall(r"[a-zA-Z0-9_.$/:\-]+", norm(text)))

def contains_any(text: str, words: List[str]) -> bool:
    t = norm(text)
    return any(w.lower() in t for w in words)

def print_header(title: str):
    clear()
    print(CYAN + BOLD + title + RESET)
    print("-" * 70)

def color_result(ok: bool):
    return GREEN + "✔ CORRECT" + RESET if ok else RED + "✖ NOT QUITE" + RESET

# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class Question:
    id: str
    category: str
    prompt: str
    rule: str
    answer_points: List[str]
    required_terms: List[str]
    accepted_terms: List[str]
    hints: List[str]
    explanation: str
    difficulty: int = 1
    mode: str = "read"  # read, optimize, write, repair
    skills: List[str] = field(default_factory=list)

# ============================================================
# QUESTION BANKS
# 18 per category. Add more by extending these lists.
# ============================================================

RULE_READING = [
    Question(
        id="rr001", category="Rule Reading", mode="read", difficulty=1,
        rule='alert http any any -> any any (http.method; content:"POST"; sid:100001; rev:1;)',
        prompt="What part of HTTP traffic does http.method inspect, and what would this rule alert on?",
        answer_points=["http method", "request method", "post requests"],
        required_terms=["method"],
        accepted_terms=["post", "verb", "request"],
        hints=[
            "This keyword does not inspect the URI, body, cookie, or header value.",
            "HTTP methods are verbs such as GET, POST, PUT, DELETE, and HEAD.",
            "This rule is looking for POST in the HTTP request method buffer."
        ],
        explanation="http.method selects the HTTP request method buffer. The content match then looks for POST, so the rule alerts on HTTP POST requests."
    ),
    Question(
        id="rr002", category="Rule Reading", mode="read", difficulty=1,
        rule='alert http any any -> any any (http.uri; content:"/admin"; sid:100002; rev:1;)',
        prompt="What does http.uri inspect, and why is content:\"/admin\" scoped better than a raw payload match?",
        answer_points=["uri path", "request uri", "url path", "admin endpoint"],
        required_terms=["uri"],
        accepted_terms=["path", "url", "endpoint", "admin"],
        hints=[
            "This inspects the requested resource, not the full packet payload.",
            "Think of the part after the domain name in a web request.",
            "A URI-scoped match avoids matching the word admin in unrelated HTTP body text."
        ],
        explanation="http.uri inspects the HTTP request URI. Scoping content to http.uri makes the match more precise because it looks for /admin in the requested path instead of anywhere in the packet."
    ),
    Question(
        id="rr003", category="Rule Reading", mode="read", difficulty=1,
        rule='alert tls any any -> any any (tls.sni; content:"example.com"; sid:100003; rev:1;)',
        prompt="What does tls.sni inspect, and during what part of the connection is it normally visible?",
        answer_points=["server name indication", "hostname", "domain in tls handshake", "client hello"],
        required_terms=["sni"],
        accepted_terms=["domain", "hostname", "handshake", "client hello"],
        hints=[
            "SNI helps a TLS server know which certificate/site the client wants.",
            "It is commonly visible before the encrypted application data starts.",
            "Look for the domain name in the TLS ClientHello."
        ],
        explanation="tls.sni inspects the Server Name Indication hostname from the TLS handshake, typically found in the ClientHello before application data is encrypted."
    ),
    Question(
        id="rr004", category="Rule Reading", mode="read", difficulty=2,
        rule='alert tcp any any -> any 443 (flow:established,to_server; sid:100004; rev:1;)',
        prompt="What does flow:established,to_server mean in this rule?",
        answer_points=["established tcp session", "client to server direction", "traffic to server after handshake"],
        required_terms=["established"],
        accepted_terms=["to_server", "server", "session", "handshake", "client"],
        hints=[
            "established means Suricata has seen the TCP session as established.",
            "to_server means the packet direction is from client toward server.",
            "This avoids matching random packets that are not part of a valid client-to-server flow."
        ],
        explanation="flow:established,to_server limits the rule to packets in an established TCP session traveling from the client to the server."
    ),
    Question(
        id="rr005", category="Rule Reading", mode="read", difficulty=2,
        rule='alert tcp any any -> any any (flags:S; sid:100005; rev:1;)',
        prompt="What does flags:S inspect, and what kind of activity can this help detect?",
        answer_points=["tcp syn flag", "connection attempts", "syn scan"],
        required_terms=["syn"],
        accepted_terms=["flag", "scan", "connection", "handshake"],
        hints=[
            "The S flag is used at the beginning of a TCP handshake.",
            "Many SYNs to many ports can indicate scanning.",
            "This rule matches TCP packets with SYN set."
        ],
        explanation="flags:S matches TCP SYN packets. This can be useful for detecting connection attempts or, with thresholding, SYN scan behavior."
    ),
    Question(
        id="rr006", category="Rule Reading", mode="read", difficulty=2,
        rule='alert dns any any -> any any (dns.query; content:"bad-domain.com"; sid:100006; rev:1;)',
        prompt="What does dns.query inspect, and what is the rule looking for?",
        answer_points=["dns query name", "domain requested", "bad-domain.com"],
        required_terms=["dns"],
        accepted_terms=["query", "domain", "requested", "bad-domain.com"],
        hints=[
            "This is not inspecting the answer IP address.",
            "It is looking at the name being queried by a client.",
            "The content match is scoped to the DNS query buffer."
        ],
        explanation="dns.query inspects the queried domain name. This rule alerts when a DNS query contains bad-domain.com."
    ),
    Question(
        id="rr007", category="Rule Reading", mode="read", difficulty=2,
        rule='alert http any any -> any any (http.user_agent; content:"curl"; nocase; sid:100007; rev:1;)',
        prompt="What does http.user_agent inspect, and what does nocase change?",
        answer_points=["user-agent header", "case insensitive", "curl"],
        required_terms=["user"],
        accepted_terms=["agent", "header", "case", "curl", "insensitive"],
        hints=[
            "This buffer is an HTTP request header commonly used to identify client software.",
            "nocase means CURL, Curl, and curl can all match.",
            "The rule is looking for curl in the User-Agent header."
        ],
        explanation="http.user_agent scopes inspection to the User-Agent header. nocase makes the content comparison case-insensitive."
    ),
    Question(
        id="rr008", category="Rule Reading", mode="read", difficulty=2,
        rule='alert http any any -> any any (content:"password"; http.request_body; sid:100008; rev:1;)',
        prompt="What does http.request_body do in this rule?",
        answer_points=["request body", "post body", "http body", "form data"],
        required_terms=["body"],
        accepted_terms=["request", "post", "form", "payload"],
        hints=[
            "This is usually where submitted form values or POST data may appear.",
            "It is not the URI and not the User-Agent header.",
            "The content keyword is scoped to the HTTP request body."
        ],
        explanation="http.request_body scopes the content match to the HTTP request body, such as submitted form data or POST content."
    ),
    Question(
        id="rr009", category="Rule Reading", mode="read", difficulty=2,
        rule='alert ip any any -> any any (dsize:>1200; sid:100009; rev:1;)',
        prompt="What does dsize:>1200 evaluate?",
        answer_points=["payload size greater than 1200", "packet data size", "application data bytes"],
        required_terms=["size"],
        accepted_terms=["1200", "bytes", "payload", "data", "greater"],
        hints=[
            "This is about the amount of packet data, not the IP address.",
            "The > symbol means greater than.",
            "It matches packets with data size greater than 1200 bytes."
        ],
        explanation="dsize tests the packet payload/data size. dsize:>1200 matches when the packet data size is greater than 1200 bytes."
    ),
    Question(
        id="rr010", category="Rule Reading", mode="read", difficulty=2,
        rule='alert http any any -> any any (http.host; content:"evil.com"; sid:100010; rev:1;)',
        prompt="What does http.host inspect, and how is it different from tls.sni?",
        answer_points=["http host header", "host header", "tls sni is handshake"],
        required_terms=["host"],
        accepted_terms=["header", "http", "sni", "tls", "handshake"],
        hints=[
            "HTTP Host is an HTTP header.",
            "TLS SNI is seen in the TLS handshake before encrypted HTTP content.",
            "http.host is for plain HTTP or decoded HTTP, not the TLS ClientHello."
        ],
        explanation="http.host inspects the HTTP Host header. tls.sni inspects the hostname from the TLS handshake. They are different protocol fields."
    ),
    Question(
        id="rr011", category="Rule Reading", mode="read", difficulty=3,
        rule='alert http any any -> any any (content:"cmd.exe"; http.uri; nocase; sid:100011; rev:1;)',
        prompt="What buffer is content:\"cmd.exe\" matched against, and why is that important?",
        answer_points=["http uri buffer", "uri scoped content", "not entire payload"],
        required_terms=["uri"],
        accepted_terms=["buffer", "scoped", "payload", "cmd.exe", "nocase"],
        hints=[
            "The keyword after content changes where Suricata looks.",
            "It is not looking through the entire packet payload.",
            "The match is scoped to the HTTP URI and is case-insensitive."
        ],
        explanation="The content match is scoped to http.uri, so Suricata searches for cmd.exe in the URI only. That reduces false positives compared to an unscoped payload match."
    ),
    Question(
        id="rr012", category="Rule Reading", mode="read", difficulty=3,
        rule='alert http any any -> any any (content:"/login"; http.uri; content:"username="; http.request_body; sid:100012; rev:1;)',
        prompt="What are the two separate matches in this rule checking?",
        answer_points=["login in uri", "username in request body", "uri and body"],
        required_terms=["uri", "body"],
        accepted_terms=["login", "username", "request", "form"],
        hints=[
            "The first content is scoped to the URI.",
            "The second content is scoped to the HTTP request body.",
            "This checks for a login endpoint and submitted username field."
        ],
        explanation="The rule checks for /login in the URI and username= in the HTTP request body. Using two scoped buffers makes the logic more precise."
    ),
    Question(
        id="rr013", category="Rule Reading", mode="read", difficulty=3,
        rule='alert tcp any any -> any 22 (flow:to_server,established; content:"SSH-"; sid:100013; rev:1;)',
        prompt="What does this rule likely detect on TCP port 22?",
        answer_points=["ssh banner", "ssh traffic", "client to server established ssh"],
        required_terms=["ssh"],
        accepted_terms=["banner", "port 22", "established", "server"],
        hints=[
            "Port 22 is commonly associated with SSH.",
            "SSH protocol banners begin with SSH-.",
            "The flow direction is toward the server in an established session."
        ],
        explanation="This rule looks for SSH- in established client-to-server traffic to port 22, which commonly indicates SSH protocol traffic or banner exchange."
    ),
    Question(
        id="rr014", category="Rule Reading", mode="read", difficulty=3,
        rule='alert http any any -> any any (http.header; content:"X-Api-Key"; nocase; sid:100014; rev:1;)',
        prompt="What does http.header inspect, and what is the risk of using this rule alone?",
        answer_points=["http headers", "x-api-key header", "may be noisy without value or scope"],
        required_terms=["header"],
        accepted_terms=["api", "key", "noisy", "value", "false"],
        hints=[
            "This searches all HTTP headers.",
            "Header name alone may be legitimate in many apps.",
            "Without a specific value, host, URI, or flow context, it may be noisy."
        ],
        explanation="http.header inspects HTTP headers. A rule matching only X-Api-Key may alert on legitimate API traffic unless scoped with host, URI, value pattern, or other context."
    ),
    Question(
        id="rr015", category="Rule Reading", mode="read", difficulty=3,
        rule='alert dns any any -> any any (dns.query; content:".ru"; endswith; sid:100015; rev:1;)',
        prompt="What does endswith mean in this DNS rule?",
        answer_points=["query ends with .ru", "suffix match", "domain ending"],
        required_terms=["end"],
        accepted_terms=["suffix", ".ru", "domain", "query"],
        hints=[
            "This does not mean .ru can appear anywhere.",
            "It means the inspected buffer must end with the content.",
            "The rule targets DNS queries ending in .ru."
        ],
        explanation="endswith requires the content to appear at the end of the selected buffer, so this rule targets DNS queries ending with .ru."
    ),
    Question(
        id="rr016", category="Rule Reading", mode="read", difficulty=3,
        rule='alert http any any -> any any (http.uri; pcre:"/\\/wp-admin\\/.*\\.php/i"; sid:100016; rev:1;)',
        prompt="What is the pcre looking for in the URI?",
        answer_points=["wp-admin php uri", "wordpress admin php path", "case insensitive regex"],
        required_terms=["wp-admin"],
        accepted_terms=["php", "uri", "regex", "case", "wordpress"],
        hints=[
            "The /i at the end makes the regular expression case-insensitive.",
            "The pattern includes wp-admin and a PHP file.",
            "It is scoped to HTTP URI."
        ],
        explanation="The PCRE looks for a URI containing /wp-admin/ followed later by a .php path, case-insensitively."
    ),
    Question(
        id="rr017", category="Rule Reading", mode="read", difficulty=3,
        rule='alert tcp any any -> any any (flow:stateless; flags:S; sid:100017; rev:1;)',
        prompt="What does flow:stateless imply here, and when might it be used?",
        answer_points=["does not require established flow", "stateless packet matching", "scan or malformed traffic"],
        required_terms=["stateless"],
        accepted_terms=["established", "session", "scan", "packet"],
        hints=[
            "This rule does not require Suricata to track an established session.",
            "It can match individual packets without full flow state.",
            "It is sometimes useful for scan-like or abnormal packet detection."
        ],
        explanation="flow:stateless tells Suricata not to require normal flow tracking state. Combined with flags:S, it can match SYN packets without needing an established session."
    ),
    Question(
        id="rr018", category="Rule Reading", mode="read", difficulty=3,
        rule='alert http any any -> any any (http.uri; content:"/download"; startswith; sid:100018; rev:1;)',
        prompt="What does startswith do in this URI rule?",
        answer_points=["uri starts with /download", "prefix match", "beginning of buffer"],
        required_terms=["start"],
        accepted_terms=["prefix", "beginning", "uri", "download"],
        hints=[
            "It does not match /download anywhere in the URI.",
            "It requires the selected buffer to begin with the content.",
            "The selected buffer is http.uri."
        ],
        explanation="startswith requires the content to appear at the start of the selected buffer, so this alerts when the URI begins with /download."
    ),
]


VARIABLES_AND_STRUCTURE = [
    Question(
        id="vs001", category="Variables & Structure", mode="read", difficulty=1,
        rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound HTTP to protected network"; http.uri; content:"/admin"; sid:600001; rev:1;)',
        prompt="In plain English, what does $EXTERNAL_NET any -> $HOME_NET any mean?",
        answer_points=["outside to protected network", "external to internal", "traffic from external net to home net"],
        required_terms=[],
        accepted_terms=["external", "home", "protected", "internal", "outside", "inbound"],
        hints=[
            "$HOME_NET usually means the networks you defend.",
            "$EXTERNAL_NET usually means outside/untrusted networks.",
            "The arrow shows traffic direction."
        ],
        explanation="$EXTERNAL_NET any -> $HOME_NET any means traffic from external/untrusted networks to protected/internal networks on any source and destination port.",
        skills=["rule_structure"]
    ),
    Question(
        id="vs002", category="Variables & Structure", mode="read", difficulty=1,
        rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound DNS query"; dns.query; content:"example.com"; sid:600002; rev:1;)',
        prompt="Why does this outbound DNS rule use $HOME_NET as the source?",
        answer_points=["internal client querying outbound", "home net makes dns query", "protected host source"],
        required_terms=[],
        accepted_terms=["internal", "home", "client", "source", "outbound"],
        hints=[
            "Think about who sends a DNS query.",
            "Internal clients usually initiate outbound DNS lookups.",
            "$HOME_NET as source means protected hosts are making the request."
        ],
        explanation="The source is $HOME_NET because the protected/internal host is initiating the DNS query outbound toward external DNS infrastructure.",
        skills=["rule_structure", "dns"]
    ),
    Question(
        id="vs003", category="Variables & Structure", mode="read", difficulty=1,
        rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound TLS SNI"; tls.sni; content:"bad.example"; sid:600003; rev:1;)',
        prompt="What is the protected host doing in this rule?",
        answer_points=["making outbound tls connection", "connecting to bad.example", "sending tls client hello"],
        required_terms=[],
        accepted_terms=["outbound", "tls", "sni", "connecting", "bad.example"],
        hints=[
            "$HOME_NET is on the left side of the arrow.",
            "That means the protected host is the source.",
            "tls.sni shows the hostname requested in the TLS handshake."
        ],
        explanation="A protected/internal host is making an outbound TLS connection where the SNI hostname contains bad.example.",
        skills=["rule_structure", "tls"]
    ),
    Question(
        id="vs004", category="Variables & Structure", mode="read", difficulty=1,
        rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound curl User-Agent"; http.user_agent; content:"curl"; nocase; sid:600004; rev:1;)',
        prompt="Why is $HOME_NET -> $EXTERNAL_NET better than any any -> any any for this rule?",
        answer_points=["reduces noise", "outbound internal traffic", "more specific direction"],
        required_terms=[],
        accepted_terms=["noise", "specific", "outbound", "internal", "direction"],
        hints=[
            "any any -> any any matches every direction.",
            "$HOME_NET -> $EXTERNAL_NET describes internal hosts going outbound.",
            "Specific direction reduces false positives."
        ],
        explanation="$HOME_NET -> $EXTERNAL_NET makes the rule specific to outbound traffic from protected hosts, which is usually less noisy than matching every possible direction.",
        skills=["rule_structure", "tuning", "http_buffers"]
    ),
    Question(
        id="vs005", category="Variables & Structure", mode="read", difficulty=1,
        rule='alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Inbound web traffic"; http.uri; content:"/login"; sid:600005; rev:1;)',
        prompt="What does destination port 80 mean in this rule?",
        answer_points=["traffic to web server port 80", "http destination port", "dest port 80"],
        required_terms=[],
        accepted_terms=["80", "web", "http", "destination", "port"],
        hints=[
            "The destination port is after $HOME_NET.",
            "Port 80 is commonly HTTP.",
            "This limits the alert to traffic going to protected hosts on port 80."
        ],
        explanation="Destination port 80 means the traffic is going to protected hosts on TCP/HTTP port 80.",
        skills=["rule_structure", "http_buffers"]
    ),
]


OPTIMIZATION = [
    Question(
        id="op001", category="Optimization", mode="optimize", difficulty=1,
        rule='alert http any any -> any any (content:"login"; sid:200001; rev:1;)',
        prompt="This rule is noisy. How would you make it better for detecting actual login attempts?",
        answer_points=["scope to http.uri", "use http.method post", "match request body fields", "add flow established to_server"],
        required_terms=[],
        accepted_terms=["http.uri", "post", "method", "body", "flow", "to_server", "username"],
        hints=[
            "Do not leave content unscoped if you know where it should appear.",
            "Most login submissions use POST and may include username/password fields.",
            "A stronger rule scopes /login to URI, POST to method, and form fields to request body."
        ],
        explanation="Better logic would use flow:established,to_server, match /login in http.uri, require POST in http.method, and optionally match username/password fields in http.request_body."
    ),
    Question(
        id="op002", category="Optimization", mode="optimize", difficulty=1,
        rule='alert dns any any -> any any (content:"com"; sid:200002; rev:1;)',
        prompt="Why is this DNS rule bad, and how should it be improved?",
        answer_points=["too broad", "scope to dns.query", "specific domain or suffix", "endswith"],
        required_terms=[],
        accepted_terms=["broad", "dns.query", "specific", "domain", "endswith", "suffix"],
        hints=[
            "com appears in a huge amount of normal DNS traffic.",
            "Use dns.query so the match applies to queried names.",
            "Use specific domains, suspicious TLD suffixes, or threat intel domains."
        ],
        explanation="Matching com is extremely broad. Scope to dns.query and match a specific domain, suspicious suffix, or IOC. Use endswith for suffix logic where appropriate."
    ),
    Question(
        id="op003", category="Optimization", mode="optimize", difficulty=2,
        rule='alert tcp any any -> any any (flags:S; sid:200003; rev:1;)',
        prompt="This SYN rule fires too often. How do you tune it for scan behavior?",
        answer_points=["add threshold", "track by source", "count many syns", "limit alert rate"],
        required_terms=[],
        accepted_terms=["threshold", "track by_src", "count", "seconds", "rate", "detection_filter"],
        hints=[
            "A single SYN is normal.",
            "Scan behavior is about rate, volume, and destination spread.",
            "Use thresholding/detection_filter and track by source."
        ],
        explanation="Do not alert on every SYN. Add rate logic such as detection_filter or thresholding, tracking by source over a time window."
    ),
    Question(
        id="op004", category="Optimization", mode="optimize", difficulty=2,
        rule='alert http any any -> any any (http.user_agent; content:"Mozilla"; sid:200004; rev:1;)',
        prompt="Why is this user-agent rule poor, and what would a better version focus on?",
        answer_points=["mozilla is normal", "specific suspicious user agent", "nocase", "known tool"],
        required_terms=[],
        accepted_terms=["normal", "specific", "suspicious", "tool", "curl", "python", "powershell", "nocase"],
        hints=[
            "Mozilla appears in many normal browser User-Agents.",
            "User-Agent rules should target unusual or known malicious client strings.",
            "Add nocase and match a more specific suspicious value."
        ],
        explanation="Mozilla is too common. A better rule targets a specific suspicious User-Agent string, automation tool, malware family string, or environment-specific anomaly."
    ),
    Question(
        id="op005", category="Optimization", mode="optimize", difficulty=2,
        rule='alert http any any -> any any (content:"admin"; sid:200005; rev:1;)',
        prompt="How would you reduce false positives while still detecting admin page access?",
        answer_points=["scope to http.uri", "match /admin", "startswith or depth", "host scope"],
        required_terms=[],
        accepted_terms=["http.uri", "/admin", "startswith", "host", "flow", "to_server"],
        hints=[
            "The word admin can appear in page text, cookies, comments, or scripts.",
            "Admin access usually belongs in the URI/path.",
            "Host or URI scoping makes this far cleaner."
        ],
        explanation="Scope the match to http.uri and look for an admin path such as /admin, /wp-admin, or /administrator. Add host or flow context if appropriate."
    ),
    Question(
        id="op006", category="Optimization", mode="optimize", difficulty=2,
        rule='alert tls any any -> any any (tls.sni; content:"cdn"; sid:200006; rev:1;)',
        prompt="This TLS SNI rule is noisy. What tuning approach makes sense?",
        answer_points=["match specific domain", "avoid generic cdn", "allowlist known cdns", "environment baseline"],
        required_terms=[],
        accepted_terms=["specific", "domain", "allowlist", "baseline", "known", "sni"],
        hints=[
            "cdn is generic and appears in legitimate infrastructure.",
            "Use specific suspicious hostnames or IOC domains.",
            "Baseline common CDNs in your environment."
        ],
        explanation="Generic SNI strings like cdn are noisy. Tune by matching specific malicious domains, suspicious patterns, or domains not expected in the environment."
    ),
    Question(
        id="op007", category="Optimization", mode="optimize", difficulty=2,
        rule='alert ip any any -> any any (dsize:>100; sid:200007; rev:1;)',
        prompt="Why is dsize:>100 alone usually weak, and what context would improve it?",
        answer_points=["too generic", "add protocol context", "ports", "flow", "specific payload"],
        required_terms=[],
        accepted_terms=["generic", "protocol", "port", "flow", "content", "threshold"],
        hints=[
            "Many normal packets have payloads larger than 100 bytes.",
            "Size checks are useful when paired with protocol or behavior context.",
            "Add protocol, direction, port, content, or thresholding."
        ],
        explanation="dsize alone is rarely meaningful. Pair it with protocol, direction, port, content, flow state, or behavior thresholds."
    ),
    Question(
        id="op008", category="Optimization", mode="optimize", difficulty=2,
        rule='alert http any any -> any any (http.header; content:"token"; sid:200008; rev:1;)',
        prompt="How would you improve this rule so it does not alert on every normal token header?",
        answer_points=["specific header name", "specific token pattern", "host or uri scope", "pcre"],
        required_terms=[],
        accepted_terms=["specific", "header", "pattern", "pcre", "host", "uri", "value"],
        hints=[
            "The word token can appear in many legitimate headers.",
            "Look for a specific header/value pattern or suspicious token format.",
            "Host/URI scoping can reduce noise."
        ],
        explanation="Use a specific header name/value, suspicious token pattern, PCRE if needed, and host or URI context. Avoid generic header words."
    ),
    Question(
        id="op009", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (content:"cmd.exe"; sid:200009; rev:1;)',
        prompt="How would you tune this for web exploitation attempts?",
        answer_points=["scope to http.uri or request_body", "nocase", "flow to_server", "add related commands"],
        required_terms=[],
        accepted_terms=["http.uri", "request_body", "nocase", "flow", "to_server", "powershell", "whoami"],
        hints=[
            "cmd.exe in a server response may not mean exploitation.",
            "Exploit attempts often place command strings in the URI or request body.",
            "Use flow direction and HTTP buffers."
        ],
        explanation="Scope cmd.exe to http.uri or http.request_body, add flow:established,to_server, use nocase, and consider related command indicators when appropriate."
    ),
    Question(
        id="op010", category="Optimization", mode="optimize", difficulty=3,
        rule='alert dns any any -> any any (dns.query; pcre:"/[a-z0-9]{12,}\\./"; sid:200010; rev:1;)',
        prompt="This tries to catch suspicious long DNS labels. What else should be added to reduce false positives?",
        answer_points=["threshold", "label length", "exclude known domains", "entropy", "track by source"],
        required_terms=[],
        accepted_terms=["threshold", "allowlist", "known", "entropy", "source", "baseline", "length"],
        hints=[
            "Long labels can be legitimate for CDNs, tracking, and cloud services.",
            "Rate and repetition matter for tunneling/DGA behavior.",
            "Use allowlists and track behavior by source."
        ],
        explanation="Long DNS labels alone can be noisy. Add thresholds, source tracking, known-domain allowlists, entropy/label logic, and environmental baselining."
    ),
    Question(
        id="op011", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (http.uri; content:"/"; sid:200011; rev:1;)',
        prompt="Why is matching / in every URI useless, and what should rule logic contain instead?",
        answer_points=["matches nearly everything", "specific path", "method", "host", "behavior"],
        required_terms=[],
        accepted_terms=["everything", "specific", "path", "method", "host", "behavior"],
        hints=[
            "Almost all HTTP URIs contain a slash.",
            "A detection rule needs a meaningful condition.",
            "Use a specific path, parameter, method, host, or behavior."
        ],
        explanation="A slash appears in nearly every URI, so this is effectively meaningless. Use specific paths, suspicious parameters, method constraints, host constraints, or behavioral logic."
    ),
    Question(
        id="op012", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (http.cookie; content:"session"; sid:200012; rev:1;)',
        prompt="How would you make this cookie rule useful?",
        answer_points=["specific cookie name or value", "suspicious pattern", "host scope", "pcre"],
        required_terms=[],
        accepted_terms=["specific", "cookie", "value", "host", "pcre", "pattern"],
        hints=[
            "Many legitimate apps use session cookies.",
            "A useful rule needs a specific cookie name/value or suspicious format.",
            "Host scoping is often needed for app-specific cookies."
        ],
        explanation="Session is too generic. Make it useful by targeting a specific cookie name/value, suspicious pattern, vulnerable app behavior, or app-specific host."
    ),
    Question(
        id="op013", category="Optimization", mode="optimize", difficulty=3,
        rule='alert tcp any any -> any 3389 (sid:200013; rev:1;)',
        prompt="This alerts on all RDP destination traffic. How would you tune it for suspicious behavior?",
        answer_points=["threshold connections", "external to internal", "track by source", "failed auth not visible", "scope networks"],
        required_terms=[],
        accepted_terms=["threshold", "source", "external", "internal", "network", "rate", "3389"],
        hints=[
            "Destination port alone is not suspicious if RDP is expected.",
            "Direction and source/destination networks matter.",
            "Rate, repeated attempts, and unauthorized source ranges are better conditions."
        ],
        explanation="Tune RDP detection by scoping source/destination networks, tracking repeated attempts by source, alerting on unauthorized zones, or correlating with logs for auth failures."
    ),
    Question(
        id="op014", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (http.uri; content:"id="; sid:200014; rev:1;)',
        prompt="How would you improve this for possible SQL injection instead of normal IDs?",
        answer_points=["add sql keywords", "pcre", "uri parameter patterns", "nocase", "avoid id alone"],
        required_terms=[],
        accepted_terms=["select", "union", "or 1=1", "pcre", "nocase", "parameter", "sql"],
        hints=[
            "id= is common and normal.",
            "SQL injection detection needs suspicious operators or keywords.",
            "Look for patterns like union select, quotes, comments, or boolean logic."
        ],
        explanation="id= alone is normal. Add SQLi indicators such as union/select, quotes, comments, OR 1=1, encoded variants, and case-insensitive matching."
    ),
    Question(
        id="op015", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (content:"powershell"; sid:200015; rev:1;)',
        prompt="How would you tune this for malicious PowerShell over HTTP?",
        answer_points=["scope to uri or body", "encodedcommand", "download cradle", "nocase", "flow to_server"],
        required_terms=[],
        accepted_terms=["uri", "body", "encodedcommand", "-enc", "iex", "downloadstring", "nocase", "flow"],
        hints=[
            "PowerShell in a webpage response may be documentation or normal text.",
            "Malicious use often appears in URI parameters, POST body, or command strings.",
            "Look for -enc, IEX, DownloadString, or similar patterns."
        ],
        explanation="Scope to http.uri or http.request_body, add flow:to_server, use nocase, and look for stronger patterns like -enc, EncodedCommand, IEX, or DownloadString."
    ),
    Question(
        id="op016", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (http.host; content:"google"; sid:200016; rev:1;)',
        prompt="Why is this bad, and what kind of host match would be better?",
        answer_points=["too broad", "specific fqdn", "endswith", "exact hostname", "not generic brand"],
        required_terms=[],
        accepted_terms=["broad", "specific", "fqdn", "endswith", "exact", "hostname"],
        hints=[
            "google appears in many legitimate hostnames and services.",
            "Use a specific FQDN or controlled suffix match.",
            "Generic brand strings are almost always noisy."
        ],
        explanation="Generic host content like google is too broad. Use a specific FQDN, exact hostname logic, or suffix match with careful scoping."
    ),
    Question(
        id="op017", category="Optimization", mode="optimize", difficulty=3,
        rule='alert http any any -> any any (pcre:"/admin|login|signin|wp-admin/i"; sid:200017; rev:1;)',
        prompt="This PCRE matches many auth/admin words anywhere. How should it be tightened?",
        answer_points=["scope to http.uri", "specific paths", "method", "host", "reduce alternation"],
        required_terms=[],
        accepted_terms=["http.uri", "specific", "path", "method", "host", "flow"],
        hints=[
            "PCRE without buffer scoping can be expensive and noisy.",
            "Admin/login words are normal on many sites.",
            "Scope to URI, host, and method; use specific paths."
        ],
        explanation="Scope the PCRE to http.uri, reduce broad alternation, add specific paths/hosts, and use method/flow context where appropriate."
    ),
    Question(
        id="op018", category="Optimization", mode="optimize", difficulty=3,
        rule='alert ip any any -> any any (sid:200018; rev:1;)',
        prompt="This rule has no detection logic. What makes a Suricata rule operationally useful?",
        answer_points=["specific condition", "content or protocol keyword", "metadata", "sid rev msg", "scoping"],
        required_terms=[],
        accepted_terms=["specific", "content", "protocol", "flow", "metadata", "msg", "sid", "rev"],
        hints=[
            "A rule should not alert just because traffic exists.",
            "It needs a condition that describes suspicious behavior.",
            "Good rules include message, SID, revision, protocol/buffer scoping, and operational context."
        ],
        explanation="A useful rule needs meaningful match conditions, protocol/buffer scoping, SID/rev/msg, and enough context to reduce false positives."
    ),
]

WRITING = [
    Question(
        id="wr001", category="Writing", mode="write", difficulty=1,
        rule="(build full rule)",
        prompt="Write a rule that alerts on HTTP POST requests to a login endpoint.",
        answer_points=["alert http", "http.method", "POST", "http.uri", "/login", "sid"],
        required_terms=["alert", "http", "sid", "http.method", "post", "http.uri", "/login"],
        accepted_terms=[],
        hints=[
            "Use alert http and include a SID.",
            "Scope POST to http.method.",
            "Scope /login to http.uri."
        ],
        explanation='Example: alert http any any -> any any (msg:"HTTP POST to login endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/login"; sid:300001; rev:1;)'
    ),
    Question(
        id="wr002", category="Writing", mode="write", difficulty=1,
        rule="(build full rule)",
        prompt="Write a rule that alerts on a DNS query for bad-domain.com.",
        answer_points=["alert dns", "dns.query", "bad-domain.com", "sid"],
        required_terms=["alert", "dns", "sid", "dns.query", "bad-domain.com"],
        accepted_terms=[],
        hints=[
            "Use alert dns.",
            "Use dns.query to inspect the queried domain.",
            "Match bad-domain.com with content."
        ],
        explanation='Example: alert dns any any -> any any (msg:"DNS query for bad-domain.com"; dns.query; content:"bad-domain.com"; sid:300002; rev:1;)'
    ),
    Question(
        id="wr003", category="Writing", mode="write", difficulty=1,
        rule="(build full rule)",
        prompt="Write a rule that alerts on TLS SNI for evil.example.",
        answer_points=["alert tls", "tls.sni", "evil.example", "sid"],
        required_terms=["alert", "tls", "sid", "tls.sni", "evil.example"],
        accepted_terms=[],
        hints=[
            "Use alert tls.",
            "SNI is inspected with tls.sni.",
            "Match the hostname evil.example."
        ],
        explanation='Example: alert tls any any -> any any (msg:"TLS SNI evil.example"; tls.sni; content:"evil.example"; sid:300003; rev:1;)'
    ),
    Question(
        id="wr004", category="Writing", mode="write", difficulty=1,
        rule="(build full rule)",
        prompt="Write a rule that alerts on curl in the HTTP User-Agent, case-insensitive.",
        answer_points=["alert http", "http.user_agent", "curl", "nocase", "sid"],
        required_terms=["alert", "http", "sid", "http.user_agent", "curl", "nocase"],
        accepted_terms=[],
        hints=[
            "Use http.user_agent.",
            "Use content:\"curl\".",
            "Add nocase so Curl/CURL/curl all match."
        ],
        explanation='Example: alert http any any -> any any (msg:"curl user agent"; flow:established,to_server; http.user_agent; content:"curl"; nocase; sid:300004; rev:1;)'
    ),
    Question(
        id="wr005", category="Writing", mode="write", difficulty=1,
        rule="(build full rule)",
        prompt="Write a rule that alerts on TCP SYN packets.",
        answer_points=["alert tcp", "flags:S", "sid"],
        required_terms=["alert", "tcp", "sid", "flags:s"],
        accepted_terms=[],
        hints=[
            "Use alert tcp.",
            "TCP SYN is flags:S.",
            "Include sid and rev."
        ],
        explanation='Example: alert tcp any any -> any any (msg:"TCP SYN observed"; flags:S; sid:300005; rev:1;)'
    ),
    Question(
        id="wr006", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts when /wp-admin/ appears in the HTTP URI.",
        answer_points=["alert http", "http.uri", "/wp-admin/", "sid"],
        required_terms=["alert", "http", "sid", "http.uri", "/wp-admin"],
        accepted_terms=[],
        hints=[
            "This belongs in the URI buffer.",
            "Use content:\"/wp-admin\" after http.uri.",
            "Use flow:established,to_server if you want request direction."
        ],
        explanation='Example: alert http any any -> any any (msg:"WordPress admin access"; flow:established,to_server; http.uri; content:"/wp-admin/"; sid:300006; rev:1;)'
    ),
    Question(
        id="wr007", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts on HTTP requests containing cmd.exe in the URI, case-insensitive.",
        answer_points=["alert http", "http.uri", "cmd.exe", "nocase", "sid"],
        required_terms=["alert", "http", "sid", "http.uri", "cmd.exe", "nocase"],
        accepted_terms=[],
        hints=[
            "Use http.uri to avoid scanning the whole payload.",
            "Use content:\"cmd.exe\".",
            "Use nocase."
        ],
        explanation='Example: alert http any any -> any any (msg:"cmd.exe in URI"; flow:established,to_server; http.uri; content:"cmd.exe"; nocase; sid:300007; rev:1;)'
    ),
    Question(
        id="wr008", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts on DNS queries ending in .ru.",
        answer_points=["alert dns", "dns.query", ".ru", "endswith", "sid"],
        required_terms=["alert", "dns", "sid", "dns.query", ".ru", "endswith"],
        accepted_terms=[],
        hints=[
            "Use dns.query.",
            "Use content:\".ru\".",
            "Use endswith to make it a suffix match."
        ],
        explanation='Example: alert dns any any -> any any (msg:"DNS query ending in .ru"; dns.query; content:".ru"; endswith; sid:300008; rev:1;)'
    ),
    Question(
        id="wr009", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts on HTTP request bodies containing password=.",
        answer_points=["alert http", "http.request_body", "password=", "sid"],
        required_terms=["alert", "http", "sid", "http.request_body", "password="],
        accepted_terms=[],
        hints=[
            "Use the request body buffer.",
            "The content should be password=.",
            "Add flow:established,to_server for client requests."
        ],
        explanation='Example: alert http any any -> any any (msg:"password field in request body"; flow:established,to_server; http.request_body; content:"password="; sid:300009; rev:1;)'
    ),
    Question(
        id="wr010", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts on SSH banner text SSH- on TCP port 22.",
        answer_points=["alert tcp", "any 22", "content:\"SSH-\"", "sid"],
        required_terms=["alert", "tcp", "sid", "22", "ssh-"],
        accepted_terms=[],
        hints=[
            "Use tcp and destination port 22.",
            "SSH banners start with SSH-.",
            "Use content:\"SSH-\"."
        ],
        explanation='Example: alert tcp any any -> any 22 (msg:"SSH banner observed"; flow:established,to_server; content:"SSH-"; sid:300010; rev:1;)'
    ),
    Question(
        id="wr011", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts on HTTP Host header evil.com.",
        answer_points=["alert http", "http.host", "evil.com", "sid"],
        required_terms=["alert", "http", "sid", "http.host", "evil.com"],
        accepted_terms=[],
        hints=[
            "Use http.host for the Host header.",
            "Match evil.com.",
            "Do not use tls.sni for an HTTP Host header question."
        ],
        explanation='Example: alert http any any -> any any (msg:"HTTP Host evil.com"; http.host; content:"evil.com"; sid:300011; rev:1;)'
    ),
    Question(
        id="wr012", category="Writing", mode="write", difficulty=2,
        rule="(build full rule)",
        prompt="Write a rule that alerts on packets with payload/data size greater than 1200 bytes.",
        answer_points=["alert ip", "dsize:>1200", "sid"],
        required_terms=["alert", "ip", "sid", "dsize:>1200"],
        accepted_terms=[],
        hints=[
            "Use alert ip for general IP packet matching.",
            "Use dsize for packet data size.",
            "The operator is greater-than: dsize:>1200."
        ],
        explanation='Example: alert ip any any -> any any (msg:"Large packet data size"; dsize:>1200; sid:300012; rev:1;)'
    ),
    Question(
        id="wr013", category="Writing", mode="write", difficulty=3,
        rule="(build full rule)",
        prompt="Write a tuned rule for possible command execution: HTTP URI contains powershell, case-insensitive, client-to-server only.",
        answer_points=["alert http", "flow:established,to_server", "http.uri", "powershell", "nocase", "sid"],
        required_terms=["alert", "http", "sid", "flow:established,to_server", "http.uri", "powershell", "nocase"],
        accepted_terms=[],
        hints=[
            "Use flow:established,to_server.",
            "Scope the match to http.uri.",
            "Use nocase for PowerShell variants."
        ],
        explanation='Example: alert http any any -> any any (msg:"PowerShell in HTTP URI"; flow:established,to_server; http.uri; content:"powershell"; nocase; sid:300013; rev:1;)'
    ),
    Question(
        id="wr014", category="Writing", mode="write", difficulty=3,
        rule="(build full rule)",
        prompt="Write a rule for possible SQL injection where the URI contains union and select, case-insensitive.",
        answer_points=["alert http", "http.uri", "union", "select", "nocase", "sid"],
        required_terms=["alert", "http", "sid", "http.uri", "union", "select", "nocase"],
        accepted_terms=[],
        hints=[
            "Use the URI buffer.",
            "Use two content matches: union and select.",
            "Use nocase on both content matches."
        ],
        explanation='Example: alert http any any -> any any (msg:"Possible SQLi union select in URI"; flow:established,to_server; http.uri; content:"union"; nocase; content:"select"; nocase; sid:300014; rev:1;)'
    ),
    Question(
        id="wr015", category="Writing", mode="write", difficulty=3,
        rule="(build full rule)",
        prompt="Write a rule that alerts on X-Api-Key appearing in HTTP headers, case-insensitive.",
        answer_points=["alert http", "http.header", "x-api-key", "nocase", "sid"],
        required_terms=["alert", "http", "sid", "http.header", "x-api-key", "nocase"],
        accepted_terms=[],
        hints=[
            "Use http.header.",
            "The content is X-Api-Key.",
            "Use nocase."
        ],
        explanation='Example: alert http any any -> any any (msg:"X-Api-Key header observed"; http.header; content:"X-Api-Key"; nocase; sid:300015; rev:1;)'
    ),
    Question(
        id="wr016", category="Writing", mode="write", difficulty=3,
        rule="(build full rule)",
        prompt="Write a rule using detection_filter to alert when one source sends more than 20 SYNs in 60 seconds.",
        answer_points=["alert tcp", "flags:S", "detection_filter", "track by_src", "count 20", "seconds 60", "sid"],
        required_terms=["alert", "tcp", "sid", "flags:s", "detection_filter", "track by_src", "count 20", "seconds 60"],
        accepted_terms=[],
        hints=[
            "Use flags:S for SYN.",
            "Use detection_filter for rate logic.",
            "Track by_src with count 20 and seconds 60."
        ],
        explanation='Example: alert tcp any any -> any any (msg:"Possible SYN scan"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:300016; rev:1;)'
    ),
    Question(
        id="wr017", category="Writing", mode="write", difficulty=3,
        rule="(build full rule)",
        prompt="Write a rule that alerts on HTTP URI starting with /download.",
        answer_points=["alert http", "http.uri", "/download", "startswith", "sid"],
        required_terms=["alert", "http", "sid", "http.uri", "/download", "startswith"],
        accepted_terms=[],
        hints=[
            "Use http.uri.",
            "Use content:\"/download\".",
            "Use startswith so the URI begins with that value."
        ],
        explanation='Example: alert http any any -> any any (msg:"URI starts with /download"; http.uri; content:"/download"; startswith; sid:300017; rev:1;)'
    ),
    Question(
        id="wr018", category="Writing", mode="write", difficulty=3,
        rule="(build full rule)",
        prompt="Write a rule that alerts on an HTTP cookie containing suspicious_session=.",
        answer_points=["alert http", "http.cookie", "suspicious_session=", "sid"],
        required_terms=["alert", "http", "sid", "http.cookie", "suspicious_session="],
        accepted_terms=[],
        hints=[
            "Use http.cookie.",
            "Match suspicious_session=.",
            "Include sid and rev."
        ],
        explanation='Example: alert http any any -> any any (msg:"Suspicious session cookie"; http.cookie; content:"suspicious_session="; sid:300018; rev:1;)'
    ),
]


REPAIR = [
    Question(
        id="rp001", category="Rule Repair", mode="repair", difficulty=1,
        rule='alert http any any -> any any (content:"login"; sid:400001; rev:1;)',
        prompt="Repair this noisy login rule so it scopes /login to the HTTP URI and POST to the HTTP method.",
        answer_points=["http.uri", "/login", "http.method", "POST", "flow:established,to_server"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.uri", "/login", "http.method", "post"],
        accepted_terms=[],
        hints=[
            "Do not leave login as a raw unscoped content match.",
            "Use http.uri for /login.",
            "Use http.method with content:\"POST\"."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"HTTP POST to login endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/login"; sid:400001; rev:2;)',
        skills=["repair", "http_buffers", "content_matching", "tuning", "rule_structure"]
    ),
    Question(
        id="rp002", category="Rule Repair", mode="repair", difficulty=1,
        rule='alert dns any any -> any any (content:"evil.com"; sid:400002; rev:1;)',
        prompt="Repair this DNS rule so the domain match is scoped to the DNS query buffer.",
        answer_points=["dns.query", "evil.com"],
        required_terms=["alert", "dns", "sid", "rev", "msg", "dns.query", "evil.com"],
        accepted_terms=[],
        hints=[
            "Raw content can match outside the specific DNS query name.",
            "Use dns.query before matching the domain.",
            "Keep the content match for evil.com."
        ],
        explanation='Better rule: alert dns any any -> any any (msg:"DNS query for evil.com"; dns.query; content:"evil.com"; sid:400002; rev:2;)',
        skills=["repair", "dns", "content_matching", "rule_structure"]
    ),
    Question(
        id="rp003", category="Rule Repair", mode="repair", difficulty=1,
        rule='alert tls any any -> any any (http.host; content:"bad.example"; sid:400003; rev:1;)',
        prompt="Repair this rule. It is supposed to detect TLS SNI bad.example, not HTTP Host.",
        answer_points=["tls.sni", "bad.example"],
        required_terms=["alert", "tls", "sid", "rev", "msg", "tls.sni", "bad.example"],
        accepted_terms=[],
        hints=[
            "HTTP Host and TLS SNI are different fields.",
            "For TLS hostname in the handshake, use tls.sni.",
            "Keep the protocol as tls."
        ],
        explanation='Better rule: alert tls any any -> any any (msg:"TLS SNI bad.example"; tls.sni; content:"bad.example"; sid:400003; rev:2;)',
        skills=["repair", "tls", "content_matching", "rule_structure"]
    ),
    Question(
        id="rp004", category="Rule Repair", mode="repair", difficulty=1,
        rule='alert tcp any any any any (flags:S; sid:400004; rev:1;)',
        prompt="Repair the structure error in this TCP SYN rule.",
        answer_points=["->", "flags:S"],
        required_terms=["alert", "tcp", "->", "sid", "rev", "msg", "flags:s"],
        accepted_terms=[],
        hints=[
            "Suricata rules need a direction operator.",
            "The direction operator is ->.",
            "Place it between source and destination fields."
        ],
        explanation='Better rule: alert tcp any any -> any any (msg:"TCP SYN observed"; flags:S; sid:400004; rev:2;)',
        skills=["repair", "tcp_flow", "rule_structure"]
    ),
    Question(
        id="rp005", category="Rule Repair", mode="repair", difficulty=2,
        rule='alert http any any -> any any (http.user_agent; content:"curl"; sid:400005; rev:1;)',
        prompt="Repair this User-Agent rule so it catches curl regardless of case and only client-to-server traffic.",
        answer_points=["http.user_agent", "curl", "nocase", "flow:established,to_server"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.user_agent", "curl", "nocase", "flow:established,to_server"],
        accepted_terms=[],
        hints=[
            "curl may appear as Curl, CURL, or curl.",
            "Use nocase.",
            "Use flow:established,to_server for request direction."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"curl User-Agent"; flow:established,to_server; http.user_agent; content:"curl"; nocase; sid:400005; rev:2;)',
        skills=["repair", "http_buffers", "tcp_flow", "content_matching", "rule_structure"]
    ),
    Question(
        id="rp006", category="Rule Repair", mode="repair", difficulty=2,
        rule='alert http any any -> any any (content:"cmd.exe"; sid:400006; rev:1;)',
        prompt="Repair this possible command-execution rule so cmd.exe is scoped to the HTTP URI and case-insensitive.",
        answer_points=["http.uri", "cmd.exe", "nocase", "flow:established,to_server"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.uri", "cmd.exe", "nocase"],
        accepted_terms=[],
        hints=[
            "Raw content may match anywhere.",
            "Command execution attempts often place cmd.exe in URI parameters.",
            "Use http.uri and nocase."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"cmd.exe in HTTP URI"; flow:established,to_server; http.uri; content:"cmd.exe"; nocase; sid:400006; rev:2;)',
        skills=["repair", "http_buffers", "content_matching", "tuning", "rule_structure"]
    ),
    Question(
        id="rp007", category="Rule Repair", mode="repair", difficulty=2,
        rule='alert dns any any -> any any (dns.query; content:".ru"; sid:400007; rev:1;)',
        prompt="Repair this DNS suffix rule so it only alerts when the query ends with .ru.",
        answer_points=["dns.query", ".ru", "endswith"],
        required_terms=["alert", "dns", "sid", "rev", "msg", "dns.query", ".ru", "endswith"],
        accepted_terms=[],
        hints=[
            "Without suffix logic, .ru could match anywhere in the query.",
            "Use endswith.",
            "Keep dns.query scoped."
        ],
        explanation='Better rule: alert dns any any -> any any (msg:"DNS query ending in .ru"; dns.query; content:".ru"; endswith; sid:400007; rev:2;)',
        skills=["repair", "dns", "content_matching", "tuning", "rule_structure"]
    ),
    Question(
        id="rp008", category="Rule Repair", mode="repair", difficulty=2,
        rule='alert http any any -> any any (http.uri; content:"admin"; sid:400008; rev:1;)',
        prompt="Repair this admin rule so it is less noisy and looks for an admin path.",
        answer_points=["http.uri", "/admin", "flow:established,to_server"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.uri", "/admin"],
        accepted_terms=[],
        hints=[
            "admin without a slash may match too broadly.",
            "Admin access normally appears as a path.",
            "Use /admin or a more specific admin path."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"HTTP admin path access"; flow:established,to_server; http.uri; content:"/admin"; sid:400008; rev:2;)',
        skills=["repair", "http_buffers", "content_matching", "tuning", "rule_structure"]
    ),
    Question(
        id="rp009", category="Rule Repair", mode="repair", difficulty=2,
        rule='alert ip any any -> any any (dsize:>100; sid:400009; rev:1;)',
        prompt="Repair this weak large-packet rule so it is more operationally useful for unusually large packet payloads.",
        answer_points=["dsize:>1200", "msg", "sid", "rev"],
        required_terms=["alert", "ip", "sid", "rev", "msg", "dsize:>1200"],
        accepted_terms=[],
        hints=[
            "dsize:>100 is too low for most environments.",
            "Use a more meaningful threshold like >1200 for this drill.",
            "Make sure the rule has msg, sid, and rev."
        ],
        explanation='Better rule: alert ip any any -> any any (msg:"Unusually large packet payload"; dsize:>1200; sid:400009; rev:2;)',
        skills=["repair", "tuning", "rule_structure"]
    ),
    Question(
        id="rp010", category="Rule Repair", mode="repair", difficulty=2,
        rule='alert http any any -> any any (http.header; content:"X-Api-Key"; sid:400010; rev:1;)',
        prompt="Repair this header rule so the header name match is case-insensitive.",
        answer_points=["http.header", "X-Api-Key", "nocase"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.header", "x-api-key", "nocase"],
        accepted_terms=[],
        hints=[
            "Header capitalization can vary.",
            "Use nocase.",
            "Keep the match scoped to http.header."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"X-Api-Key header observed"; http.header; content:"X-Api-Key"; nocase; sid:400010; rev:2;)',
        skills=["repair", "http_buffers", "content_matching", "rule_structure"]
    ),
    Question(
        id="rp011", category="Rule Repair", mode="repair", difficulty=3,
        rule='alert tcp any any -> any any (flags:S; sid:400011; rev:1;)',
        prompt="Repair this SYN rule so it alerts only after more than 20 SYNs from the same source in 60 seconds.",
        answer_points=["detection_filter", "track by_src", "count 20", "seconds 60"],
        required_terms=["alert", "tcp", "sid", "rev", "msg", "flags:s", "detection_filter", "track by_src", "count 20", "seconds 60"],
        accepted_terms=[],
        hints=[
            "A single SYN is normal.",
            "Use detection_filter for rate-based alerting.",
            "Track by source with count 20 and seconds 60."
        ],
        explanation='Better rule: alert tcp any any -> any any (msg:"Possible SYN scan"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:400011; rev:2;)',
        skills=["repair", "tcp_flow", "thresholding", "tuning", "rule_structure"]
    ),
    Question(
        id="rp012", category="Rule Repair", mode="repair", difficulty=3,
        rule='alert http any any -> any any (pcre:"/admin|login|signin|wp-admin/i"; sid:400012; rev:1;)',
        prompt="Repair this broad PCRE rule by scoping it to HTTP URI and making the match more specific to wp-admin PHP access.",
        answer_points=["http.uri", "pcre", "wp-admin", "php"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.uri", "pcre", "wp-admin", "php"],
        accepted_terms=[],
        hints=[
            "Do not run a broad PCRE against everything if you can scope it.",
            "Use http.uri before the PCRE.",
            "Make the pattern target wp-admin PHP paths."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"Possible wp-admin PHP access"; flow:established,to_server; http.uri; pcre:"/\\\\/wp-admin\\\\/.*\\\\.php/i"; sid:400012; rev:2;)',
        skills=["repair", "http_buffers", "regex", "tuning", "rule_structure"]
    ),
    Question(
        id="rp013", category="Rule Repair", mode="repair", difficulty=3,
        rule='alert http any any -> any any (http.uri; content:"id="; sid:400013; rev:1;)',
        prompt="Repair this weak id= rule so it looks more like SQL injection using union and select in the URI.",
        answer_points=["http.uri", "union", "select", "nocase"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.uri", "union", "select", "nocase"],
        accepted_terms=[],
        hints=[
            "id= alone is normal.",
            "Add SQLi terms like union and select.",
            "Use nocase."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"Possible SQLi union select in URI"; flow:established,to_server; http.uri; content:"union"; nocase; content:"select"; nocase; sid:400013; rev:2;)',
        skills=["repair", "http_buffers", "content_matching", "tuning", "rule_structure"]
    ),
    Question(
        id="rp014", category="Rule Repair", mode="repair", difficulty=3,
        rule='alert http any any -> any any (content:"powershell"; sid:400014; rev:1;)',
        prompt="Repair this PowerShell rule so it looks for PowerShell in the HTTP URI, case-insensitive, client-to-server.",
        answer_points=["flow:established,to_server", "http.uri", "powershell", "nocase"],
        required_terms=["alert", "http", "sid", "rev", "msg", "flow:established,to_server", "http.uri", "powershell", "nocase"],
        accepted_terms=[],
        hints=[
            "Scope to client-to-server requests.",
            "Use http.uri.",
            "Use nocase for PowerShell variants."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"PowerShell in HTTP URI"; flow:established,to_server; http.uri; content:"powershell"; nocase; sid:400014; rev:2;)',
        skills=["repair", "http_buffers", "tcp_flow", "content_matching", "tuning", "rule_structure"]
    ),
    Question(
        id="rp015", category="Rule Repair", mode="repair", difficulty=3,
        rule='alert http any any -> any any (http.host; content:"google"; sid:400015; rev:1;)',
        prompt="Repair this overly broad Host rule so it matches a specific suspicious FQDN instead.",
        answer_points=["http.host", "evil-google-login.example", "specific"],
        required_terms=["alert", "http", "sid", "rev", "msg", "http.host", "evil-google-login.example"],
        accepted_terms=[],
        hints=[
            "google is too broad.",
            "Use a specific suspicious hostname for this drill.",
            "Keep the match in http.host."
        ],
        explanation='Better rule: alert http any any -> any any (msg:"Suspicious HTTP Host"; http.host; content:"evil-google-login.example"; sid:400015; rev:2;)',
        skills=["repair", "http_buffers", "content_matching", "tuning", "rule_structure"]
    ),
]

ALL_QUESTIONS = VARIABLES_AND_STRUCTURE + RULE_READING + OPTIMIZATION + WRITING + REPAIR

SKILL_DEFINITIONS = {
    "rule_structure": "Basic rule structure: action, protocol, direction, options, sid/rev/msg",
    "http_buffers": "HTTP buffer scoping: http.uri, http.method, http.host, headers, body",
    "dns": "DNS inspection: dns.query and domain matching",
    "tls": "TLS inspection: tls.sni and handshake hostname concepts",
    "tcp_flow": "TCP/session logic: flow, established, to_server, TCP flags",
    "content_matching": "Content matching: content, nocase, startswith, endswith",
    "tuning": "False-positive reduction and rule optimization",
    "thresholding": "Rate limiting and detection_filter/threshold logic",
    "regex": "PCRE and pattern matching",
    "writing": "Writing valid Suricata rules",
    "repair": "Finding and fixing broken or weak rules",
}

def infer_skills(q: Question) -> List[str]:
    txt = " ".join([
        q.category, q.mode, q.prompt, q.rule, q.explanation,
        " ".join(q.required_terms), " ".join(q.answer_points)
    ]).lower()

    skills = set()

    if q.mode == "write":
        skills.add("writing")
        skills.add("rule_structure")
    if q.mode == "optimize":
        skills.add("tuning")
    if q.mode == "repair":
        skills.add("repair")
        skills.add("rule_structure")

    if any(x in txt for x in ["http.", "http ", "uri", "user_agent", "host header", "request_body", "cookie"]):
        skills.add("http_buffers")
    if "dns" in txt or "dns.query" in txt:
        skills.add("dns")
    if "tls" in txt or "sni" in txt:
        skills.add("tls")
    if any(x in txt for x in ["flow", "established", "to_server", "flags", "syn", "tcp"]):
        skills.add("tcp_flow")
    if any(x in txt for x in ["content", "nocase", "startswith", "endswith"]):
        skills.add("content_matching")
    if any(x in txt for x in ["threshold", "detection_filter", "rate", "track by_src"]):
        skills.add("thresholding")
    if "pcre" in txt or "regex" in txt:
        skills.add("regex")
    if any(x in txt for x in ["false positive", "noisy", "tune", "optimize", "reduce"]):
        skills.add("tuning")

    if not skills:
        skills.add("rule_structure")

    return sorted(skills)

# Attach skill tags to existing questions without rewriting every question object.
for _q in ALL_QUESTIONS:
    if not _q.skills:
        _q.skills = infer_skills(_q)

# Beginner-safe adaptive controls.
# The trainer starts with foundational concepts and unlocks harder questions gradually.
ADVANCED_TERMS = [
    "byte_test", "byte_jump", "dword", "isdataat", "within", "distance",
    "offset", "depth", "pcre", "flowbits", "xbits", "file_data",
    "base64_decode", "ja3", "dataset", "lua", "iprep"
]

FOUNDATION_TERMS = [
    "http.method", "http.uri", "http.user_agent", "http.host",
    "dns.query", "tls.sni", "flow", "flags", "sid", "rev", "msg",
    "content", "nocase"
]

def question_text(q: Question) -> str:
    return " ".join([q.prompt, q.rule, q.explanation, " ".join(q.required_terms), " ".join(q.answer_points)]).lower()

def is_advanced_question(q: Question) -> bool:
    txt = question_text(q)
    return q.difficulty >= 3 or any(term in txt for term in ADVANCED_TERMS)

def is_foundation_question(q: Question) -> bool:
    txt = question_text(q)
    return q.difficulty == 1 or any(term in txt for term in FOUNDATION_TERMS)

def learner_level(progress: Dict, bank: Optional[List[Question]] = None) -> str:
    qs = progress.get("questions", {})
    ids = {q.id for q in bank} if bank else None

    seen = correct = 0
    mastered = 0
    for qid, st in qs.items():
        if ids is not None and qid not in ids:
            continue
        seen += st.get("seen", 0)
        correct += st.get("correct", 0)
        if st.get("mastery", 0) >= 5:
            mastered += 1

    accuracy = (correct / seen) if seen else 0

    skill_values = [v.get("mastery", 0) for v in progress.get("skills", {}).values()]
    avg_skill_mastery = (sum(skill_values) / len(skill_values)) if skill_values else 0

    if seen < 8:
        return "BEGINNER"
    if accuracy < 0.70 or mastered < 4 or avg_skill_mastery < 1.5:
        return "BEGINNER"
    if seen < 20 or accuracy < 0.85 or mastered < 10 or avg_skill_mastery < 3.0:
        return "INTERMEDIATE"
    return "ADVANCED"

def explain_selection_reason(q: Question, progress: Dict, bank: List[Question]) -> str:
    level = learner_level(progress, bank)
    st = qstats(progress, q.id)
    if st.get("seen", 0) == 0:
        return f"{level} path: new concept"
    if st.get("mastery", 0) <= 2:
        return f"{level} path: review weak area"
    if st.get("wrong", 0) > 0:
        return f"{level} path: retry previously missed concept"
    return f"{level} path: reinforce mastered concept"

# ============================================================
# PROGRESS / ADAPTIVE ENGINE
# ============================================================

def load_progress() -> Dict:
    if not os.path.exists(PROGRESS_FILE):
        return {"questions": {}, "sessions": []}
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"questions": {}, "sessions": []}

def save_progress(progress: Dict):
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(progress, f, indent=2)

def global_stats(progress: Dict) -> Dict:
    qs = progress.get("questions", {})
    seen = sum(v.get("seen", 0) for v in qs.values())
    correct = sum(v.get("correct", 0) for v in qs.values())
    wrong = sum(v.get("wrong", 0) for v in qs.values())
    mastered = sum(1 for v in qs.values() if v.get("mastery", 0) >= 5)
    return {
        "seen": seen,
        "correct": correct,
        "wrong": wrong,
        "mastered": mastered,
        "accuracy": round((correct / seen) * 100, 1) if seen else 0.0
    }

def category_stats(progress: Dict, bank: List[Question]) -> Dict:
    ids = {q.id for q in bank}
    qs = progress.get("questions", {})
    seen = sum(v.get("seen", 0) for k, v in qs.items() if k in ids)
    correct = sum(v.get("correct", 0) for k, v in qs.items() if k in ids)
    wrong = sum(v.get("wrong", 0) for k, v in qs.items() if k in ids)
    mastered = sum(1 for k, v in qs.items() if k in ids and v.get("mastery", 0) >= 5)
    return {
        "seen": seen,
        "correct": correct,
        "wrong": wrong,
        "mastered": mastered,
        "total": len(ids),
        "accuracy": round((correct / seen) * 100, 1) if seen else 0.0
    }

def qstats(progress: Dict, qid: str) -> Dict:
    return progress.setdefault("questions", {}).setdefault(qid, {
        "seen": 0,
        "correct": 0,
        "wrong": 0,
        "hints_used": 0,
        "mastery": 0,
        "last_seen": None
    })

def skill_stats(progress: Dict, skill: str) -> Dict:
    return progress.setdefault("skills", {}).setdefault(skill, {
        "seen": 0,
        "correct": 0,
        "wrong": 0,
        "hints_used": 0,
        "mastery": 0
    })

def update_skill_stats(progress: Dict, q: Question, ok: bool, hints_used: int):
    for skill in q.skills:
        st = skill_stats(progress, skill)
        st["seen"] += 1
        st["correct"] += int(ok)
        st["wrong"] += int(not ok)
        st["hints_used"] += hints_used

        if ok and hints_used == 0:
            st["mastery"] = min(5, st["mastery"] + 1)
        elif ok:
            st["mastery"] = min(5, st["mastery"] + 0.5)
        else:
            st["mastery"] = max(0, st["mastery"] - 0.5)

def update_stats(progress: Dict, q: Question, ok: bool, hints_used: int):
    s = qstats(progress, q.id)
    s["seen"] += 1
    s["correct"] += int(ok)
    s["wrong"] += int(not ok)
    s["hints_used"] += hints_used
    s["last_seen"] = datetime.now().isoformat(timespec="seconds")

    # Adaptive question mastery:
    # Correct with no hints = strongest.
    # Correct with hints = smaller gain.
    # Wrong = drops.
    if ok and hints_used == 0:
        s["mastery"] = min(5, s["mastery"] + 2)
    elif ok:
        s["mastery"] = min(5, s["mastery"] + 1)
    else:
        s["mastery"] = max(0, s["mastery"] - 1)

    update_skill_stats(progress, q, ok, hints_used)

def pick_questions(bank: List[Question], count: Optional[int], adaptive: bool, progress: Dict) -> List[Question]:
    pool = list(bank)

    if not adaptive:
        random.shuffle(pool)
        return pool if count is None else pool[:count]

    level = learner_level(progress, bank)

    # Gate questions by learner level.
    # BEGINNER: mostly difficulty 1 and foundational difficulty 2. Avoid advanced/regex-heavy logic.
    # INTERMEDIATE: difficulty 1-2, with a small amount of difficulty 3 review.
    # ADVANCED: full bank.
    if level == "BEGINNER":
        gated = [q for q in pool if q.difficulty == 1 and q.mode in ["read", "write"]]
        if len(gated) >= max(5, count or 5):
            pool = gated
    elif level == "INTERMEDIATE":
        gated = [q for q in pool if q.difficulty <= 2 or (q.difficulty == 3 and not any(t in question_text(q) for t in ADVANCED_TERMS))]
        if len(gated) >= max(5, count or 5):
            pool = gated
    # ADVANCED uses full pool.

    def weight(q: Question) -> float:
        st = qstats(progress, q.id)

        unseen_boost = 12 if st["seen"] == 0 else 0
        weak_boost = max(0, 5 - st["mastery"]) * 3
        wrong_boost = st["wrong"] * 2.5
        hint_boost = st["hints_used"] * 0.5

        # Level-specific difficulty preference.
        if level == "BEGINNER":
            difficulty_fit = {1: 5, 2: 2, 3: -8}.get(q.difficulty, 0)
            advanced_penalty = -20 if is_advanced_question(q) else 0
        elif level == "INTERMEDIATE":
            difficulty_fit = {1: 2, 2: 5, 3: 1}.get(q.difficulty, 0)
            advanced_penalty = -6 if any(t in question_text(q) for t in ADVANCED_TERMS) else 0
        else:
            difficulty_fit = {1: 1, 2: 3, 3: 5}.get(q.difficulty, 0)
            advanced_penalty = 0

        return unseen_boost + weak_boost + wrong_boost + hint_boost + difficulty_fit + advanced_penalty + random.random()

    pool.sort(key=weight, reverse=True)
    selected = pool if count is None else pool[:count]
    random.shuffle(selected)
    return selected


# ============================================================
# VALIDATION
# ============================================================

def validate_rule_structure(ans: str) -> List[str]:
    a = norm(ans)
    issues = []

    if not a.startswith("alert "):
        issues.append("Rule should start with alert.")
    if "->" not in a:
        issues.append("Missing traffic direction operator ->.")
    if "(" not in ans or ")" not in ans:
        issues.append("Missing rule option parentheses (...).")
    if not re.search(r"\bsid\s*:\s*\d+\s*;", a):
        issues.append("Missing numeric sid:<number>; option.")
    if not re.search(r"\brev\s*:\s*\d+\s*;", a):
        issues.append("Missing rev:<number>; option.")
    if "msg:" not in a:
        issues.append("Missing msg:\"...\" option. Not always required by Suricata, but required for this trainer.")
    if not any(re.search(rf"\b{p}\b", a) for p in ["http", "tcp", "udp", "dns", "tls", "ip", "icmp"]):
        issues.append("Missing or unsupported protocol.")
    if a.count("(") != a.count(")"):
        issues.append("Unbalanced parentheses.")
    if '"' in ans and ans.count('"') % 2 != 0:
        issues.append("Unbalanced double quotes.")
    if not a.endswith(")"):
        issues.append("Rule should end with a closing parenthesis. Example: rev:1;)")
    return issues

def term_present(ans_norm: str, term: str) -> bool:
    t = term.lower().strip()

    # Normalize common spaces in options for checking.
    compact_ans = ans_norm.replace(" ", "")
    compact_t = t.replace(" ", "")

    if t == "->":
        return "->" in ans_norm

    if compact_t in compact_ans:
        return True

    # Flexible matching for quoted content.
    if t.startswith("content:"):
        return compact_t in compact_ans

    return t in ans_norm

def score_read_or_optimize(ans: str, q: Question) -> Tuple[bool, List[str]]:
    a = norm(ans)
    ans_tokens = tokens(ans)
    missing = []

    # For reading/optimization, require conceptual coverage without being too brittle.
    required_hit = True
    for term in q.required_terms:
        if term.lower() not in a and term.lower() not in ans_tokens:
            required_hit = False
            missing.append(f"Expected concept: {term}")

    point_hits = 0
    for point in q.answer_points:
        if len(tokens(point) & ans_tokens) >= 1 or norm(point) in a:
            point_hits += 1

    accepted_hit = any(t.lower() in a for t in q.accepted_terms)
    ok = required_hit and (point_hits >= 1 or accepted_hit)

    if not ok and not missing:
        missing.append("Your answer missed the main detection concept. Use 'hint' if you want a targeted clue.")
    return ok, missing

def score_write(ans: str, q: Question) -> Tuple[bool, List[str]]:
    a = norm(ans)
    issues = validate_rule_structure(ans)

    for term in q.required_terms:
        if not term_present(a, term):
            issues.append(f"Missing required element: {term}")

    # Catch common buffer mistakes.
    if "tls.sni" in q.required_terms and "http.host" in a:
        issues.append("Used http.host, but this question requires TLS SNI.")
    if "http.host" in q.required_terms and "tls.sni" in a:
        issues.append("Used tls.sni, but this question requires HTTP Host header.")
    if "http.uri" in q.required_terms and "http.uri" not in a:
        issues.append("Content should be scoped to http.uri for this question.")
    if "http.request_body" in q.required_terms and "http.request_body" not in a:
        issues.append("Content should be scoped to http.request_body for this question.")

    return len(issues) == 0, issues

def score_answer(ans: str, q: Question) -> Tuple[bool, List[str]]:
    if q.mode in ["write", "repair"]:
        return score_write(ans, q)
    return score_read_or_optimize(ans, q)


# ============================================================
# GUIDED BUILD MODE
# ============================================================

GUIDED_BUILDS = [
    {
        "title": "Build HTTP URI Rule",
        "goal": "Detect external HTTP requests to /admin on protected hosts.",
        "protocol": "http",
        "src": "$EXTERNAL_NET",
        "dst": "$HOME_NET",
        "buffer": "http.uri",
        "content": "/admin",
        "why": "Use http.uri because /admin is a web path. Use $EXTERNAL_NET -> $HOME_NET because this is inbound traffic to protected assets.",
        "final": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"External HTTP request to admin path"; flow:established,to_server; http.uri; content:"/admin"; sid:510001; rev:1;)'
    },
    {
        "title": "Build DNS Query Rule",
        "goal": "Detect protected hosts querying bad-domain.com.",
        "protocol": "dns",
        "src": "$HOME_NET",
        "dst": "$EXTERNAL_NET",
        "buffer": "dns.query",
        "content": "bad-domain.com",
        "why": "Use dns.query because we care about the queried domain. Use $HOME_NET -> $EXTERNAL_NET because internal clients are making outbound DNS queries.",
        "final": 'alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Internal DNS query for bad-domain.com"; dns.query; content:"bad-domain.com"; sid:510002; rev:1;)'
    },
    {
        "title": "Build TLS SNI Rule",
        "goal": "Detect protected hosts making TLS connections to suspicious.example.",
        "protocol": "tls",
        "src": "$HOME_NET",
        "dst": "$EXTERNAL_NET",
        "buffer": "tls.sni",
        "content": "suspicious.example",
        "why": "Use tls.sni for the hostname visible in the TLS handshake. Use $HOME_NET -> $EXTERNAL_NET for outbound client connections.",
        "final": 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound TLS SNI suspicious.example"; tls.sni; content:"suspicious.example"; sid:510003; rev:1;)'
    },
    {
        "title": "Build User-Agent Rule",
        "goal": "Detect curl User-Agent from internal hosts going outbound.",
        "protocol": "http",
        "src": "$HOME_NET",
        "dst": "$EXTERNAL_NET",
        "buffer": "http.user_agent",
        "content": "curl",
        "why": "Use http.user_agent because curl appears in the User-Agent header. Add nocase because capitalization can vary.",
        "final": 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Internal curl User-Agent outbound"; flow:established,to_server; http.user_agent; content:"curl"; nocase; sid:510004; rev:1;)'
    },
    {
        "title": "Build Login POST Rule",
        "goal": "Detect external POST requests to /login on protected web servers.",
        "protocol": "http",
        "src": "$EXTERNAL_NET",
        "dst": "$HOME_NET",
        "buffer": "http.uri and http.method",
        "content": "/login and POST",
        "why": "Use http.method for POST and http.uri for /login. This teaches multiple buffers in one rule.",
        "final": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"External POST to login endpoint"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/login"; sid:510005; rev:1;)'
    },
]

def ask_step(prompt: str, expected: str, explanation: str, allow_contains=True) -> bool:
    print("\n" + CYAN + prompt + RESET)
    ans = input("> ").strip()
    if ans.lower() in ["exit", "quit"]:
        raise KeyboardInterrupt
    a = ans.lower()
    e = expected.lower()
    ok = (e in a) if allow_contains else (a == e)
    if ok:
        print(GREEN + "Correct." + RESET)
    else:
        print(YELLOW + "Not quite. Here's the guided answer:" + RESET)
        print(f"Expected: {expected}")
    print(explanation)
    return ok

def run_guided_build_mode():
    progress = load_progress()
    random.shuffle(GUIDED_BUILDS)

    for item in GUIDED_BUILDS:
        try:
            print_header("GUIDED RULE BUILD MODE")
            print(BOLD + item["title"] + RESET)
            print("\nGoal:")
            print(item["goal"])
            print("\nBefore building, remember the rule skeleton:")
            print('alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> (msg:"..."; <buffer>; content:"..."; sid:<id>; rev:1;)')
            print("\nNetwork variables:")
            print("  $HOME_NET = protected/internal networks")
            print("  $EXTERNAL_NET = outside/untrusted networks")
            print("\n" + item["why"])

            pause()

            correct_steps = 0
            total_steps = 5

            print_header("GUIDED RULE BUILD MODE - STEP BY STEP")
            print("We will build this one piece at a time.\n")

            if ask_step("1. What protocol should this rule use?", item["protocol"], f"Protocol should be {item['protocol']} because that parser understands the traffic."):
                correct_steps += 1

            if ask_step("2. What source network variable should we use?", item["src"], f"Use {item['src']} based on the traffic direction in the goal."):
                correct_steps += 1

            if ask_step("3. What destination network variable should we use?", item["dst"], f"Use {item['dst']} based on where the traffic is going."):
                correct_steps += 1

            if ask_step("4. What buffer should inspect the match?", item["buffer"].split(" and ")[0], f"Buffer choice: {item['buffer']}. This prevents raw noisy content matching."):
                correct_steps += 1

            if ask_step("5. What content should be matched?", item["content"].split(" and ")[0], f"Content should match the indicator or behavior: {item['content']}."):
                correct_steps += 1

            print("\n" + CYAN + "MODEL RULE" + RESET)
            print(item["final"])
            print("\nDo not worry about memorizing the whole thing yet.")
            print("Focus on why each part is there: protocol, variables, direction, buffer, content, msg/sid/rev.")

            fake_q = Question(
                id="guided_" + item["title"].lower().replace(" ", "_"),
                category="Guided Build",
                prompt=item["goal"],
                rule=item["final"],
                answer_points=[],
                required_terms=[],
                accepted_terms=[],
                hints=[],
                explanation=item["final"],
                difficulty=1,
                mode="read",
                skills=["writing", "rule_structure", "content_matching"]
            )

            update_stats(progress, fake_q, correct_steps >= 4, 0)
            save_progress(progress)
            pause()

        except KeyboardInterrupt:
            save_progress(progress)
            return

# ============================================================
# TRAINING LOOP
# ============================================================

def show_question(q: Question, index: int, total: int, stats: Dict, session: Dict, cat_stats: Dict, all_stats: Dict, level: str, reason: str):
    print_header(f"SOC SURICATA TRAINER - {q.category}")
    print(f"Question {index}/{total} | Difficulty {q.difficulty}/3 | Mode: {q.mode} | Learner Level: {level}")
    print(f"Adaptive reason: {reason}")
    print("Skills: " + ", ".join(q.skills))
    print("-" * 70)
    print(f"THIS QUESTION  Seen: {stats.get('seen', 0)} | Correct: {stats.get('correct', 0)} | Wrong: {stats.get('wrong', 0)} | Mastery: {stats.get('mastery', 0)}/5")
    print(f"THIS SESSION   Asked: {session.get('asked', 0)} | Correct: {session.get('correct', 0)} | Wrong: {session.get('wrong', 0)}")
    print(f"CATEGORY       Correct: {cat_stats.get('correct', 0)} | Wrong: {cat_stats.get('wrong', 0)} | Mastered: {cat_stats.get('mastered', 0)}/{cat_stats.get('total', 0)} | Accuracy: {cat_stats.get('accuracy', 0)}%")
    print(f"ALL TRAINING   Correct: {all_stats.get('correct', 0)} | Wrong: {all_stats.get('wrong', 0)} | Accuracy: {all_stats.get('accuracy', 0)}%")
    print("-" * 70)
    print("\nRULE:")
    print(q.rule)
    print("\nQUESTION:")
    print(q.prompt)
    print("\nCommands: hint | explain | skip | exit")
    print("-" * 70)

def run_session(category: str, bank: List[Question], adaptive: bool = True, count: Optional[int] = None):
    progress = load_progress()
    questions = pick_questions(bank, count, adaptive, progress)

    session = {
        "category": category,
        "started": datetime.now().isoformat(timespec="seconds"),
        "asked": 0,
        "correct": 0,
        "wrong": 0,
        "adaptive": adaptive
    }

    for idx, q in enumerate(questions, start=1):
        hints_used = 0

        while True:
            show_question(
                q,
                idx,
                len(questions),
                qstats(progress, q.id),
                session,
                category_stats(progress, bank),
                global_stats(progress),
                learner_level(progress, bank),
                explain_selection_reason(q, progress, bank)
            )
            ans = input("\n> ").strip()

            if not ans:
                continue

            cmd = ans.lower().strip()

            if cmd == "exit":
                progress["sessions"].append(session)
                save_progress(progress)
                return

            if cmd == "skip":
                print(YELLOW + "\nSkipped." + RESET)
                print("\nEXPLANATION:")
                print(q.explanation)
                update_stats(progress, q, False, hints_used)
                session["asked"] += 1
                session["wrong"] += 1
                save_progress(progress)
                pause()
                break

            if cmd == "hint":
                if hints_used < len(q.hints):
                    print(YELLOW + f"\nHINT {hints_used + 1}: {q.hints[hints_used]}" + RESET)
                    hints_used += 1
                else:
                    print(YELLOW + "\nNo more hints. Try answering, or type explain." + RESET)
                input("\nPress Enter to answer...")
                continue

            if cmd == "explain":
                print("\nEXPLANATION:")
                print(q.explanation)
                input("\nPress Enter to answer...")
                continue

            before_mastery = qstats(progress, q.id).get("mastery", 0)
            ok, issues = score_answer(ans, q)

            print("\n" + color_result(ok))

            if issues:
                print("\nFEEDBACK:")
                for issue in issues:
                    print(" - " + issue)

            update_stats(progress, q, ok, hints_used)
            after_mastery = qstats(progress, q.id).get("mastery", 0)

            session["asked"] += 1
            session["correct"] += int(ok)
            session["wrong"] += int(not ok)
            save_progress(progress)

            print("\nMASTERY UPDATE:")
            if after_mastery > before_mastery:
                print(GREEN + f" + Question mastery increased: {before_mastery}/5 -> {after_mastery}/5" + RESET)
            elif after_mastery < before_mastery:
                print(RED + f" - Question mastery decreased: {before_mastery}/5 -> {after_mastery}/5" + RESET)
            else:
                print(YELLOW + f" = Question mastery unchanged: {after_mastery}/5" + RESET)

            print(f" Session score: {session['correct']}/{session['asked']} correct")

            print("\nGOOD ANSWER / EXPLANATION:")
            print(q.explanation)

            if not ok:
                remediate_after_wrong(q)

            pause()
            break

    session["ended"] = datetime.now().isoformat(timespec="seconds")
    progress["sessions"].append(session)
    save_progress(progress)

    print_header("SESSION COMPLETE")
    print(f"Category: {category}")
    print(f"Asked: {session['asked']}")
    print(GREEN + f"Correct: {session['correct']}" + RESET)
    print(RED + f"Wrong: {session['wrong']}" + RESET)
    if session["asked"]:
        print(f"Score: {round((session['correct'] / session['asked']) * 100, 1)}%")
    print_recommendations(progress)
    pause()

# ============================================================
# REVIEW / REPORTING
# ============================================================

def weakest_skills(progress: Dict, limit: int = 5) -> List[Tuple[str, Dict]]:
    skills = progress.get("skills", {})
    rows = []
    for skill, st in skills.items():
        seen = st.get("seen", 0)
        if seen == 0:
            continue
        accuracy = st.get("correct", 0) / seen if seen else 0
        rows.append((st.get("mastery", 0), accuracy, -st.get("wrong", 0), skill, st))
    rows.sort(key=lambda x: (x[0], x[1], x[2]))
    return [(skill, st) for _, _, _, skill, st in rows[:limit]]

def print_recommendations(progress: Dict):
    weak = weakest_skills(progress)
    if not weak:
        print("\nRECOMMENDATIONS:")
        print(" - No weak skill data yet. Run Beginner Adaptive Path or Rule Repair first.")
        return

    print("\nRECOMMENDATIONS:")
    for skill, st in weak:
        desc = SKILL_DEFINITIONS.get(skill, skill)
        seen = st.get("seen", 0)
        correct = st.get("correct", 0)
        wrong = st.get("wrong", 0)
        mastery = st.get("mastery", 0)
        acc = round((correct / seen) * 100, 1) if seen else 0
        print(f" - {skill}: {desc}")
        print(f"   Mastery {mastery}/5 | Accuracy {acc}% | Correct {correct} | Wrong {wrong}")
        if skill == "http_buffers":
            print("   Next drill: distinguish http.uri vs http.host vs http.user_agent vs http.request_body.")
        elif skill == "rule_structure":
            print("   Next drill: write rules with action/protocol/direction/options/msg/sid/rev.")
        elif skill == "tuning":
            print("   Next drill: repair noisy rules by adding buffer scope, flow, specificity, or thresholds.")
        elif skill == "thresholding":
            print("   Next drill: practice detection_filter with track/count/seconds.")
        elif skill == "dns":
            print("   Next drill: practice dns.query, domain IOCs, startswith/endswith suffix logic.")
        elif skill == "tls":
            print("   Next drill: practice tls.sni vs http.host.")
        elif skill == "tcp_flow":
            print("   Next drill: practice flow:established,to_server and TCP flags.")
        elif skill == "regex":
            print("   Next drill: keep PCRE scoped to buffers and use it only when content is not enough.")
        elif skill == "repair":
            print("   Next drill: run Rule Repair Mode.")
        else:
            print("   Next drill: repeat adaptive mixed questions.")


def export_progress_report():
    progress = load_progress()
    qs = progress.get("questions", {})
    skills = progress.get("skills", {})

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_name = f"suricata_training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    total_seen = sum(v.get("seen", 0) for v in qs.values())
    total_correct = sum(v.get("correct", 0) for v in qs.values())
    total_wrong = sum(v.get("wrong", 0) for v in qs.values())
    accuracy = round((total_correct / total_seen) * 100, 1) if total_seen else 0

    weak = weakest_skills(progress, limit=5)

    lines = []
    lines.append("SURICATA ANALYST TRAINING REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("OVERALL")
    lines.append("-" * 60)
    lines.append(f"Questions seen: {total_seen}")
    lines.append(f"Correct:        {total_correct}")
    lines.append(f"Wrong:          {total_wrong}")
    lines.append(f"Accuracy:       {accuracy}%")
    lines.append("")
    lines.append("SKILL TREE")
    lines.append("-" * 60)

    if not skills:
        lines.append("No skill data yet.")
    else:
        for skill in sorted(SKILL_DEFINITIONS):
            st = skills.get(skill, {"seen": 0, "correct": 0, "wrong": 0, "mastery": 0})
            seen = st.get("seen", 0)
            correct = st.get("correct", 0)
            wrong = st.get("wrong", 0)
            mastery = st.get("mastery", 0)
            acc = round((correct / seen) * 100, 1) if seen else 0
            lines.append(f"{skill}: mastery {mastery}/5 | seen {seen} | correct {correct} | wrong {wrong} | accuracy {acc}%")
            lines.append(f"  {SKILL_DEFINITIONS.get(skill, '')}")

    lines.append("")
    lines.append("WEAK AREAS / RECOMMENDED NEXT STEPS")
    lines.append("-" * 60)
    if not weak:
        lines.append("No weak-area data yet. Recommended: run Start Training.")
    else:
        for skill, st in weak:
            lines.append(f"- {skill}: {SKILL_DEFINITIONS.get(skill, skill)}")
            if skill == "http_buffers":
                lines.append("  Next: review http.uri vs http.host vs http.user_agent vs http.request_body.")
            elif skill == "rule_structure":
                lines.append("  Next: practice identifying action/protocol/source/direction/destination/options.")
            elif skill == "tuning":
                lines.append("  Next: practice replacing broad raw content with scoped buffers and network variables.")
            elif skill == "dns":
                lines.append("  Next: practice dns.query and domain matching.")
            elif skill == "tls":
                lines.append("  Next: practice tls.sni vs http.host.")
            elif skill == "writing":
                lines.append("  Next: run Scaffolded Rule Writing before Full Rule Writing.")
            else:
                lines.append("  Next: repeat Start Training or Mixed Adaptive Drill.")

    Path(report_name).write_text("\n".join(lines), encoding="utf-8")
    soft_clear("REPORT EXPORTED")
    simple_success(f"Saved report: {report_name}")
    print("\nYou can attach or copy this file for training records.")
    pause()

def show_progress():
    progress = load_progress()
    print_header("TRAINING PROGRESS")

    rows = []
    qmap = {q.id: q for q in ALL_QUESTIONS}

    for qid, s in progress.get("questions", {}).items():
        q = qmap.get(qid)
        if not q:
            continue
        rows.append((s.get("mastery", 0), s.get("wrong", 0), s.get("seen", 0), q.category, q.prompt[:45]))

    if not rows:
        print("No progress yet.")
        pause()
        return

    rows.sort(key=lambda x: (x[0], -x[1], x[2]))

    print(f"{'Mastery':<8} {'Wrong':<6} {'Seen':<6} {'Category':<15} Prompt")
    print("-" * 90)
    for mastery, wrong, seen, cat, prompt in rows:
        print(f"{mastery:<8} {wrong:<6} {seen:<6} {cat:<15} {prompt}")

    print("\nLowest mastery items appear first. Adaptive mode prioritizes these automatically.")

    print("\nSKILL TREE")
    print("-" * 90)
    skills = progress.get("skills", {})
    if not skills:
        print("No skill data yet.")
    else:
        for skill in sorted(SKILL_DEFINITIONS):
            st = skills.get(skill, {"seen": 0, "correct": 0, "wrong": 0, "mastery": 0})
            seen = st.get("seen", 0)
            correct = st.get("correct", 0)
            wrong = st.get("wrong", 0)
            mastery = st.get("mastery", 0)
            acc = round((correct / seen) * 100, 1) if seen else 0
            print(f"{skill:<18} Mastery {mastery}/5 | Seen {seen:<3} | Correct {correct:<3} | Wrong {wrong:<3} | Acc {acc}%")
            print(f"  {SKILL_DEFINITIONS[skill]}")

    print_recommendations(progress)
    pause()

def reset_progress():
    print_header("RESET PROGRESS")
    confirm = input("Type RESET to delete trainer progress: ").strip()
    if confirm == "RESET":
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
        print(GREEN + "\nProgress reset." + RESET)
    else:
        print(YELLOW + "\nCanceled." + RESET)
    pause()

# ============================================================
# MENU
# ============================================================


# ============================================================
# BEGINNER CURRICULUM MODE
# Lesson -> identify -> choose -> fill blank -> guided build.
# This avoids throwing analysts directly into full rule writing.
# ============================================================

def normalize_choice(x: str) -> str:
    return (x or "").strip().lower()

def curriculum_pause():
    input("\nPress Enter to continue...")

def curriculum_mcq(question: str, choices: List[str], correct_index: int, why: str):
    print("\n" + CYAN + "CHECKPOINT" + RESET)
    print(question)
    for i, choice in enumerate(choices, start=1):
        print(f"  {i}. {choice}")
    ans = normalize_choice(input("> "))
    try:
        picked = int(ans) - 1
    except ValueError:
        picked = -1

    if picked == correct_index:
        print(GREEN + "Correct." + RESET)
    else:
        print(YELLOW + f"Not quite. Correct answer: {correct_index + 1}. {choices[correct_index]}" + RESET)
    print(why)
    curriculum_pause()

def curriculum_fill(prompt: str, expected: List[str], why: str):
    print("\n" + CYAN + "FILL-IN" + RESET)
    print(prompt)
    ans = normalize_choice(input("> "))
    ok = any(e.lower() in ans for e in expected)
    if ok:
        print(GREEN + "Correct." + RESET)
    else:
        print(YELLOW + "Not quite. Guided answer: " + " / ".join(expected) + RESET)
    print(why)
    curriculum_pause()
    return ok

def curriculum_show_rule_parts(rule: str):
    print("\n" + CYAN + "RULE WALKTHROUGH" + RESET)
    print(rule)
    print("\nRead it left to right:")
    print("  alert              = create an alert")
    print("  protocol           = parser/traffic type, like http, dns, tls, tcp")
    print("  source             = where traffic comes from")
    print("  ->                 = direction")
    print("  destination        = where traffic goes")
    print("  options            = what to inspect and match")
    print("  msg/sid/rev        = alert name, unique ID, revision")
    curriculum_pause()

def curriculum_guided_build(title: str, goal: str, skeleton: str, blanks: List[Tuple[str, str, str]], final_rule: str):
    print_header("GUIDED BUILD - " + title)
    print("Goal:")
    print(goal)
    print("\nWe are NOT writing the whole rule from scratch yet.")
    print("We will fill in one piece at a time.\n")
    print("Skeleton:")
    print(skeleton)
    curriculum_pause()

    answers = {}
    for key, expected, why in blanks:
        print_header("GUIDED BUILD - " + title)
        print("Skeleton:")
        working = skeleton
        for k, v in answers.items():
            working = working.replace("{" + k + "}", v)
        print(working)
        print(f"\nFill this blank: {{{key}}}")
        ans = input("> ").strip()
        if expected.lower() not in ans.lower():
            print(YELLOW + f"Guided answer: {expected}" + RESET)
            ans = expected
        else:
            print(GREEN + "Correct." + RESET)
        print(why)
        answers[key] = ans
        curriculum_pause()

    print_header("GUIDED BUILD COMPLETE - " + title)
    print("Completed model rule:")
    print(final_rule)
    print("\nWhy this works:")
    print("  - Uses network variables instead of any any everywhere.")
    print("  - Uses the right protocol parser.")
    print("  - Uses the right buffer before content.")
    print("  - Includes msg, sid, and rev.")
    curriculum_pause()

def curriculum_full_rule_intro():
    print_header("BEFORE FULL RULE WRITING")
    print("""
At this point, analysts should have seen the rule in pieces.

Full rule writing should come AFTER they can answer:
  1. What traffic direction do I care about?
  2. Which protocol parser should I use?
  3. Which buffer should I inspect?
  4. What exact content should I match?
  5. Is the match too broad?
  6. Do I need nocase?
  7. Do I have msg, sid, and rev?

For beginners, the trainer should grade full rules but also show the model answer immediately.
""".strip())
    curriculum_pause()


def remediation_question(skill: str):
    soft_clear("QUICK REMEDIATION")
    if skill == "http_buffers":
        curriculum_mcq(
            "A rule needs to match /login in a web request path. Which buffer should be used?",
            ["http.host", "http.uri", "dns.query", "tls.sni"],
            1,
            "Use http.uri for web paths like /login, /admin, and /download."
        )
    elif skill == "rule_structure":
        curriculum_mcq(
            "Which part shows traffic direction?",
            ["sid:100001;", "content:\"/admin\";", "->", "msg:\"test\";"],
            2,
            "The arrow -> separates source from destination."
        )
    elif skill == "dns":
        curriculum_mcq(
            "Which buffer should inspect the domain name being queried?",
            ["http.uri", "tls.sni", "dns.query", "http.host"],
            2,
            "Use dns.query for DNS query names."
        )
    elif skill == "tls":
        curriculum_mcq(
            "Which buffer should inspect the TLS handshake hostname?",
            ["tls.sni", "http.host", "dns.query", "content only"],
            0,
            "Use tls.sni for the hostname in the TLS handshake."
        )
    elif skill == "tuning":
        curriculum_mcq(
            'Why is content:"admin" by itself noisy?',
            ["It only matches encrypted traffic", "It can match anywhere, not just a URI path", "It disables sid", "It only works in DNS"],
            1,
            "Raw content can match too broadly. Better: http.uri; content:\"/admin\";"
        )
    else:
        curriculum_mcq(
            "What should a beginner do before adding advanced logic like detection_filter?",
            ["Guess", "Start with buffer scope and specific content", "Remove sid", "Use any any everywhere"],
            1,
            "Start simple: correct protocol, direction, buffer, content, msg, sid, rev."
        )

def remediate_after_wrong(q: Question):
    if not q.skills:
        return
    print("\n" + YELLOW + "Mini-remediation: let's reinforce the key concept before moving on." + RESET)
    remediation_question(q.skills[0])

def run_beginner_curriculum():
    # Module 1: variables and structure
    show_lesson("MODULE 1 - NETWORK VARIABLES", NETWORK_VARIABLES_LESSON)
    curriculum_mcq(
        "What does $HOME_NET usually represent?",
        ["The internet", "Networks we protect", "Only DNS servers", "A Suricata log file"],
        1,
        "$HOME_NET is normally the internal/protected network range defined in Suricata variables."
    )
    curriculum_mcq(
        "What does $EXTERNAL_NET any -> $HOME_NET any usually describe?",
        ["Outbound traffic from internal clients", "Inbound traffic toward protected networks", "Only DNS traffic", "Only encrypted traffic"],
        1,
        "The arrow points from source to destination. This means outside/untrusted traffic going to protected networks."
    )
    curriculum_show_rule_parts('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound admin path"; http.uri; content:"/admin"; sid:700001; rev:1;)')
    curriculum_fill(
        "In this direction, fill the protected destination variable: alert http $EXTERNAL_NET any -> ______ any (...)",
        ["$HOME_NET", "home_net"],
        "$HOME_NET goes on the destination side when external traffic is coming inbound to protected assets."
    )

    # Module 2: buffers
    show_lesson("MODULE 2 - BUFFERS", BUFFER_LESSON)
    curriculum_mcq(
        "Which buffer should inspect a web path like /login or /admin?",
        ["http.host", "http.uri", "tls.sni", "dns.query"],
        1,
        "http.uri is for the web path/URI. Do not use raw content for paths when http.uri is available."
    )
    curriculum_mcq(
        "Which buffer should inspect a DNS domain being queried?",
        ["dns.query", "http.uri", "http.user_agent", "flow"],
        0,
        "dns.query is the DNS query name."
    )
    curriculum_mcq(
        "Which buffer should inspect a TLS hostname from the handshake?",
        ["http.host", "tls.sni", "http.request_body", "sid"],
        1,
        "tls.sni is the hostname in the TLS ClientHello/handshake."
    )
    curriculum_fill(
        'Fill the buffer for a URI path: alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Admin path"; ______; content:"/admin"; sid:700002; rev:1;)',
        ["http.uri"],
        "Use http.uri before content:\"/admin\" so Suricata looks in the URI/path."
    )

    # Module 3: reading questions
    show_lesson("MODULE 3 - READING RULES", """
Reading a rule means translating it into plain English.

Ask:
  1. What protocol?
  2. Source to destination?
  3. What buffer?
  4. What content?
  5. What would cause an alert?

Example:
  alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Bad DNS"; dns.query; content:"bad.com"; sid:700003; rev:1;)

Plain English:
  Alert when an internal/protected host makes a DNS query containing bad.com.
""")
    curriculum_mcq(
        'Plain English: alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Bad DNS"; dns.query; content:"bad.com"; sid:700003; rev:1;)',
        [
            "External host browses to /bad.com",
            "Internal host queries DNS for bad.com",
            "TLS SNI contains bad.com inbound",
            "A TCP SYN goes to port 22"
        ],
        1,
        "dns.query + $HOME_NET -> $EXTERNAL_NET means an internal client is making an outbound DNS query."
    )

    # Module 4: guided building
    show_lesson("MODULE 4 - BUILDING RULES SLOWLY", RULE_BUILDING_LESSON)
    curriculum_guided_build(
        title="HTTP /admin URI",
        goal="Detect inbound HTTP requests from external networks to /admin on protected hosts.",
        skeleton='alert {protocol} {src} any -> {dst} any (msg:"External admin path"; {buffer}; content:"{content}"; sid:700004; rev:1;)',
        blanks=[
            ("protocol", "http", "Use http because this is HTTP web traffic."),
            ("src", "$EXTERNAL_NET", "Inbound traffic starts from outside/untrusted networks."),
            ("dst", "$HOME_NET", "The protected network is the destination."),
            ("buffer", "http.uri", "The /admin path belongs in the HTTP URI buffer."),
            ("content", "/admin", "The exact path we care about is /admin.")
        ],
        final_rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"External admin path"; http.uri; content:"/admin"; sid:700004; rev:1;)'
    )

    curriculum_guided_build(
        title="DNS bad-domain.com Query",
        goal="Detect internal hosts querying bad-domain.com.",
        skeleton='alert {protocol} {src} any -> {dst} any (msg:"Bad DNS query"; {buffer}; content:"{content}"; sid:700005; rev:1;)',
        blanks=[
            ("protocol", "dns", "Use dns because this is a DNS query."),
            ("src", "$HOME_NET", "Internal/protected clients usually initiate the query."),
            ("dst", "$EXTERNAL_NET", "The query is going outbound."),
            ("buffer", "dns.query", "The domain name being requested is in dns.query."),
            ("content", "bad-domain.com", "This is the suspicious domain to match.")
        ],
        final_rule='alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Bad DNS query"; dns.query; content:"bad-domain.com"; sid:700005; rev:1;)'
    )

    curriculum_guided_build(
        title="TLS SNI suspicious.example",
        goal="Detect internal hosts connecting to suspicious.example over TLS.",
        skeleton='alert {protocol} {src} any -> {dst} any (msg:"Suspicious TLS SNI"; {buffer}; content:"{content}"; sid:700006; rev:1;)',
        blanks=[
            ("protocol", "tls", "Use tls because we are inspecting TLS handshake metadata."),
            ("src", "$HOME_NET", "The internal/protected host is initiating the outbound connection."),
            ("dst", "$EXTERNAL_NET", "The connection is going to the outside network."),
            ("buffer", "tls.sni", "The TLS hostname is in tls.sni."),
            ("content", "suspicious.example", "This is the suspicious hostname.")
        ],
        final_rule='alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious TLS SNI"; tls.sni; content:"suspicious.example"; sid:700006; rev:1;)'
    )

    # Module 5: tuning
    show_lesson("MODULE 5 - TUNING WITHOUT OVERWHELMING", TUNING_LESSON)
    curriculum_mcq(
        'Why is this noisy? alert http any any -> any any (content:"admin"; sid:700007; rev:1;)',
        [
            "It has too many buffers",
            "It matches admin anywhere and in any direction",
            "sid is always bad",
            "HTTP rules cannot use content"
        ],
        1,
        "The rule is broad because it uses any any -> any any and raw content. Better: use network variables and http.uri."
    )
    curriculum_guided_build(
        title="Tune a Noisy Admin Rule",
        goal="Fix a noisy raw content admin rule by using direction, variables, and http.uri.",
        skeleton='alert {protocol} {src} any -> {dst} any (msg:"Inbound admin path"; {buffer}; content:"{content}"; sid:700008; rev:1;)',
        blanks=[
            ("protocol", "http", "Admin path is HTTP web traffic."),
            ("src", "$EXTERNAL_NET", "We care about inbound attempts from outside."),
            ("dst", "$HOME_NET", "Protected web assets are inside $HOME_NET."),
            ("buffer", "http.uri", "Admin path belongs in the URI, not raw packet content."),
            ("content", "/admin", "Use /admin instead of generic admin.")
        ],
        final_rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound admin path"; http.uri; content:"/admin"; sid:700008; rev:1;)'
    )

    # Module 6: only now introduce full rule answering
    curriculum_full_rule_intro()
    run_session("Beginner Curriculum Review", VARIABLES_AND_STRUCTURE + [q for q in RULE_READING if q.difficulty == 1], adaptive=True, count=10)

def run_beginner_path():
    run_beginner_curriculum()


def choose_count() -> Optional[int]:
    print("\nHow many questions?")
    print("1 10-question drill")
    print("2 15-question drill")
    print("3 Full category")
    c = input("> ").strip()
    if c == "1":
        return 10
    if c == "2":
        return 15
    return None



def choose_level():
    soft_clear("START TRAINING")
    print("Choose the analyst level:")
    print()
    print(GREEN + "1 Beginner" + RESET + "      New to Suricata rules")
    print(YELLOW + "2 Intermediate" + RESET + "  Knows basics, needs practice")
    print(RED + "3 Advanced" + RESET + "      Comfortable with rules/tuning")
    c = menu_choice()
    if c == "2":
        return "INTERMEDIATE"
    if c == "3":
        return "ADVANCED"
    return "BEGINNER"

def run_start_training():
    level = choose_level()

    if level == "BEGINNER":
        lesson_card(
            "COURSE START - BEGINNER",
            "Build confidence by learning one rule piece at a time.",
            [
                "Learn $HOME_NET and $EXTERNAL_NET.",
                "Read simple rules in plain English.",
                "Choose correct buffers.",
                "Fill blanks before writing full rules.",
                "Tune noisy rules without jumping into advanced syntax."
            ],
            "Analysts need to understand what a rule is doing before they can safely tune or write one."
        )
        run_beginner_curriculum()
        recap_card(
            "BEGINNER COURSE",
            [
                "Rule direction with $HOME_NET and $EXTERNAL_NET",
                "Basic rule structure",
                "HTTP/DNS/TLS buffer selection",
                "Guided rule building",
                "Basic tuning by scoping raw content"
            ],
            "Run Scaffolded Rule Writing next, then export a progress report."
        )
        run_scaffolded_writing()

    elif level == "INTERMEDIATE":
        lesson_card(
            "COURSE START - INTERMEDIATE",
            "Practice reading, tuning, repair, and scaffolded writing.",
            [
                "Review variables and buffers quickly.",
                "Practice rule reading.",
                "Tune noisy rules.",
                "Repair weak rules.",
                "Use scaffolded writing before full writing."
            ],
            "Intermediate analysts usually need repetition and feedback, not just harder syntax."
        )
        show_lesson("QUICK REVIEW - VARIABLES", NETWORK_VARIABLES_LESSON)
        show_lesson("QUICK REVIEW - BUFFERS", BUFFER_LESSON)
        run_session("Intermediate Reading", VARIABLES_AND_STRUCTURE + RULE_READING, adaptive=True, count=10)
        run_session("Intermediate Tuning", OPTIMIZATION, adaptive=True, count=10)
        run_session("Intermediate Repair", REPAIR, adaptive=True, count=10)
        run_scaffolded_writing()

    else:
        lesson_card(
            "COURSE START - ADVANCED",
            "Practice mixed adaptive questions and capstone scenarios.",
            [
                "Mixed reading/writing/tuning/repair.",
                "Weak-area recommendations.",
                "Capstone scenario.",
                "Progress export."
            ],
            "Advanced analysts should prove they can reason across multiple rule types and tuning decisions."
        )
        run_session("Advanced Mixed Drill", ALL_QUESTIONS, adaptive=True, count=15)
        run_capstone()

    export_prompt = input("\nExport progress report now? (y/n)> ").strip().lower()
    if export_prompt == "y":
        export_progress_report()

def run_scaffolded_writing():
    print_header("SCAFFOLDED RULE WRITING")
    print("""
This mode teaches writing without making the analyst invent the whole rule.

Flow:
  1. Read the goal.
  2. Pick protocol.
  3. Pick direction variables.
  4. Pick buffer.
  5. Pick content.
  6. Review the completed model rule.
""".strip())
    curriculum_pause()

    curriculum_guided_build(
        title="Scaffold HTTP Login POST",
        goal="Detect external POST requests to /login.",
        skeleton='alert {protocol} {src} any -> {dst} any (msg:"External POST to login"; http.method; content:"POST"; {buffer}; content:"{content}"; sid:710001; rev:1;)',
        blanks=[
            ("protocol", "http", "Use http because this is web traffic."),
            ("src", "$EXTERNAL_NET", "External users are the source."),
            ("dst", "$HOME_NET", "Protected web servers are the destination."),
            ("buffer", "http.uri", "The /login endpoint belongs in the URI."),
            ("content", "/login", "The endpoint to match is /login.")
        ],
        final_rule='alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"External POST to login"; http.method; content:"POST"; http.uri; content:"/login"; sid:710001; rev:1;)'
    )

    curriculum_guided_build(
        title="Scaffold Outbound Curl User-Agent",
        goal="Detect internal hosts using curl over HTTP.",
        skeleton='alert {protocol} {src} any -> {dst} any (msg:"Outbound curl User-Agent"; {buffer}; content:"{content}"; nocase; sid:710002; rev:1;)',
        blanks=[
            ("protocol", "http", "Use http because User-Agent is an HTTP header."),
            ("src", "$HOME_NET", "Internal hosts are the source."),
            ("dst", "$EXTERNAL_NET", "The traffic is going outbound."),
            ("buffer", "http.user_agent", "curl appears in the User-Agent header."),
            ("content", "curl", "Match curl and use nocase for capitalization differences.")
        ],
        final_rule='alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound curl User-Agent"; http.user_agent; content:"curl"; nocase; sid:710002; rev:1;)'
    )


def run_capstone():
    soft_clear("FINAL CAPSTONE")
    print("""
Scenario:
  An internal host is suspected of reaching out to suspicious.example over TLS.
  You want a Suricata rule that alerts when protected hosts make outbound TLS
  connections where SNI contains suspicious.example.

Think through:
  - Source: protected internal host = $HOME_NET
  - Destination: outside network = $EXTERNAL_NET
  - Protocol: tls
  - Buffer: tls.sni
  - Content: suspicious.example
""".strip())
    pause()

    expected = Question(
        id="capstone_tls_sni",
        category="Capstone",
        prompt="Build an outbound TLS SNI rule for suspicious.example.",
        rule="(build full rule)",
        answer_points=[],
        required_terms=["alert", "tls", "$home_net", "$external_net", "->", "sid", "rev", "msg", "tls.sni", "suspicious.example"],
        accepted_terms=[],
        hints=[],
        explanation='Model answer: alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound TLS SNI suspicious.example"; tls.sni; content:"suspicious.example"; sid:900001; rev:1;)',
        difficulty=2,
        mode="write",
        skills=["tls", "rule_structure", "writing", "content_matching"]
    )

    print("\nWrite the full rule, or type skip to see the answer.")
    ans = input("> ").strip()
    if ans.lower() == "skip":
        ok = False
        issues = ["Skipped capstone."]
    else:
        ok, issues = score_answer(ans, expected)

    print("\n" + color_result(ok))
    if issues:
        print("\nFeedback:")
        for issue in issues:
            print(" - " + issue)
    print("\n" + expected.explanation)

    progress = load_progress()
    update_stats(progress, expected, ok, 0 if ok else 1)
    save_progress(progress)

    if not ok:
        remediate_after_wrong(expected)

    recap_card(
        "CAPSTONE",
        [
            "Mapped scenario to traffic direction",
            "Selected protocol parser",
            "Selected correct buffer",
            "Built or reviewed a deployable-style rule"
        ],
        "Export a report or rerun weak-area practice."
    )

def main():
    while True:
        soft_clear("SURICATA ANALYST TRAINER")
        box("Main Menu", [
            "1  Start Training",
            "2  Guided Rule Build",
            "3  Scaffolded Rule Writing",
            "4  Rule Reading Practice",
            "5  Tuning Practice",
            "6  Rule Repair Practice",
            "7  Mixed Adaptive Drill",
            "8  Capstone Scenario",
            "9  Glossary / Quick Reference",
            "10 Show Progress / Skill Tree",
            "11 Export Progress Report",
            "12 Reset Progress",
            "0  Exit"
        ], CYAN)
        print()
        print("Recommended for new analysts: choose " + GREEN + "1 Start Training" + RESET)
        c = menu_choice()

        if c in ["0", "q", "quit", "exit"]:
            break
        elif c == "1":
            run_start_training()
        elif c == "2":
            run_guided_build_mode()
        elif c == "3":
            run_scaffolded_writing()
        elif c == "4":
            run_session("Rule Reading", VARIABLES_AND_STRUCTURE + RULE_READING, adaptive=True, count=choose_count())
        elif c == "5":
            show_lesson("TUNING LESSON", TUNING_LESSON)
            run_session("Optimization", OPTIMIZATION, adaptive=True, count=choose_count())
        elif c == "6":
            show_lesson("RULE REPAIR LESSON", TUNING_LESSON)
            run_session("Rule Repair", REPAIR, adaptive=True, count=choose_count())
        elif c == "7":
            run_session("Mixed", ALL_QUESTIONS, adaptive=True, count=choose_count())
        elif c == "8":
            run_capstone()
        elif c == "9":
            show_glossary()
        elif c == "10":
            show_progress()
        elif c == "11":
            export_progress_report()
        elif c == "12":
            reset_progress()
        else:
            simple_warn("Invalid selection.")
            pause()

if __name__ == "__main__":
    main()
