# LDPForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for carrier engineers, network infrastructure architects, and NetDevOps teams deploying Zero-Trust MPLS Label Distribution Protocol (RFC 5036 & RFC 5443).**

---

## 1\. Quickstart: Web Application Studio

The **LDPForge Pro Web Studio** is completely self-contained and operates 100% client-side with zero external dependencies. Open `source-code/index.html` directly in any web browser:

\# Optional local web server

cd product\_122/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Industry Presets**:  
   - **Carrier Backbone LDP-IGP Sync (Grade A+)**: Complete Zero-Trust MPLS core with RFC 5443 sync, session protection, /32 label filtering, and MD5 authentication.  
   - **Enterprise WAN Explicit Null (Grade A+)**: High-QoS deployment utilizing Explicit Null (Label 0\) for voice/video EXP preservation and TCP-AO.  
   - **Vulnerable Blackhole Unauthenticated (Grade F)**: Insecure baseline exposing missing LDP-IGP sync, unauthenticated TCP 646, and missing session protection.  
2. **RFC 5036 LDP PDU Parameters**: Configure LSR ID, Label Space (0 for per-platform), Message Type (Hello, Initialization, Keepalive, Label Mapping), Message ID, and FEC Prefix/Length.  
3. **RFC 5443 LDP-IGP Sync Simulator**: Real-time diagnostic modeling link recovery vs LDP session convergence, calculating traffic blackhole risk.  
4. **Penultimate Hop Popping (PHP) Analyzer**: Visualizes Implicit Null (Label 3\) vs Explicit Null (Label 0), assessing impact on 3-bit EXP DiffServ QoS classification.  
5. **10-Point Zero-Trust Scorecard**: Real-time compliance rating (0–100%, Grades A+ to F) with granular remediation instructions.  
6. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard export and binary `.pcap` capture file generation.  
7. **Multi-Platform Synthesizer**: Instant production configuration generation for Cisco IOS-XE, Cisco IOS-XR, Juniper Junos, Arista EOS, Linux FRRouting (`ldpd`), and Prometheus alerting rules.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/ldpforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/ldpforge-cli.py \--dissect

### 2.2 Diagnosing LDP-IGP Synchronization & Blackholes

\# Inspect vulnerable preset (LDP-IGP Sync Disabled)

./build/ldpforge-cli.py \--preset build/presets/vulnerable-blackhole-unauthenticated.json \--sync

\# Inspect carrier core preset (LDP-IGP Sync Active)

./build/ldpforge-cli.py \--preset build/presets/carrier-backbone-ldp-sync.json \--sync

### 2.3 Evaluating Penultimate Hop Popping (PHP) & QoS Impact

./build/ldpforge-cli.py \--php

### 2.4 Running 10-Point Zero-Trust MPLS Audits

./build/ldpforge-cli.py \--preset build/presets/carrier-backbone-ldp-sync.json \--audit

### 2.5 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing network decoders or validating with Wireshark:

./build/ldpforge-cli.py \--preset build/presets/carrier-backbone-ldp-sync.json \--pcap carrier-ldp.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-n \-r carrier-ldp.pcap

### 2.6 Automated CI/CD Pipeline Gating (`--strict`)

Integrate LDPForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit MPLS LDP Control Plane & Sync Compliance

  run: |

    python3 build/ldpforge-cli.py \\

      \--preset build/presets/production-ldp.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and zero transit blackhole hazard. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or fatal blackhole detected. Pipeline halts.*

---

## 3\. Production Hardening & Configuration Guide

### 3.1 Cisco IOS-XE Hardened Core Configuration

mpls ip

mpls ldp router-id Loopback0 force

mpls ldp session-protection

mpls ldp graceful-restart

mpls ldp explicit-null

mpls ldp password required

mpls ldp neighbor 10.254.0.2 password Ldp\$ecureMpl\$2026\!

\! Filter label allocation to /32 host routes only

no mpls ldp label allocate global

mpls ldp label allocate global host-routes

interface GigabitEthernet0/0/1

 ip address 10.100.0.1 255.255.255.252

 mpls ip

 mpls ldp sync

 bfd interval 50 min\_rx 50 multiplier 3

 mpls ldp bfd

router ospf 1

 router-id 10.254.0.1

 mpls ldp sync

---

## 4\. Troubleshooting & High-Impact Failure Modes

1. **Transient MPLS Blackhole Outage During Link Up**:  
   - *Cause*: IGP link came up and lowered metric to normal before LDP TCP 646 session established label mappings.  
   - *Resolution*: Enable RFC 5443 LDP-IGP Synchronization (`mpls ldp sync` under OSPF/IS-IS).  
2. **QoS Drops on Egress PE (VoIP / Critical Traffic)**:  
   - *Cause*: Implicit Null (Label 3\) strips the MPLS header upstream, discarding the 3-bit EXP field before the egress router can classify the packet.  
   - *Resolution*: Configure `mpls ldp explicit-null` to preserve EXP bits to the egress router.  
3. **Session Teardown on Interface Flap**:  
   - *Cause*: Direct LDP session bound to physical link without targeted backup.  
   - *Resolution*: Configure `mpls ldp session-protection` to maintain targeted LDP sessions over loopbacks.  
4. **LFIB Table Bloat & High CPU**:  
   - *Cause*: Router allocates MPLS labels for every transit subnet and /30 link prefix.  
   - *Resolution*: Filter label allocation strictly to `/32` Loopback prefixes.