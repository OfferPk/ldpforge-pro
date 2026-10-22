

LDPv1

# **LDPForge Pro**

RFC 5036 MPLS Label Distribution Protocol & RFC 5443 LDP-IGP Sync Blackhole Studio  
RFC 5036 LDP RFC 5443 IGP-SYNC PHP (LABEL 0/3) ZERO-TRUST MPLS  
Carrier Backbone LDP-IGP Sync (Grade A+) Enterprise WAN Explicit Null (Grade A+) Vulnerable Blackhole Unauthenticated (Grade F)

RFC 5036 LDP PDU Parameters PDU: 38B

Local LSR ID  
Label Space ID  
LDP Message Type 0x0100 \- Hello Message (UDP 646\) 0x0200 \- Initialization Message (TCP 646\) 0x0201 \- KeepAlive Message (TCP 646\) 0x0400 \- Label Mapping Message 0x0001 \- Notification Message  
Message ID  
FEC Prefix  
Prefix Length  
PHP / Assigned Label Label 0 \- Explicit Null (QoS Preserved) Label 3 \- Implicit Null (Standard PHP) Label 16001 \- Explicit Label (UHP)  
TCP 646 Authentication RFC 5036 MD5 Protected RFC 5925 TCP-AO Protected Unauthenticated (Cleartext)

RFC 5443 LDP-IGP Sync Blackhole Simulator RFC 5443

OPTIMAL: Link & LDP Fully Converged  
No blackhole detected. Forwarding state is fully synchronized.

LDP-IGP Sync Config Enabled (MaxMetric 65535\) Disabled (Normal Metric Attracted)  
Physical Link Status Link UP (Recovered / Active) Link DOWN (Failure)  
LDP Session State Operational (Labels Exchanged) Initializing / OpenSent (No Labels) Down (Session Disconnected)  
Transit Traffic (Mbps)

Penultimate Hop Popping (PHP) Evaluation Label 0

Explicit Null (Label 0\) Active  
Penultimate router sends Label 0\. Egress PE inspects EXP bits for DiffServ QoS.  
• **Implicit Null (Label 3\)**: Strips MPLS label on penultimate router. Saves 1 lookup on egress, but loses 3-bit EXP/QoS bits.  
• **Explicit Null (Label 0\)**: Preserves 3-bit EXP bits for end-to-end Carrier QoS to the egress PE.

10-Point Zero-Trust MPLS Control Plane (LDP) Scorecard PASSING

A+

**100 / 100 Points Production Zero-Trust**  
All 10 MPLS transport security and synchronization controls satisfied.

RFC 5036 Binary Wireframe & Wireshark Hex Dissector  
Copy Hex Download PCAP  
0000 00 01 00 26 0a fe 00 01 00 00 04 00 00 1e 00 00 |...&............|

Multi-Platform Production Synthesizer Copy Config  
Cisco IOS-XE Cisco IOS-XR Juniper Junos Arista EOS Linux FRR (ldpd) Prometheus Alerts  
\! Generating configuration...