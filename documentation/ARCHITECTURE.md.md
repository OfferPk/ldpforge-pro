# LDPForge Pro \- Architecture & Technical Specification

> **IETF RFC 5036 (LDP \- Label Distribution Protocol), RFC 5443 (LDP-IGP Synchronization), RFC 3478 (Graceful Restart) & Penultimate Hop Popping (PHP) Architecture**

---

## 1\. Executive Summary & Protocol Overview

The **Label Distribution Protocol (LDP / IETF RFC 5036\)** is the foundational MPLS control plane protocol responsible for establishing and maintaining Label Switched Paths (LSPs) across service provider carrier backbones, enterprise MPLS WANs, and cloud interconnect fabrics.

LDP maps Layer 3 routing reachability (derived from Interior Gateway Protocols such as OSPF or IS-IS) into Layer 2.5 MPLS label bindings, enabling high-throughput hardware label switching (PUSH, SWAP, POP) without requiring intermediate routers to inspect IP headers.

\+-----------------------------------------------------------------------------------------+

|                                LDP ARCHITECTURAL OVERVIEW                               |

\+--------------------------+---------------------------------------+----------------------+

| Domain                   | Standard Mechanism                    | Operational Impact   |

\+--------------------------+---------------------------------------+----------------------+

| Peer Discovery           | UDP Port 646 Multicast (224.0.0.2)    | Discovers directly   |

|                          | & Unicast Targeted Hellos (tLDP)      | connected & remote PEs|

\+--------------------------+---------------------------------------+----------------------+

| Session Management       | TCP Port 646 State Machine            | Reliable session     |

|                          | (Non-Existent \-\> Init \-\> Operational) | negotiation & keepalive|

\+--------------------------+---------------------------------------+----------------------+

| Transit Blackhole Shield | RFC 5443 LDP-IGP Synchronization      | Prevents drops when  |

|                          | Holds IGP metric at 65535 on link up  | IGP beats LDP up     |

\+--------------------------+---------------------------------------+----------------------+

| Egress Optimization      | Penultimate Hop Popping (PHP)         | Implicit Null (3) vs |

|                          | Strips or preserves EXP/QoS bits      | Explicit Null (0)    |

\+--------------------------+---------------------------------------+----------------------+

| Fast Resiliency          | LDP Session Protection & BFD          | Retains LIB bindings |

|                          | Sub-50ms hardware link cut detection  | through link flaps   |

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. RFC 5036 LDP PDU Anatomy & Header Specifications

Every LDP PDU consists of a **10-octet PDU Header**, followed by one or more LDP Messages:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|          Version (1)          |          PDU Length           |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                         LSR ID (4 octets)                     |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|       Label Space ID (2)      |  Message Type  | Message Len  |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                          Message ID                           |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                     Mandatory & Optional TLVs ...             |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

### 2.1 PDU Header Fields

- **Version (16 bits)**: Protocol version; set to `0x0001` for RFC 5036\.  
- **PDU Length (16 bits)**: Total length of PDU in octets excluding the Version and PDU Length fields (i.e., 6 octets for LDP ID \+ length of messages).  
- **LDP Identifier (LDP ID) (48 bits / 6 octets)**:  
  - **LSR ID (4 octets)**: 32-bit unique IP address identifying the Label Switching Router (typically Loopback0).  
  - **Label Space ID (2 octets)**: `0x0000` specifies a per-platform label space where a label has identical meaning across all interfaces. Non-zero values represent per-interface label spaces.

---

## 3\. The Classic LDP-IGP Synchronization Blackhole (RFC 5443\)

One of the most catastrophic and elusive failure modes in MPLS networks is the **LDP-IGP Synchronization Blackhole**:

\[ PE-1 \] \======= \[ P-1 \] \---------------- \[ P-2 \] \======= \[ PE-2 \]

                     \\                      /

                      \\---- \[ P-Alternate \]/

### 3.1 The Failure Sequence (Without LDP-IGP Sync)

1. The direct physical link between `P-1` and `P-2` experiences a fiber cut, and traffic reroutes via `P-Alternate`.  
2. The fiber is spliced and the physical link transitions to **UP**.  
3. The underlying IGP (OSPF or IS-IS) forms an immediate adjacency and advertises its normal link metric (e.g., `10`).  
4. `PE-1` and `P-1` run SPF and determine that the direct `P-1` \$\\rightarrow\$ `P-2` link is the shortest path.  
5. Ingress traffic is immediately shifted onto the `P-1` \$\\rightarrow\$ `P-2` link.  
6. **The Blackhole**: LDP relies on TCP port 646\. Establishing the TCP 3-way handshake, exchanging Initialization messages, and distributing Label Mapping messages takes **3 to 10 seconds**.  
7. Because `P-1` has not received label mappings from `P-2`, `P-1` has **no outgoing label in its LFIB** for destinations behind `PE-2`.  
8. **Result**: `P-1` silently drops 100% of customer VPN and MPLS transit traffic during the convergence window\!

### 3.2 The RFC 5443 Solution

- When the physical link comes up, the IGP advertises the **Maximum Metric** (`65535` in OSPF, or `0xFFFFFE` in wide metric IS-IS).  
- Transit routers keep forwarding traffic across the alternate path (`P-Alternate`).  
- Only after the LDP session reaches the `OPERATIONAL` state and label bindings are fully populated does LDP signal the IGP to lower the metric to its normal calibrated value (`10`).  
- **Result**: Zero dropped packets during link recovery.

---

## 4\. Penultimate Hop Popping (PHP) & QoS Preservation

During LSP traversal, the egress PE router is the final destination for an MPLS FEC (Forwarding Equivalence Class).

\[ Ingress PE \] \--(Label 100)--\> \[ Transit P \] \--(PHP?)--\> \[ Egress PE \]

### 4.1 Implicit Null (`Label 3` / Standard PHP)

- The egress PE advertises **Implicit Null (Label 3\)** to upstream transit router `P`.  
- Upstream router `P` examines its LFIB, sees outgoing label 3, **strips (pops) the outermost MPLS label**, and forwards native IP to the egress PE.  
- **Advantage**: Saves one CPU/ASIC label lookup on the egress PE router.  
- **Hazard**: Stripping the MPLS header removes the 3-bit **Traffic Class / EXP** field\! If the egress PE uses EXP-based classification for DiffServ QoS, voice and critical traffic cannot be prioritized on egress queues.

### 4.2 Explicit Null (`Label 0` for IPv4 / `Label 2` for IPv6)

- The egress PE advertises **Explicit Null (Label 0\)**.  
- Upstream router `P` swaps the incoming label to `Label 0` and forwards the packet with the MPLS header intact.  
- The egress PE receives the MPLS header, inspects the 3-bit EXP field to classify the packet into high-priority QoS queues, and then pops the label.  
- **Best Practice**: Mandatory in carrier backbones and enterprise WANs carrying voice, video, or financial HFT data.

---

## 5\. LDP Session Protection & Targeted LDP (tLDP)

When an optical interface bounces, physical link-down events instantly tear down the directly connected LDP session, purging all associated label mappings from the Label Information Base (LIB).

**LDP Session Protection** addresses this:

1. When two adjacent routers establish an LDP session over a direct link, they simultaneously negotiate a **Targeted LDP (tLDP)** session between their Loopback addresses.  
2. If the physical link flaps, the direct link Hello times out, but the **Targeted LDP session remains active** via alternate routing paths.  
3. The router retains all label bindings in its LIB in a dormant state.  
4. When the direct link recovers or alternate paths converge, the router re-activates the existing labels immediately without waiting for a fresh label exchange.

---

## 6\. 10-Point Zero-Trust MPLS Control Plane (LDP) Audit Framework

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **LDP-SEC-01** | RFC 5036 TCP 646 Cryptographic Auth | 15 pts | Mandatory MD5 or TCP-AO key on TCP port 646\. |
| **LDP-SEC-02** | RFC 5443 LDP-IGP Synchronization | 15 pts | Max-Metric hold during LDP convergence; zero blackholes. |
| **LDP-SEC-03** | LDP Session Protection & Targeted LDP | 12 pts | Multi-hop targeted session redundancy for fast failover. |
| **LDP-SEC-04** | Label Allocation Filtering (/32 Only) | 10 pts | Allocates labels only for Loopback /32 prefixes. |
| **LDP-SEC-05** | RFC 3478 Graceful Restart / Helper Mode | 10 pts | Preserves forwarding state during RP failover. |
| **LDP-SEC-06** | Explicit Null PHP Policy for QoS | 8 pts | Label 0 preserves 3-bit EXP field for egress QoS. |
| **LDP-SEC-07** | Deterministic LSR-ID (Loopback0) Binding | 8 pts | Pinned with `force` parameter to prevent ID flapping. |
| **LDP-SEC-08** | Control Plane Policing (CoPP) Port 646 | 8 pts | Hardware rate-limiting for UDP/TCP port 646\. |
| **LDP-SEC-09** | Sub-Second Link Detection (BFD for LDP) | 7 pts | Sub-50ms hardware link failure detection. |
| **LDP-SEC-10** | Ordered Label Control Mode Enforced | 7 pts | Labels allocated only after downstream mapping exists. |

