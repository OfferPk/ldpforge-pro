/**
 * LDPForge Pro - RFC 5036 LDP Protocol Engine & Wireframe Dissector
 * 
 * Implements:
 * - RFC 5036 LDP PDU encoding and decoding (Version 1, PDU Length, 6-byte LDP ID).
 * - LDP Messages: Hello (UDP 646), Initialization (TCP 646), Keepalive, Label Mapping (FEC & Label TLVs).
 * - Penultimate Hop Popping (PHP) analyzer (Implicit Null Label 3 vs Explicit Null Label 0).
 * - RFC 5443 LDP-IGP Synchronization blackhole diagnostic engine.
 * - LIB / LFIB state table generator with PUSH, SWAP, and POP forwarding actions.
 * - Wireshark-style hex dump formatting and binary PCAP generation.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LDPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // RFC 5036 Message Types
  const MSG_TYPES = {
    NOTIFICATION: 0x0001,
    HELLO: 0x0100,
    INITIALIZATION: 0x0200,
    KEEPALIVE: 0x0201,
    ADDRESS: 0x0300,
    ADDRESS_WITHDRAW: 0x0301,
    LABEL_MAPPING: 0x0400,
    LABEL_REQUEST: 0x0401,
    LABEL_ABORT_REQUEST: 0x0402,
    LABEL_WITHDRAW: 0x0403,
    LABEL_RELEASE: 0x0404
  };

  // RFC 5036 TLV Types
  const TLV_TYPES = {
    FEC: 0x0100,
    ADDRESS_LIST: 0x0101,
    HOP_COUNT: 0x0103,
    PATH_VECTOR: 0x0104,
    GENERIC_LABEL: 0x0200,
    STATUS: 0x0300,
    COMMON_HELLO_PARMS: 0x0400,
    IPV4_TRANSPORT_ADDR: 0x0401,
    CONFIG_SEQ_NUM: 0x0402,
    COMMON_SESSION_PARMS: 0x0500
  };

  // Special Reserved MPLS Labels (RFC 3032 / RFC 5036)
  const RESERVED_LABELS = {
    EXPLICIT_NULL_IPV4: 0,
    ROUTER_ALERT: 1,
    EXPLICIT_NULL_IPV6: 2,
    IMPLICIT_NULL: 3,
    ENTROPY_LABEL_INDICATOR: 7,
    OAM_ALERT: 14
  };

  function parseIpv4(ipStr) {
    if (!ipStr || typeof ipStr !== 'string') return [0, 0, 0, 0];
    const parts = ipStr.trim().split('.');
    if (parts.length !== 4) return [0, 0, 0, 0];
    return parts.map(p => {
      const n = parseInt(p, 10);
      return (isNaN(n) || n < 0 || n > 255) ? 0 : n;
    });
  }

  function formatIpv4(bytes, offset = 0) {
    return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
  }

  /**
   * Forges an RFC 5036 compliant LDP PDU
   */
  function forgePacket(config) {
    const lsrId = config.lsrId || '10.254.0.1';
    const labelSpace = config.labelSpace !== undefined ? config.labelSpace : 0;
    const msgType = config.msgType || MSG_TYPES.HELLO;
    const messageId = config.messageId || 1001;
    const holdTime = config.holdTime || 15;
    const keepaliveTime = config.keepaliveTime || 180;
    const isTargeted = !!config.isTargeted;
    const fecPrefix = config.fecPrefix || '10.100.0.0';
    const fecPrefixLen = config.fecPrefixLen !== undefined ? config.fecPrefixLen : 24;
    const assignedLabel = config.assignedLabel !== undefined ? config.assignedLabel : 16001;
    const transportAddr = config.transportAddr || lsrId;

    const lsrBytes = parseIpv4(lsrId);
    const transportBytes = parseIpv4(transportAddr);
    const msgBytes = [];

    // Construct specific Message payload
    if (msgType === MSG_TYPES.HELLO) {
      // Common Hello Parameters TLV (Type 0x0400, Len 4)
      msgBytes.push(0x04, 0x00); // Type: Common Hello Parameters
      msgBytes.push(0x00, 0x04); // Length: 4 bytes
      msgBytes.push((holdTime >> 8) & 0xff, holdTime & 0xff);
      // Flags: T (Targeted), R (Request send targeted), G (G-MPLS)
      const flags = (isTargeted ? 0x80 : 0x00);
      msgBytes.push(flags, 0x00); // Flags & Reserved

      // IPv4 Transport Address TLV (Type 0x0401, Len 4)
      msgBytes.push(0x04, 0x01); // Type: IPv4 Transport Address
      msgBytes.push(0x00, 0x04); // Length: 4 bytes
      msgBytes.push(...transportBytes);

    } else if (msgType === MSG_TYPES.INITIALIZATION) {
      // Common Session Parameters TLV (Type 0x0500, Len 14)
      msgBytes.push(0x05, 0x00); // Type: Common Session Parameters
      msgBytes.push(0x00, 0x0e); // Length: 14 bytes
      msgBytes.push(0x00, 0x01); // Protocol Version: 1
      msgBytes.push((keepaliveTime >> 8) & 0xff, keepaliveTime & 0xff); // KeepAlive Time
      msgBytes.push(0x00); // A-bit (0 = Downstream Unsolicited), D-bit (0)
      msgBytes.push(0x00); // Path Vector Limit
      msgBytes.push(0x10, 0x00); // Max PDU Length: 4096 (0x1000)
      // Receiver LDP Identifier (6 bytes): 4 bytes IP + 2 bytes label space
      const rxLsrBytes = parseIpv4(config.receiverLsrId || '10.254.0.2');
      msgBytes.push(...rxLsrBytes, 0x00, 0x00);

    } else if (msgType === MSG_TYPES.KEEPALIVE) {
      // Keepalive message has empty body (no mandatory TLVs)

    } else if (msgType === MSG_TYPES.LABEL_MAPPING) {
      // FEC TLV (Type 0x0100)
      const fecBytes = parseIpv4(fecPrefix);
      const prefixBytesToEncode = Math.ceil(fecPrefixLen / 8);
      const fecValBytes = [
        0x02, // Prefix FEC Element
        0x00, 0x01, // Address Family: IPv4 (1)
        fecPrefixLen // PreLen
      ];
      for (let i = 0; i < prefixBytesToEncode; i++) {
        fecValBytes.push(fecBytes[i] || 0);
      }
      msgBytes.push(0x01, 0x00); // TLV Type: FEC
      msgBytes.push((fecValBytes.length >> 8) & 0xff, fecValBytes.length & 0xff);
      msgBytes.push(...fecValBytes);

      // Generic Label TLV (Type 0x0200, Len 4)
      // Label is 20-bit value encoded in 4 octets
      const labelVal = assignedLabel & 0xfffff;
      msgBytes.push(0x02, 0x00); // TLV Type: Generic Label
      msgBytes.push(0x00, 0x04); // Length: 4 bytes
      msgBytes.push((labelVal >> 16) & 0x0f, (labelVal >> 8) & 0xff, labelVal & 0xff, 0x00);

    } else if (msgType === MSG_TYPES.NOTIFICATION) {
      // Status TLV (Type 0x0300, Len 10)
      msgBytes.push(0x03, 0x00); // Type: Status TLV
      msgBytes.push(0x00, 0x0a); // Length: 10 bytes
      // Status code: 32 bits. e.g. 0x00000000 Success, 0x8000000B Session KeepAlive Timer Expired
      const statusCode = config.statusCode || 0x00000000;
      msgBytes.push(
        (statusCode >> 24) & 0xff,
        (statusCode >> 16) & 0xff,
        (statusCode >> 8) & 0xff,
        statusCode & 0xff
      );
      msgBytes.push((messageId >> 24) & 0xff, (messageId >> 16) & 0xff, (messageId >> 8) & 0xff, messageId & 0xff);
      msgBytes.push((msgType >> 8) & 0xff, msgType & 0xff);
    }

    // Wrap in LDP Message Header (Type: 16 bits, Length: 16 bits, MsgID: 32 bits)
    const msgLen = 4 + msgBytes.length; // Message ID (4B) + Parameters
    const fullMessage = [
      (msgType >> 8) & 0xff, msgType & 0xff,
      (msgLen >> 8) & 0xff, msgLen & 0xff,
      (messageId >> 24) & 0xff, (messageId >> 16) & 0xff, (messageId >> 8) & 0xff, messageId & 0xff,
      ...msgBytes
    ];

    // LDP PDU Header: Version (2B), PDU Length (2B), LDP Identifier (6B)
    // PDU Length = length of LDP ID (6B) + all messages
    const pduLen = 6 + fullMessage.length;
    const pduHeader = [
      0x00, 0x01, // Version 1
      (pduLen >> 8) & 0xff, pduLen & 0xff,
      ...lsrBytes,
      (labelSpace >> 8) & 0xff, labelSpace & 0xff
    ];

    const rawBytes = new Uint8Array([...pduHeader, ...fullMessage]);

    return {
      version: 1,
      pduLength: pduLen,
      totalLength: rawBytes.length,
      lsrId: lsrId,
      labelSpace: labelSpace,
      ldpIdentifier: `${lsrId}:${labelSpace}`,
      msgType: msgType,
      messageId: messageId,
      rawBytes: rawBytes,
      hexString: Array.from(rawBytes).map(b => b.toString(16).padStart(2, '0')).join('')
    };
  }

  /**
   * Formats raw bytes into a standard Wireshark-style hex dump
   */
  function formatHexDump(rawBytes) {
    const bytes = Array.from(rawBytes);
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const offsetHex = i.toString(16).padStart(4, '0');
      const hexPart1 = slice.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const hexPart2 = slice.slice(8, 16).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const hexPart = `${hexPart1.padEnd(23, ' ')}  ${hexPart2.padEnd(23, ' ')}`;
      const asciiPart = slice.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
      lines.push(`${offsetHex}   ${hexPart.padEnd(48, ' ')}   |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  /**
   * Diagnoses RFC 5443 LDP-IGP Synchronization & Blackhole Risk
   */
  function diagnoseLdpIgpSync(params) {
    const igpSyncEnabled = !!params.igpSyncEnabled;
    const linkStatus = params.linkStatus || 'UP';
    const ldpSessionState = params.ldpSessionState || 'OPERATIONAL'; // DOWN, INITIALIZING, OPERATIONAL
    const igpNormalMetric = params.igpNormalMetric || 10;
    const ldpSyncMaxMetric = 65535; // Standard OSPF Max-Metric
    const transitTrafficBps = params.transitTrafficBps || 1000000000; // 1 Gbps default

    // If link is UP but LDP is not yet operational
    if (linkStatus === 'UP' && ldpSessionState !== 'OPERATIONAL') {
      if (!igpSyncEnabled) {
        return {
          status: 'FATAL_BLACKHOLE',
          riskLevel: 'CRITICAL',
          igpAdvertisedMetric: igpNormalMetric,
          ldpSessionState: ldpSessionState,
          isBlackholing: true,
          title: 'FATAL MPLS BLACKHOLE: LDP-IGP Sync Disabled',
          description: `Physical link is UP and IGP metric is at normal value (${igpNormalMetric}), attracting transit traffic. However, LDP session is ${ldpSessionState} and no label bindings exist in LFIB. 100% of customer MPLS/VPN traffic traversing this link is dropped!`,
          remediation: 'Enable RFC 5443 LDP-IGP Synchronization (`mpls ldp sync` in Cisco or `set protocols ospf ldp-synchronization` in Junos) to hold IGP metric at 65535 until LDP is Operational.'
        };
      } else {
        return {
          status: 'PROTECTED_SYNC',
          riskLevel: 'PROTECTED',
          igpAdvertisedMetric: ldpSyncMaxMetric,
          ldpSessionState: ldpSessionState,
          isBlackholing: false,
          title: 'PROTECTED: LDP-IGP Sync Active (Max-Metric Advertised)',
          description: `Link is UP but LDP session is ${ldpSessionState}. RFC 5443 LDP-IGP Sync holds the advertised IGP metric at ${ldpSyncMaxMetric}. Transit traffic is deterred and steered over alternate LSPs until label exchange finishes.`,
          remediation: 'Configuration is compliant. LDP will drop metric to normal once session reaches Operational state.'
        };
      }
    }

    return {
      status: 'HEALTHY',
      riskLevel: 'OPTIMAL',
      igpAdvertisedMetric: igpNormalMetric,
      ldpSessionState: ldpSessionState,
      isBlackholing: false,
      title: 'OPTIMAL: Link & LDP Session Fully Converged',
      description: `LDP session is OPERATIONAL with active label bindings in LFIB. IGP metric is set to normal (${igpNormalMetric}). Forwarding state is fully synchronized.`,
      remediation: 'Maintain current configuration and monitor LDP session keepalives.'
    };
  }

  /**
   * Evaluates Penultimate Hop Popping (PHP) Behavior
   */
  function evaluatePhpPolicy(policy, qosRequired = true) {
    if (policy === 'IMPLICIT_NULL' || policy === 'LABEL_3') {
      return {
        labelValue: 3,
        labelType: 'Implicit Null (Label 3)',
        popLocation: 'Penultimate Hop Router (Upstream)',
        egressLookupSaved: true,
        qosExpPreserved: false,
        grade: qosRequired ? 'WARN' : 'PASS',
        summary: 'Standard PHP (Label 3). The penultimate router strips the MPLS header before forwarding to the egress PE.',
        impact: qosRequired 
          ? 'HAZARD: Stripping MPLS header on penultimate router discards the 3-bit EXP/QoS field, breaking DiffServ classification on the egress router.'
          : 'Efficient for best-effort IP networks; eliminates one label lookup on the egress PE router.'
      };
    } else if (policy === 'EXPLICIT_NULL' || policy === 'LABEL_0') {
      return {
        labelValue: 0,
        labelType: 'Explicit Null (Label 0)',
        popLocation: 'Ultimate Hop Router (Egress PE)',
        egressLookupSaved: false,
        qosExpPreserved: true,
        grade: 'PASS',
        summary: 'Explicit Null (Label 0). Penultimate router sends packet with Label 0 intact.',
        impact: 'OPTIMAL for Carrier/Enterprise QoS. Egress PE inspects the 3-bit EXP field to enforce egress QoS policies before popping the label.'
      };
    } else {
      return {
        labelValue: 16001,
        labelType: 'Ultimate Hop Popping (UHP)',
        popLocation: 'Ultimate Hop Router (Egress PE)',
        egressLookupSaved: false,
        qosExpPreserved: true,
        grade: 'INFO',
        summary: 'Ultimate Hop Popping (UHP) with non-zero label. Used in MPLS Traffic Engineering or segment routing.',
        impact: 'Egress router performs complete label swap/pop in software or hardware.'
      };
    }
  }

  /**
   * Models the Label Information Base (LIB) and Label Forwarding Information Base (LFIB)
   */
  function generateLfibTable(prefixes, localLsrId, neighbors) {
    return prefixes.map((p, idx) => {
      const localLabel = 1000 + idx;
      const remoteLabel = p.isEgress ? (p.explicitNull ? 0 : 3) : (2000 + idx);
      const action = remoteLabel === 3 ? 'POP_LABEL' : (p.isIngress ? 'PUSH_LABEL' : 'SWAP_LABEL');
      const nextHop = neighbors[0] ? neighbors[0].ip : '10.100.0.2';

      return {
        prefix: p.prefix,
        prefixLen: p.prefixLen,
        inLabel: p.isIngress ? 'IP' : localLabel,
        outLabel: remoteLabel,
        action: action,
        nextHop: nextHop,
        interface: 'GigabitEthernet0/0/1',
        phpStatus: remoteLabel === 3 ? 'Implicit Null Pop' : (remoteLabel === 0 ? 'Explicit Null Swap' : 'Label Swap')
      };
    });
  }

  /**
   * Generates a standard binary PCAP file containing the forged LDP packet
   */
  function generatePcap(forgedPacket, isUdp = true) {
    const pduBytes = forgedPacket.rawBytes;
    
    // Ethernet Header (14 bytes)
    // Dest: 01:00:5E:00:00:02 (All-Routers multicast) for UDP Hello, or Unicast for TCP
    const ethDst = isUdp ? [0x01, 0x00, 0x5e, 0x00, 0x00, 0x02] : [0x00, 0x50, 0x56, 0xa1, 0xb2, 0xc3];
    const ethSrc = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    const ethType = [0x08, 0x00]; // IPv4
    const ethHdr = [...ethDst, ...ethSrc, ...ethType];

    // IP Header (20 bytes)
    const ipTotalLen = 20 + (isUdp ? 8 : 20) + pduBytes.length;
    const ipSrc = parseIpv4(forgedPacket.lsrId);
    const ipDst = isUdp ? [224, 0, 0, 2] : parseIpv4('10.254.0.2');
    const ipProto = isUdp ? 17 : 6; // UDP or TCP
    
    const ipHdr = [
      0x45, 0x00,
      (ipTotalLen >> 8) & 0xff, ipTotalLen & 0xff,
      0x1c, 0x9d, 0x00, 0x00,
      0x40, ipProto,
      0x00, 0x00, // Checksum placeholder
      ...ipSrc,
      ...ipDst
    ];

    // Checksum for IP
    let ipSum = 0;
    for (let i = 0; i < 20; i += 2) {
      ipSum += (ipHdr[i] << 8) + ipHdr[i + 1];
    }
    while (ipSum >> 16) {
      ipSum = (ipSum & 0xffff) + (ipSum >> 16);
    }
    const ipChecksum = (~ipSum) & 0xffff;
    ipHdr[10] = (ipChecksum >> 8) & 0xff;
    ipHdr[11] = ipChecksum & 0xff;

    // Transport Layer: UDP (8B) or TCP (20B) on port 646
    let l4Hdr = [];
    if (isUdp) {
      const udpLen = 8 + pduBytes.length;
      l4Hdr = [
        0x02, 0x86, // Src Port: 646 (LDP)
        0x02, 0x86, // Dst Port: 646 (LDP)
        (udpLen >> 8) & 0xff, udpLen & 0xff,
        0x00, 0x00  // UDP Checksum optional
      ];
    } else {
      l4Hdr = [
        0x02, 0x86, // Src Port: 646
        0x02, 0x86, // Dst Port: 646
        0x00, 0x00, 0x00, 0x01, // Seq
        0x00, 0x00, 0x00, 0x01, // Ack
        0x50, 0x18, // Header length (20 bytes), Flags: ACK, PSH
        0x72, 0x10, // Window size
        0x00, 0x00, // Checksum
        0x00, 0x00  // Urgent ptr
      ];
    }

    const packetPayload = [...ethHdr, ...ipHdr, ...l4Hdr, ...pduBytes];
    const packetLen = packetPayload.length;

    // PCAP Global Header (24 bytes)
    const pcapGlobalHeader = [
      0xd4, 0xc3, 0xb2, 0xa1, // Magic Number
      0x02, 0x00, 0x04, 0x00, // Version 2.4
      0x00, 0x00, 0x00, 0x00, // Timezone GMT
      0x00, 0x00, 0x00, 0x00, // Sigfigs
      0x00, 0x00, 0x04, 0x00, // Snaplen 262144
      0x01, 0x00, 0x00, 0x00  // LinkType Ethernet (1)
    ];

    // PCAP Record Header (16 bytes)
    const nowSec = Math.floor(Date.now() / 1000);
    const pcapRecordHeader = [
      nowSec & 0xff, (nowSec >> 8) & 0xff, (nowSec >> 16) & 0xff, (nowSec >> 24) & 0xff,
      0x00, 0x00, 0x00, 0x00,
      packetLen & 0xff, (packetLen >> 8) & 0xff, (packetLen >> 16) & 0xff, (packetLen >> 24) & 0xff,
      packetLen & 0xff, (packetLen >> 8) & 0xff, (packetLen >> 16) & 0xff, (packetLen >> 24) & 0xff
    ];

    return new Uint8Array([...pcapGlobalHeader, ...pcapRecordHeader, ...packetPayload]);
  }

  return {
    MSG_TYPES,
    TLV_TYPES,
    RESERVED_LABELS,
    forgePacket,
    formatHexDump,
    diagnoseLdpIgpSync,
    evaluatePhpPolicy,
    generateLfibTable,
    generatePcap,
    parseIpv4
  };
}));
