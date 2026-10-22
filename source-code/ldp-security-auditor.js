/**
 * LDPForge Pro - 10-Point Zero-Trust MPLS Control Plane (LDP) Security Auditor
 * 
 * Evaluates network configurations against RFC 5036, RFC 5443, RFC 3478, and carrier-grade MPLS hardening standards.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LDPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_CONTROLS = [
    {
      id: 'LDP-SEC-01',
      title: 'RFC 5036 TCP 646 Session Cryptographic Authentication',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.authMode === 'TCP_AO' || cfg.authMode === 'MD5') {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: `Cryptographic session authentication (${cfg.authMode}) active on TCP port 646.`,
            remediation: 'Compliant. Prevents rogue LDP peering and TCP RST spoofing attacks.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'Unauthenticated LDP Peering: TCP port 646 is exposed without MD5 or TCP-AO protection.',
          remediation: 'Configure `mpls ldp password <KEY>` (Cisco) or `set protocols ldp authentication-key <KEY>` (Junos) to thwart LSP spoofing.'
        };
      }
    },
    {
      id: 'LDP-SEC-02',
      title: 'RFC 5443 LDP-IGP Synchronization (Blackhole Shield)',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.ldpIgpSync) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'RFC 5443 LDP-IGP Synchronization enabled on all core links.',
            remediation: 'Compliant. Holds IGP metric at 65535 until LDP session is Operational, eliminating transit traffic blackholes.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL HAZARD: LDP-IGP Sync is disabled. Transit links advertise normal IGP metric before LDP finishes label exchange.',
          remediation: 'Enable `mpls ldp sync` under OSPF/IS-IS router configuration to avoid catastrophic drops on link recovery.'
        };
      }
    },
    {
      id: 'LDP-SEC-03',
      title: 'LDP Session Protection & Targeted LDP (tLDP)',
      maxPoints: 12,
      evaluate: function (cfg) {
        if (cfg.sessionProtection) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'LDP Session Protection active with multi-hop targeted Hellos.',
            remediation: 'Compliant. Keeps LDP session and label bindings alive during transient physical link flaps.'
          };
        }
        return {
          passed: false,
          score: 3,
          level: 'WARN',
          finding: 'Missing LDP Session Protection: Physical link flap will immediately tear down LDP session and flush LIB.',
          remediation: 'Configure `mpls ldp session-protection` (Cisco) or `set protocols ldp session-protection` (Junos).'
        };
      }
    },
    {
      id: 'LDP-SEC-04',
      title: 'Label Allocation & Distribution Filtering (/32 Host Routes)',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.labelFiltering) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Label allocation policy restricted to Loopback /32 host routes.',
            remediation: 'Compliant. Prevents LFIB table bloat and unnecessary label allocation for transit /30 and LAN subnets.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Unrestricted Label Allocation: Allocating MPLS labels for all IGP prefixes (including /30 and user LANs).',
          remediation: 'Apply `mpls ldp label allocate global host-routes` or ACL-based label allocation filtering.'
        };
      }
    },
    {
      id: 'LDP-SEC-05',
      title: 'RFC 3478 Graceful Restart / Helper Mode',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.gracefulRestart) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'RFC 3478 Graceful Restart enabled on LSR.',
            remediation: 'Compliant. Preserves forwarding state in hardware FIB across control plane reloads.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Graceful Restart disabled. Route processor switchovers cause immediate LSP teardown and traffic drop.',
          remediation: 'Configure `mpls ldp graceful-restart` to preserve forwarding plane continuity.'
        };
      }
    },
    {
      id: 'LDP-SEC-06',
      title: 'Penultimate Hop Popping (PHP) Policy & QoS Preservation',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.phpMode === 'EXPLICIT_NULL' || (cfg.phpMode === 'IMPLICIT_NULL' && !cfg.qosPreservationRequired)) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: `PHP policy correctly aligned: ${cfg.phpMode}. EXP/QoS bits handled as required.`,
            remediation: 'Compliant. Explicit Null (Label 0) preserves 3-bit EXP field to egress PE.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Implicit Null (Label 3) strips MPLS header upstream, discarding EXP/QoS bits before egress classification.',
          remediation: 'Configure `mpls ldp explicit-null` (or Junos `set protocols ldp explicit-null`) when egress DiffServ QoS is required.'
        };
      }
    },
    {
      id: 'LDP-SEC-07',
      title: 'Deterministic LSR-ID (Loopback0 /32) Binding',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.deterministicLsrId) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'LSR-ID strictly pinned to stable Loopback0 /32 address with `force` parameter.',
            remediation: 'Compliant. Eliminates transport address flapping when physical interfaces bounce.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'LSR-ID dynamically derived or missing `force` keyword. Vulnerable to renumbering on interface state changes.',
          remediation: 'Explicitly configure `mpls ldp router-id Loopback0 force`.'
        };
      }
    },
    {
      id: 'LDP-SEC-08',
      title: 'Control Plane Policing (CoPP) for Port 646 (UDP & TCP)',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.coppActive) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'Hardware CoPP filter policing UDP discovery and TCP session traffic on port 646.',
            remediation: 'Compliant. Protects Route Processor CPU from unauthorized LDP flood attacks.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'Unpoliced Control Plane: Port 646 packets punted to supervisor CPU without rate limits.',
          remediation: 'Apply CoPP policy-map policing UDP 646 and TCP 646 traffic to trusted peer addresses.'
        };
      }
    },
    {
      id: 'LDP-SEC-09',
      title: 'Sub-Second Link Failure Detection (BFD for LDP)',
      maxPoints: 7,
      evaluate: function (cfg) {
        if (cfg.bfdEnabled) {
          return {
            passed: true,
            score: 7,
            level: 'PASS',
            finding: 'Bidirectional Forwarding Detection (BFD) enabled for LDP adjacencies (sub-50ms fault detection).',
            remediation: 'Compliant. Overcomes standard 15-second LDP Hello hold time.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Standard LDP Hello Hold Time (15s). Convergence on un-signaled optical link failure will take seconds.',
          remediation: 'Configure BFD for LDP (`mpls ldp bfd` / `set protocols ldp bfd-liveness-detection`).'
        };
      }
    },
    {
      id: 'LDP-SEC-10',
      title: 'Ordered Label Control Mode Enforced',
      maxPoints: 7,
      evaluate: function (cfg) {
        if (cfg.orderedControl) {
          return {
            passed: true,
            score: 7,
            level: 'PASS',
            finding: 'Ordered Label Control mode active. Labels allocated only when downstream mapping exists.',
            remediation: 'Compliant. Prevents transient forwarding blackholes during LSP establishment.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Independent Label Control: Router advertises labels before verifying downstream reachability.',
          remediation: 'Ensure Ordered Label Control mode is active across all MPLS LSRs.'
        };
      }
    }
  ];

  function auditConfiguration(cfg) {
    let totalScore = 0;
    const findings = [];

    AUDIT_CONTROLS.forEach(ctrl => {
      const result = ctrl.evaluate(cfg);
      totalScore += result.score;
      findings.push({
        id: ctrl.id,
        title: ctrl.title,
        maxPoints: ctrl.maxPoints,
        score: result.score,
        level: result.level,
        passed: result.passed,
        finding: result.finding,
        remediation: result.remediation
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 60) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      passed: totalScore >= 80,
      findings: findings,
      evaluatedAt: new Date().toISOString()
    };
  }

  return {
    AUDIT_CONTROLS,
    auditConfiguration
  };
}));
