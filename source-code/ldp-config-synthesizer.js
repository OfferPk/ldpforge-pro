/**
 * LDPForge Pro - Multi-Platform MPLS LDP Configuration Synthesizer
 * 
 * Synthesizes production-hardened configurations for Cisco IOS-XE, Cisco IOS-XR,
 * Juniper Junos, Arista EOS, Linux FRRouting (ldpd), and Prometheus alerting rules.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LDPConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(params) {
    const lsrId = params.lsrId || '10.254.0.1';
    const authKey = params.authKey || 'Ldp$ecureMpl$2026!';
    const phpMode = params.phpMode || 'EXPLICIT_NULL';
    const explicitNull = (phpMode === 'EXPLICIT_NULL');

    return `! ==============================================================================
! Cisco IOS-XE Production-Hardened MPLS LDP Configuration
! Standards: RFC 5036 (LDP), RFC 5443 (LDP-IGP Sync), RFC 3478 (Graceful Restart)
! ==============================================================================

! 1. Pinned Deterministic LSR-ID
mpls ip
mpls ldp router-id Loopback0 force

! 2. Label Allocation Control (Host Routes /32 Only)
ip access-list standard ACL-LDP-HOST-ROUTES
 permit 10.254.0.0 0.0.255.255
 deny any
!
no mpls ldp label allocate global
mpls ldp label allocate global host-routes

! 3. LDP Session Protection & Targeted Sessions
mpls ldp session-protection
mpls ldp graceful-restart

! 4. Penultimate Hop Popping (PHP) & Explicit Null Policy
${explicitNull ? 'mpls ldp explicit-null' : '! Default Implicit Null (Label 3) active'}

! 5. LDP TCP Port 646 Cryptographic MD5 Authentication
mpls ldp password required
mpls ldp neighbor 10.254.0.2 password ${authKey}

! 6. Interface Configuration & LDP-IGP Synchronization
interface GigabitEthernet0/0/1
 description MPLS-CORE-LINK-TO-PEER
 ip address 10.100.0.1 255.255.255.252
 mpls ip
 mpls ldp sync
 bfd interval 50 min_rx 50 multiplier 3
 mpls ldp bfd
!
router ospf 1
 router-id ${lsrId}
 mpls ldp sync
 mpls ldp autoconfig
`;
  }

  function synthesizeCiscoIosXr(params) {
    const lsrId = params.lsrId || '10.254.0.1';
    const authKey = params.authKey || 'Ldp$ecureMpl$2026!';
    const phpMode = params.phpMode || 'EXPLICIT_NULL';

    return `! ==============================================================================
! Cisco IOS-XR Carrier Core MPLS LDP Configuration
! ==============================================================================
mpls ldp
 router-id ${lsrId}
 session protection
 graceful-restart
 ${phpMode === 'EXPLICIT_NULL' ? 'explicit-null' : '! implicit-null default'}
 igp sync delay on-session-up 10
 address-family ipv4
  label
   allocate for host-routes
  !
 !
 neighbor 10.254.0.2:0
  password encrypted ${authKey}
 !
 interface GigabitEthernet0/0/0/1
  bfd fast-detect
  igp sync delay 5
 !
!
router ospf 1
 router-id ${lsrId}
 mpls ldp sync
 mpls ldp auto-config
`;
  }

  function synthesizeJuniperJunos(params) {
    const lsrId = params.lsrId || '10.254.0.1';
    const authKey = params.authKey || 'Ldp$ecureMpl$2026!';
    const phpMode = params.phpMode || 'EXPLICIT_NULL';

    return `# ==============================================================================
# Juniper Junos OS Production MPLS LDP Configuration
# ==============================================================================
set protocols ldp interface ge-0/0/1.0
set protocols ldp interface lo0.0
set protocols ldp session-protection
set protocols ldp graceful-restart
${phpMode === 'EXPLICIT_NULL' ? 'set protocols ldp explicit-null' : '# default implicit-null active'}

# Cryptographic TCP Session Authentication
set protocols ldp session 10.254.0.2 authentication-key "${authKey}"

# Sub-Second Link Detection (BFD)
set protocols ldp interface ge-0/0/1.0 bfd-liveness-detection minimum-interval 50
set protocols ldp interface ge-0/0/1.0 bfd-liveness-detection multiplier 3

# RFC 5443 LDP-IGP Synchronization
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 ldp-synchronization
`;
  }

  function synthesizeAristaEos(params) {
    const lsrId = params.lsrId || '10.254.0.1';
    const authKey = params.authKey || 'Ldp$ecureMpl$2026!';

    return `! ==============================================================================
! Arista EOS Enterprise MPLS LDP Configuration
! ==============================================================================
mpls ip
!
mpls ldp
 router-id Loopback0
 session-protection
 neighbor 10.254.0.2 password 7 ${authKey}
 transport-address interface Loopback0
!
interface Ethernet1
 description MPLS-UPLINK
 no switchport
 ip address 10.100.0.1/30
 mpls ip
 mpls ldp igp sync
 mpls ldp bfd
`;
  }

  function synthesizeLinuxFRR(params) {
    const lsrId = params.lsrId || '10.254.0.1';
    const authKey = params.authKey || 'Ldp$ecureMpl$2026!';

    return `! ==============================================================================
! Linux FRRouting (FRR ldpd) Production Configuration
! File: /etc/frr/ldpd.conf
! ==============================================================================
mpls ldp
 router-id ${lsrId}
 dual-stack transport-connection prefer ipv4
 !
 address-family ipv4
  discovery hello interval 5
  discovery hello holdtime 15
  label local allocate host-routes
  !
  interface eth0
  !
 !
 neighbor 10.254.0.2 password ${authKey}
!
`;
  }

  function synthesizePrometheusAlerts(params) {
    return `# ==============================================================================
# Prometheus Alerting Rules for MPLS LDP & RFC 5443 Synchronization
# ==============================================================================
groups:
  - name: mpls_ldp_monitoring
    rules:
      - alert: LDPSessionDown
        expr: cisco_mpls_ldp_session_state != 5
        for: 15s
        labels:
          severity: critical
          tier: transport_mpls
        annotations:
          summary: "MPLS LDP Session Down (instance {{ $labels.instance }})"
          description: "LDP session to peer {{ $labels.peer_lsr_id }} is not in Operational state."

      - alert: LDPIGPSyncMismatch
        expr: (ospf_interface_ldp_sync_state == 0) and (ospf_interface_state == 1)
        for: 30s
        labels:
          severity: page
          tier: transport_mpls
        annotations:
          summary: "LDP-IGP Sync Blackhole Hazard on {{ $labels.interface }}"
          description: "Interface is UP in IGP but LDP is not synchronized, risking customer traffic blackhole."

      - alert: LDPLabelBindingDrop
        expr: rate(mpls_ldp_label_mapping_drops_total[2m]) > 0
        for: 1m
        labels:
          severity: warning
          tier: transport_mpls
        annotations:
          summary: "MPLS LDP Label Mapping Drops Detected"
          description: "Router is dropping incoming LDP label mappings due to filtering or memory exhaustion."
`;
  }

  return {
    synthesizeCiscoIosXe,
    synthesizeCiscoIosXr,
    synthesizeJuniperJunos,
    synthesizeAristaEos,
    synthesizeLinuxFRR,
    synthesizePrometheusAlerts
  };
}));
