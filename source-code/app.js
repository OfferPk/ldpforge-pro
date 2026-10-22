/**
 * LDPForge Pro - Web Studio Controller & Preset Manager
 */

(function () {
  'use strict';

  const PRESETS = {
    'carrier-backbone': {
      lsrId: '10.254.0.1',
      labelSpace: 0,
      msgType: 1024, // Label Mapping
      messageId: 1001,
      fecPrefix: '10.100.0.0',
      fecPrefixLen: 24,
      assignedLabel: 16001,
      authMode: 'MD5',
      authKey: 'CarrierLdp$ecure2026!',
      phpMode: 'EXPLICIT_NULL',
      igpSyncEnabled: true,
      linkStatus: 'UP',
      ldpSessionState: 'OPERATIONAL',
      transitTrafficMbps: 1000,
      sessionProtection: true,
      labelFiltering: true,
      gracefulRestart: true,
      deterministicLsrId: true,
      coppActive: true,
      bfdEnabled: true,
      orderedControl: true,
      qosPreservationRequired: true
    },
    'enterprise-wan': {
      lsrId: '10.200.0.1',
      labelSpace: 0,
      msgType: 1024,
      messageId: 2001,
      fecPrefix: '10.200.1.0',
      fecPrefixLen: 24,
      assignedLabel: 0, // Explicit Null
      authMode: 'TCP_AO',
      authKey: 'EnterpriseWan$AO2026',
      phpMode: 'EXPLICIT_NULL',
      igpSyncEnabled: true,
      linkStatus: 'UP',
      ldpSessionState: 'OPERATIONAL',
      transitTrafficMbps: 2500,
      sessionProtection: true,
      labelFiltering: true,
      gracefulRestart: true,
      deterministicLsrId: true,
      coppActive: true,
      bfdEnabled: true,
      orderedControl: true,
      qosPreservationRequired: true
    },
    'vulnerable-blackhole': {
      lsrId: '192.168.1.1',
      labelSpace: 0,
      msgType: 256, // Hello
      messageId: 501,
      fecPrefix: '192.168.0.0',
      fecPrefixLen: 16,
      assignedLabel: 3, // Implicit Null
      authMode: 'NONE',
      authKey: '',
      phpMode: 'IMPLICIT_NULL',
      igpSyncEnabled: false,
      linkStatus: 'UP',
      ldpSessionState: 'INITIALIZING', // Triggers Blackhole
      transitTrafficMbps: 5000,
      sessionProtection: false,
      labelFiltering: false,
      gracefulRestart: false,
      deterministicLsrId: false,
      coppActive: false,
      bfdEnabled: false,
      orderedControl: false,
      qosPreservationRequired: true
    }
  };

  let currentConfig = Object.assign({}, PRESETS['carrier-backbone']);
  let activeTab = 'cisco-ios-xe';
  let forgedPacketCache = null;

  // DOM Elements
  const inputLsrId = document.getElementById('input-lsr-id');
  const inputLabelSpace = document.getElementById('input-label-space');
  const selectMsgType = document.getElementById('select-msg-type');
  const inputMsgId = document.getElementById('input-msg-id');
  const inputFecPrefix = document.getElementById('input-fec-prefix');
  const inputFecLen = document.getElementById('input-fec-len');
  const selectPhpMode = document.getElementById('select-php-mode');
  const selectAuthMode = document.getElementById('select-auth-mode');

  const selectSyncEnabled = document.getElementById('select-sync-enabled');
  const selectLinkStatus = document.getElementById('select-link-status');
  const selectLdpState = document.getElementById('select-ldp-state');
  const inputTrafficRate = document.getElementById('input-traffic-rate');

  const syncDiagBanner = document.getElementById('sync-diag-banner');
  const syncDiagTitle = document.getElementById('sync-diag-title');
  const syncDiagDesc = document.getElementById('sync-diag-desc');

  const phpDiagBanner = document.getElementById('php-diag-banner');
  const phpDiagTitle = document.getElementById('php-diag-title');
  const phpDiagDesc = document.getElementById('php-diag-desc');
  const badgePhpType = document.getElementById('badge-php-type');
  const badgePduLen = document.getElementById('badge-pdu-len');

  const auditGradeCircle = document.getElementById('audit-grade-circle');
  const auditScoreText = document.getElementById('audit-score-text');
  const auditComplianceText = document.getElementById('audit-compliance-text');
  const auditScoreBar = document.getElementById('audit-score-bar');
  const auditStatusBadge = document.getElementById('audit-status-badge');
  const findingsContainer = document.getElementById('findings-container');

  const hexDissectorBox = document.getElementById('hex-dissector-box');
  const synthesizerOutputBox = document.getElementById('synthesizer-output-box');

  const btnCopyHex = document.getElementById('btn-copy-hex');
  const btnDownloadPcap = document.getElementById('btn-download-pcap');
  const btnCopyConfig = document.getElementById('btn-copy-config');
  const presetButtons = document.querySelectorAll('.btn-preset');
  const tabButtons = document.querySelectorAll('.tab-btn');

  function updateUiFromConfig() {
    inputLsrId.value = currentConfig.lsrId;
    inputLabelSpace.value = currentConfig.labelSpace;
    selectMsgType.value = currentConfig.msgType;
    inputMsgId.value = currentConfig.messageId;
    inputFecPrefix.value = currentConfig.fecPrefix;
    inputFecLen.value = currentConfig.fecPrefixLen;
    selectPhpMode.value = currentConfig.phpMode;
    selectAuthMode.value = currentConfig.authMode;

    selectSyncEnabled.value = currentConfig.igpSyncEnabled ? 'true' : 'false';
    selectLinkStatus.value = currentConfig.linkStatus;
    selectLdpState.value = currentConfig.ldpSessionState;
    inputTrafficRate.value = currentConfig.transitTrafficMbps;

    recomputeAll();
  }

  function readConfigFromUi() {
    currentConfig.lsrId = inputLsrId.value.trim() || '10.254.0.1';
    currentConfig.labelSpace = parseInt(inputLabelSpace.value, 10) || 0;
    currentConfig.msgType = parseInt(selectMsgType.value, 10);
    currentConfig.messageId = parseInt(inputMsgId.value, 10) || 1001;
    currentConfig.fecPrefix = inputFecPrefix.value.trim() || '10.100.0.0';
    currentConfig.fecPrefixLen = parseInt(inputFecLen.value, 10) || 24;
    currentConfig.phpMode = selectPhpMode.value;
    currentConfig.authMode = selectAuthMode.value;

    currentConfig.igpSyncEnabled = (selectSyncEnabled.value === 'true');
    currentConfig.linkStatus = selectLinkStatus.value;
    currentConfig.ldpSessionState = selectLdpState.value;
    currentConfig.transitTrafficMbps = parseInt(inputTrafficRate.value, 10) || 1000;

    if (currentConfig.phpMode === 'EXPLICIT_NULL') {
      currentConfig.assignedLabel = 0;
    } else if (currentConfig.phpMode === 'IMPLICIT_NULL') {
      currentConfig.assignedLabel = 3;
    } else {
      currentConfig.assignedLabel = 16001;
    }

    recomputeAll();
  }

  function recomputeAll() {
    // 1. Forge Packet & Hex Dump
    const packetConfig = {
      lsrId: currentConfig.lsrId,
      labelSpace: currentConfig.labelSpace,
      msgType: currentConfig.msgType,
      messageId: currentConfig.messageId,
      holdTime: 15,
      keepaliveTime: 180,
      fecPrefix: currentConfig.fecPrefix,
      fecPrefixLen: currentConfig.fecPrefixLen,
      assignedLabel: currentConfig.assignedLabel,
      transportAddr: currentConfig.lsrId
    };

    forgedPacketCache = LDPProtocolEngine.forgePacket(packetConfig);
    badgePduLen.textContent = `PDU: ${forgedPacketCache.totalLength}B`;
    hexDissectorBox.textContent = LDPProtocolEngine.formatHexDump(forgedPacketCache.rawBytes);

    // 2. LDP-IGP Sync Diagnostic
    const syncDiag = LDPProtocolEngine.diagnoseLdpIgpSync({
      igpSyncEnabled: currentConfig.igpSyncEnabled,
      linkStatus: currentConfig.linkStatus,
      ldpSessionState: currentConfig.ldpSessionState,
      igpNormalMetric: 10,
      transitTrafficBps: currentConfig.transitTrafficMbps * 1000000
    });

    syncDiagTitle.textContent = syncDiag.title;
    syncDiagDesc.textContent = syncDiag.description;
    syncDiagBanner.className = 'diag-banner ' + (
      syncDiag.status === 'FATAL_BLACKHOLE' ? 'diag-critical' :
      syncDiag.status === 'PROTECTED_SYNC' ? 'diag-protected' : 'diag-healthy'
    );

    // 3. PHP Diagnostic
    const phpDiag = LDPProtocolEngine.evaluatePhpPolicy(
      currentConfig.phpMode,
      currentConfig.qosPreservationRequired
    );
    badgePhpType.textContent = phpDiag.labelType.split(' ')[0] + ' ' + phpDiag.labelValue;
    phpDiagTitle.textContent = phpDiag.summary;
    phpDiagDesc.textContent = phpDiag.impact;
    phpDiagBanner.className = 'diag-banner ' + (
      phpDiag.grade === 'WARN' ? 'diag-critical' : 'diag-healthy'
    );

    // 4. Run 10-Point Zero-Trust Audit
    const audit = LDPSecurityAuditor.auditConfiguration({
      authMode: currentConfig.authMode,
      ldpIgpSync: currentConfig.igpSyncEnabled,
      sessionProtection: currentConfig.sessionProtection,
      labelFiltering: currentConfig.labelFiltering,
      gracefulRestart: currentConfig.gracefulRestart,
      phpMode: currentConfig.phpMode,
      qosPreservationRequired: currentConfig.qosPreservationRequired,
      deterministicLsrId: currentConfig.deterministicLsrId,
      coppActive: currentConfig.coppActive,
      bfdEnabled: currentConfig.bfdEnabled,
      orderedControl: currentConfig.orderedControl
    });

    auditScoreText.textContent = `${audit.score} / 100 Points`;
    auditGradeCircle.textContent = audit.grade;
    auditGradeCircle.className = `grade-circle grade-${audit.grade.toLowerCase().replace('+', 'plus')}`;
    auditScoreBar.style.width = `${audit.score}%`;

    if (audit.passed) {
      auditScoreBar.style.background = 'var(--primary-emerald)';
      auditComplianceText.textContent = 'Production Zero-Trust';
      auditComplianceText.style.color = 'var(--primary-emerald)';
      auditStatusBadge.textContent = 'PASSING';
      auditStatusBadge.className = 'badge badge-emerald';
    } else {
      auditScoreBar.style.background = 'var(--primary-rose)';
      auditComplianceText.textContent = 'Non-Compliant / Audit Failure';
      auditComplianceText.style.color = 'var(--primary-rose)';
      auditStatusBadge.textContent = 'CRITICAL FAILS';
      auditStatusBadge.className = 'badge badge-amber';
    }

    // Render findings
    findingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = `finding-item ${f.level.toLowerCase()}`;
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 0.2rem;">
          <span>[${f.level}] ${f.id} - ${f.title}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxPoints} pts</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.78rem;">${f.finding}</div>
      `;
      findingsContainer.appendChild(div);
    });

    // 5. Update Synthesizer Output
    renderSynthesizerConfig();
  }

  function renderSynthesizerConfig() {
    const synthParams = {
      lsrId: currentConfig.lsrId,
      authKey: currentConfig.authKey || 'Ldp$ecureMpl$2026!',
      phpMode: currentConfig.phpMode
    };

    let text = '';
    if (activeTab === 'cisco-ios-xe') {
      text = LDPConfigSynthesizer.synthesizeCiscoIosXe(synthParams);
    } else if (activeTab === 'cisco-ios-xr') {
      text = LDPConfigSynthesizer.synthesizeCiscoIosXr(synthParams);
    } else if (activeTab === 'juniper-junos') {
      text = LDPConfigSynthesizer.synthesizeJuniperJunos(synthParams);
    } else if (activeTab === 'arista-eos') {
      text = LDPConfigSynthesizer.synthesizeAristaEos(synthParams);
    } else if (activeTab === 'linux-frr') {
      text = LDPConfigSynthesizer.synthesizeLinuxFRR(synthParams);
    } else if (activeTab === 'prometheus') {
      text = LDPConfigSynthesizer.synthesizePrometheusAlerts(synthParams);
    }
    synthesizerOutputBox.textContent = text;
  }

  // Event Listeners
  [inputLsrId, inputLabelSpace, selectMsgType, inputMsgId, inputFecPrefix, inputFecLen, selectPhpMode, selectAuthMode,
   selectSyncEnabled, selectLinkStatus, selectLdpState, inputTrafficRate].forEach(el => {
    el.addEventListener('change', readConfigFromUi);
    el.addEventListener('input', readConfigFromUi);
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        currentConfig = Object.assign({}, PRESETS[presetKey]);
        updateUiFromConfig();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.getAttribute('data-tab');
      renderSynthesizerConfig();
    });
  });

  btnCopyHex.addEventListener('click', () => {
    navigator.clipboard.writeText(hexDissectorBox.textContent).then(() => {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(() => btnCopyHex.textContent = 'Copy Hex', 2000);
    });
  });

  btnCopyConfig.addEventListener('click', () => {
    navigator.clipboard.writeText(synthesizerOutputBox.textContent).then(() => {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(() => btnCopyConfig.textContent = 'Copy Config', 2000);
    });
  });

  btnDownloadPcap.addEventListener('click', () => {
    if (!forgedPacketCache) return;
    const isUdp = (currentConfig.msgType === LDPProtocolEngine.MSG_TYPES.HELLO);
    const pcapBytes = LDPProtocolEngine.generatePcap(forgedPacketCache, isUdp);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ldp-${currentConfig.lsrId}-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Initial load
  updateUiFromConfig();
})();
