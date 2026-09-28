"""Additional dashboard CSS for components used by the pages."""

EXTRA_CSS = """
<style>

.metric-card {
    position: relative;
    background: #0c131d;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 18px 16px 22px;
    overflow: hidden;
    margin-bottom: 6px;
}

.metric-accent {
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 4px;
    background: var(--accent);
}

.metric-title {
    color: #68778b;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
}

.metric-value {
    font-size: 26px;
    font-weight: 700;
    margin-top: 6px;
    color: var(--accent);
}

.metric-subtitle {
    color: var(--muted);
    font-size: 11px;
    margin-top: 3px;
}

.section-header { margin: 6px 0 14px 0; }
.section-header h2 { font-size: 19px; margin: 0; letter-spacing: -.4px; }
.section-header p { color: var(--muted); font-size: 12px; margin: 4px 0 0 0; }

.severity-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: .8px;
    border: 1px solid;
}
.severity-badge.critical { color:#ef4444; border-color:#7f1d1d; background:#2a1114; }
.severity-badge.high     { color:#fb923c; border-color:#7c3a12; background:#2a1a0f; }
.severity-badge.medium   { color:#facc15; border-color:#6b5a0c; background:#262109; }
.severity-badge.low      { color:#38bdf8; border-color:#155e75; background:#0b2230; }
.severity-badge.secure   { color:#22c55e; border-color:#14532d; background:#0b2416; }

.status-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: 'JetBrains Mono', monospace; font-size: 10px;
}
.status-online { color: var(--green); }
.status-offline { color: var(--red); }

.hero-panel {
    display: flex; justify-content: space-between; align-items: center;
    border: 1px solid var(--border);
    background: linear-gradient(120deg, rgba(56,189,248,.055), transparent 45%), #0b111a;
    border-radius: 16px; padding: 26px 30px;
}
.hero-panel h1 { margin: 0; font-size: 27px; letter-spacing: -.7px; }
.hero-panel p { color: var(--muted); max-width: 640px; margin: 8px 0 0 0; }
.hero-status { text-align: right; }
.hero-status-label { color: #68778b; font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 1.4px; }
.hero-status-value { font-size: 30px; font-weight: 800; color: var(--cyan); }
.hero-status-score { color: var(--muted); font-family: 'JetBrains Mono', monospace; }

.risk-gauge { text-align: center; padding: 10px 0 14px 0; }
.risk-number { font-size: 56px; font-weight: 800; line-height: 1; }
.risk-label { color: var(--muted); font-family: 'JetBrains Mono', monospace; }
.risk-track { height: 10px; background: #111c29; border-radius: 99px; margin: 14px 8% 8px 8%; overflow: hidden; }
.risk-fill { height: 100%; background: linear-gradient(90deg, #22c55e, #facc15, #ef4444); }
.risk-caption { color: var(--muted); font-size: 11px; }

.empty-state {
    text-align: center; padding: 60px 20px;
    border: 1px dashed var(--border2); border-radius: 16px; background: #0a1019;
}
.empty-icon { font-size: 36px; color: var(--cyan); }

.chain {
    display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 10px 0 4px 0;
}
.chain-node {
    padding: 5px 12px; border-radius: 8px; font-size: 11px;
    background: #0d1a27; border: 1px solid #254057;
    font-family: 'JetBrains Mono', monospace;
}
.chain-node.end { border-color: #7f1d1d; color: #ef4444; background: #2a1114; }
.chain-arrow { color: #4b6178; }

.kv { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--muted); }
.kv b { color: var(--text); }

.pass-tag { color: #22c55e; font-family: 'JetBrains Mono', monospace; font-weight: 600; }
.fail-tag { color: #ef4444; font-family: 'JetBrains Mono', monospace; font-weight: 600; }

</style>
"""
