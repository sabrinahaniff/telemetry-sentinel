/**
 * alerts.js
 * Formats alerts and broadcasts them to all connected plugin clients.
 */

const SEVERITY_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };

class AlertManager {
  constructor() {
    this.clients = new Set();  // connected OpenMCT plugin WebSocket clients
    this.history = [];         // keep last 100 alerts in memory
  }

  // Register a new plugin client connection
  addClient(ws) {
    this.clients.add(ws);
    // Send alert history to newly connected client
    ws.send(JSON.stringify({ type: 'history', alerts: this.history }));
    ws.on('close', () => this.clients.delete(ws));
    console.log(`Alert client connected. Total clients: ${this.clients.size}`);
  }

  // Format and broadcast a list of raw alerts from detector
  dispatch(rawAlerts, telemetrySnapshot) {
    if (!rawAlerts.length) return;

    const formatted = rawAlerts.map(alert => ({
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      severity: alert.severity,
      severityRank: SEVERITY_RANK[alert.severity] ?? 0,
      category: alert.category,
      field: alert.field,
      value: alert.value,
      message: alert.message,
      snapshot: telemetrySnapshot,  // attach the offending packet for context
    }));

    // Store in history (keep max 100)
    this.history.push(...formatted);
    if (this.history.length > 100) {
      this.history = this.history.slice(-100);
    }

    // Broadcast to all connected plugin clients
    const payload = JSON.stringify({ type: 'alerts', alerts: formatted });
    this.clients.forEach(client => {
      if (client.readyState === 1) { // 1 = OPEN
        client.send(payload);
      }
    });

    // Log to console with severity colour
    formatted.forEach(a => {
      const colour = a.severity === 'CRITICAL' ? '\x1b[31m' :
                     a.severity === 'HIGH'     ? '\x1b[33m' :
                                                 '\x1b[36m';
      console.log(`${colour}[${a.severity}]\x1b[0m [${a.category}] ${a.message}`);
    });
  }
}

module.exports = AlertManager;