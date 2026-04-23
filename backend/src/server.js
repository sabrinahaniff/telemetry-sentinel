/**
 * server.js
 * Main backend server.
 *
 * - Connects to the mock telemetry WebSocket as a client
 * - Passes every packet through the detector
 * - Serves alerts to the OpenMCT plugin via a separate WebSocket
 *
 * Run: node backend/src/server.js
 */

const WebSocket = require('ws');
const TelemetryDetector = require('./detector');
const AlertManager = require('./alerts');

// config
const TELEMETRY_SOURCE = 'ws://localhost:8081';  // mock telemetry server
const ALERT_SERVER_PORT = 8082;                  // plugin connects here

// init
const detector = new TelemetryDetector();
const alertManager = new AlertManager();

// alert WebSocket server 
const alertServer = new WebSocket.Server({ port: ALERT_SERVER_PORT });
console.log(`Alert server running on ws://localhost:${ALERT_SERVER_PORT}`);

alertServer.on('connection', (ws, req) => {
  // OWASP A01: Basic origin check
  const origin = req.headers.origin || '';
  const allowed = ['http://localhost:8080', 'http://localhost:8081'];

  if (origin && !allowed.includes(origin)) {
    console.warn(`[SECURITY] Rejected connection from unknown origin: ${origin}`);
    ws.close(1008, 'Origin not allowed');
    return;
  }

  alertManager.addClient(ws);
});

// connect to telemetry source
function connectToTelemetry() {
  console.log(`Connecting to telemetry source at ${TELEMETRY_SOURCE}...`);
  const telemetrySocket = new WebSocket(TELEMETRY_SOURCE);

  telemetrySocket.on('open', () => {
    console.log('Connected to telemetry source. Monitoring started.');
  });

  telemetrySocket.on('message', (raw) => {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      console.error('Failed to parse telemetry message:', e.message);
      return;
    }

    if (parsed.type !== 'telemetry') return;

    const data = parsed.data;
    const alerts = detector.analyze(data);
    alertManager.dispatch(alerts, data);
  });

  telemetrySocket.on('close', () => {
    console.log('Telemetry connection closed. Reconnecting in 3s...');
    setTimeout(connectToTelemetry, 3000);
  });

  telemetrySocket.on('error', (err) => {
    console.error('Telemetry connection error:', err.message);
  });
}

connectToTelemetry();