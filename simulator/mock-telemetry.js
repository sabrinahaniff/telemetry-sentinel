/**
 * mock-telemetry.js
 * Simulates a rocket's telemetry data stream.
 * Also includes attack scenarios you can trigger to test your detector.
 *
 * Run: node simulator/mock-telemetry.js
 */

const WebSocket = require('ws');

const PORT = 8081;
const wss = new WebSocket.Server({ port: PORT });

console.log(`Mock telemetry server running on ws://localhost:${PORT}`);

//  Normal telemetry state 
let state = {
  timestamp: Date.now(),
  temperature: 22,       // degrees C - engine temp
  pressure: 101.3,       // kPa - chamber pressure
  altitude: 0,           // meters
  velocity: 0,           // m/s
  fuelLevel: 100,        // percentage
  batteryVoltage: 28.5,  // volts
};

// Simulate a slow rocket ascent
function updateState() {
  state.timestamp = Date.now();
  state.altitude    += Math.random() * 10 + 5;
  state.velocity    += Math.random() * 2;
  state.temperature += (Math.random() - 0.4) * 0.5;
  state.pressure    = 101.3 - (state.altitude * 0.01);
  state.fuelLevel   = Math.max(0, state.fuelLevel - 0.05);
  state.batteryVoltage += (Math.random() - 0.5) * 0.1;
}

// Broadcast telemetry to all connected clients
function broadcast(data) {
  const payload = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

// Normal telemetry loop (every 500ms)
const normalLoop = setInterval(() => {
  updateState();
  broadcast({ type: 'telemetry', data: { ...state } });
}, 500);


// Attack 1 (A03 Injection): inject a script tag into a telemetry field
setTimeout(() => {
  console.log('[ATTACK] Firing A03 Injection attack...');
  broadcast({
    type: 'telemetry',
    data: {
      ...state,
      temperature: '<script>alert("xss")</script>',
    }
  });
}, 10000); // fires 10s after start

// Attack 2, Physics violation: temperature jumps impossibly fast
setTimeout(() => {
  console.log('[ATTACK] Firing physics violation: temperature spike...');
  broadcast({
    type: 'telemetry',
    data: { ...state, temperature: 9500 }
  });
}, 20000); // fires 20s after start

// Attack 3, Sensor flatline: same value 10 times (spoofed/frozen sensor)
setTimeout(() => {
  console.log('[ATTACK] Firing flatline attack (frozen sensor)...');
  let count = 0;
  const flatline = setInterval(() => {
    broadcast({
      type: 'telemetry',
      data: { ...state, pressure: 55.555 }  // exact same value every time
    });
    if (++count >= 10) clearInterval(flatline);
  }, 300);
}, 30000); // fires 30s after start

// Attack 4 (A01 Broken Access Control): unknown field names in packet
setTimeout(() => {
  console.log('[ATTACK] Firing unknown schema field attack...');
  broadcast({
    type: 'telemetry',
    data: {
      ...state,
      __proto__: 'polluted',          // prototype pollution attempt
      adminOverride: true,            // undeclared field
      selfDestructSequence: 'alpha',  // definitely not normal
    }
  });
}, 40000); // fires 40s after start

wss.on('connection', (ws) => {
  console.log('Client connected to mock telemetry server');
  ws.on('close', () => console.log('Client disconnected'));
});