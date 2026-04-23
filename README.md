# Telemetry Sentinel 

An OpenMCT plugin that adds a real-time security monitoring layer for [NASA's OpenMCT](https://github.com/nasa/openmct) mission control software. Detects aerospace anomalies and web security attacks in live rocket telemetry data displayed as live alerts directly inside the mission control dashboard.

![Telemetry Sentinel in action](./docs/screenshot.png)

---

## The Problem

NASA's OpenMCT is open-source software used by real mission control teams to monitor spacecraft and rockets. It displays live telemetry like temperature, pressure, altitude, fuel levels streaming from the vehicle in real time.

The real issue: **OpenMCT just displays the data. Nobody checks whether it makes physical sense or whether the data stream is being tampered with.** There is no security monitoring layer. This project mainly builds that specific layer.

---

## How It Works

```
Rocket / Spacecraft
        ↓
  Telemetry stream (WebSocket :8081)
        ↓
  OpenMCT dashboard (:8080)  ← displays raw data
        ↓
  Detection backend           ← ingests same stream
        ↓
  Two-layer anomaly detector  ← aerospace + OWASP rules
        ↓
  Alert Panel (OpenMCT plugin) ← live alerts in dashboard
```

---

## Two Detection Layers

### First Layer: Aerospace Anomaly Detection

| Check | What it catches |
|---|---|
| Physical limits | Values outside physically possible range (e.g. temperature at 9500°C) |
| Rate of change | Values changing impossibly fast between readings |
| Flatline detection | Sensor reporting the exact same value repeatedly = frozen or spoofed |

### Second Layer: OWASP Web Security

| OWASP ID | What it catches |
|---|---|
| A03 Injection | `<script>` tags, SQL, shell commands injected into telemetry fields |
| A01 Broken Access Control | Undeclared/unknown fields injected into telemetry packets |
| A05 Security Misconfiguration | Connections from unknown/unauthorized origins |

---

## Demo

The simulator fires four attacks automatically so you can watch the detector catch them live:

| Time | Attack | Type |
|---|---|---|
| 10s | `<script>alert("xss")</script>` injected into temperature field | OWASP A03 |
| 20s | Temperature jumps to 9500°C | Aerospace — physical limit |
| 30s | Pressure reports exact same value 10x in a row | Aerospace = flatline/spoofed sensor |
| 40s | `selfDestructSequence` and `adminOverride` injected as fake fields | OWASP A01 |

---

## Getting Started

### Prerequisites
- Node.js v24.14.1+ (use nvm)
- npm

### 1. Clone and set up OpenMCT
```bash
git clone https://github.com/nasa/openmct
cd openmct && npm install
```

### 2. Clone this repo
```bash
git clone https://github.com/sabrinahaniff/telemetry-sentinel
cd telemetry-sentinel/backend && npm install
```

### 3. Add the plugin to OpenMCT
Open `~/openmct/index.html` and paste the contents of `plugin/src/plugin.js` inside a `<script>` tag before `</body>`, then add:
```js
openmct.install(TelemetrySecurityPlugin());
```
before `openmct.start();`

### 4. Run everything (3 terminals)
```bash
# Terminal 1: fake rocket telemetry
node ~/telemetry-sentinel/simulator/mock-telemetry.js

# Terminal 2: security detection backend  
cd ~/telemetry-sentinel/backend && node src/server.js

# Terminal 3: OpenMCT dashboard
cd ~/openmct && npm start
```

### 5. Open the dashboard
Go to `http://localhost:8080`, click **+ Create**, select **Security Alert Panel**, and watch the alerts fire.

---

## Project Structure

```
telemetry-sentinel/
├── backend/
│   ├── src/
│   │   ├── server.js       — ingests telemetry, runs detector
│   │   ├── detector.js     — all anomaly detection logic
│   │   └── alerts.js       — formats and broadcasts alerts
│   └── package.json
├── plugin/
│   └── src/
│       └── plugin.js       — OpenMCT plugin, renders alert panel
├── simulator/
│   └── mock-telemetry.js   — fake rocket data + timed attack scripts
└── docker-compose.yml
```

---

## Tech Stack

- **Node.js**:  detection backend
- **ws**: WebSocket server and client
- **OpenMCT (NASA)**: mission control dashboard
- **Docker**: containerised setup


---

## References

- [NASA OpenMCT](https://github.com/nasa/openmct)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CCSDS Space Data Standards](https://public.ccsds.org/default.aspx)