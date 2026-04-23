/**
 * detector.test.js
 * Unit tests for every detection rule in detector.js
 * Run: npx jest
 */

const TelemetryDetector = require('./detector');

// Helper — clean reading with all normal values
const normalReading = () => ({
  timestamp: Date.now(),
  temperature: 22,
  pressure: 101.3,
  altitude: 1000,
  velocity: 50,
  fuelLevel: 80,
  batteryVoltage: 28.5,
});

// -------------------------------------------------------
// OWASP A03 — Injection Tests
// -------------------------------------------------------
describe('OWASP A03 - Injection Detection', () => {
  test('detects <script> tag in temperature field', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), temperature: '<script>alert("xss")</script>' };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'OWASP-A03-Injection')).toBe(true);
  });

  test('detects SQL injection in pressure field', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), pressure: 'SELECT * FROM telemetry' };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'OWASP-A03-Injection')).toBe(true);
  });

  test('detects shell injection attempt', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), velocity: '; rm -rf /' };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'OWASP-A03-Injection')).toBe(true);
  });

  test('does not flag normal numeric values', () => {
    const detector = new TelemetryDetector();
    const alerts = detector.analyze(normalReading());
    expect(alerts.some(a => a.category === 'OWASP-A03-Injection')).toBe(false);
  });
});

// -------------------------------------------------------
// OWASP A01 — Schema Violation Tests
// -------------------------------------------------------
describe('OWASP A01 - Schema Violation Detection', () => {
  test('detects unknown field in telemetry packet', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), selfDestructSequence: 'alpha' };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'OWASP-A01-Schema-Violation')).toBe(true);
  });

  test('detects adminOverride field injection', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), adminOverride: true };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'OWASP-A01-Schema-Violation')).toBe(true);
  });

  test('does not flag known schema fields', () => {
    const detector = new TelemetryDetector();
    const alerts = detector.analyze(normalReading());
    expect(alerts.some(a => a.category === 'OWASP-A01-Schema-Violation')).toBe(false);
  });
});

// -------------------------------------------------------
// Aerospace — Physical Limits Tests
// -------------------------------------------------------
describe('Aerospace - Physical Limits Detection', () => {
  test('detects temperature above max (9500 degrees)', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), temperature: 9500 };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'AEROSPACE-Physical-Limit')).toBe(true);
  });

  test('detects negative fuel level', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), fuelLevel: -10 };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'AEROSPACE-Physical-Limit')).toBe(true);
  });

  test('detects battery voltage above max', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), batteryVoltage: 999 };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'AEROSPACE-Physical-Limit')).toBe(true);
  });

  test('does not flag values within physical limits', () => {
    const detector = new TelemetryDetector();
    const alerts = detector.analyze(normalReading());
    expect(alerts.some(a => a.category === 'AEROSPACE-Physical-Limit')).toBe(false);
  });
});

// -------------------------------------------------------
// Aerospace — Rate of Change Tests
// -------------------------------------------------------
describe('Aerospace - Rate of Change Detection', () => {
  test('detects temperature jumping too fast between readings', () => {
    const detector = new TelemetryDetector();
    detector.analyze(normalReading()); // first reading establishes baseline
    const data = { ...normalReading(), temperature: 9500 }; // huge jump
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'AEROSPACE-Rate-Of-Change')).toBe(true);
  });

  test('does not flag normal gradual temperature change', () => {
    const detector = new TelemetryDetector();
    detector.analyze(normalReading());
    const data = { ...normalReading(), temperature: 23 }; // only 1 degree change
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'AEROSPACE-Rate-Of-Change')).toBe(false);
  });

  test('does not flag rate of change on first reading (no baseline)', () => {
    const detector = new TelemetryDetector();
    const data = { ...normalReading(), temperature: 9500 };
    const alerts = detector.analyze(data);
    expect(alerts.some(a => a.category === 'AEROSPACE-Rate-Of-Change')).toBe(false);
  });
});

// -------------------------------------------------------
// Aerospace — Flatline Detection Tests
// -------------------------------------------------------
describe('Aerospace - Flatline Detection', () => {
  test('detects sensor flatline after 5 identical readings', () => {
  const detector = new TelemetryDetector();
  let flatlineAlert = false;
  for (let i = 0; i < 6; i++) {
    const alerts = detector.analyze({ ...normalReading(), pressure: 55.555 });
    if (alerts.some(a => a.category === 'AEROSPACE-Flatline')) flatlineAlert = true;
  }
  expect(flatlineAlert).toBe(true);
});
});