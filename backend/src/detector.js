/**
 * detector.js
 * Two-layer anomaly detection engine:
 *   Layer 1- Aerospace: physics violations, sensor spoofing, impossible readings
 *   Layer 2- OWASP: injection, access control, schema tampering
 */


// The list of fields a valid telemetry packet is allowed to have.
// Anything outside this list is flagged as a schema violation.
const KNOWN_FIELDS = [
  'timestamp', 'temperature', 'pressure',
  'altitude', 'velocity', 'fuelLevel', 'batteryVoltage'
];


// Define the min/max physically possible values for each field.
const PHYSICAL_LIMITS = {
  temperature:    { min: -100,  max: 3500  },  // deg C — cryogenic fuel to engine exhaust
  pressure:       { min: 0,     max: 10000 },  // kPa
  altitude:       { min: -500,  max: 600000 }, // meters (slightly below sea level to low orbit)
  velocity:       { min: -500,  max: 8000  },  // m/s
  fuelLevel:      { min: 0,     max: 100   },  // percentage
  batteryVoltage: { min: 0,     max: 35    },  // volts
};


// How much can a value legitimately change in one reading?
// A temperature jump of 5000 degrees in 500ms is impossible.
const MAX_DELTA = {
  temperature:    500,   // deg C per reading
  pressure:       200,
  altitude:       200,
  velocity:       50,
  fuelLevel:      5,
  batteryVoltage: 2,
};



// Regex patterns that should never appear in telemetry values.
const INJECTION_PATTERNS = [
  /<script[\s\S]*?>/i,          // XSS
  /javascript:/i,               // JS URI
  /on\w+\s*=/i,                 // HTML event handlers (onclick=, onload=)
  /SELECT.*FROM/i,              // SQL injection
  /DROP\s+TABLE/i,              // SQL injection
  /\$\{.*\}/,                   // Template literal injection
  /\.\.\//,                     // Path traversal
  /;\s*(rm|ls|cat|wget|curl)/i, // Shell injection
];

//Detector class
class TelemetryDetector {
  constructor() {
    this.previousReading = null;
    this.flatlineTrackers = {}; // tracks repeated values per field
  }

  /**
   * Main entry point.
   * Pass in a telemetry data object, get back an array of alerts (empty = clean).
   */
  analyze(data) {
    const alerts = [];

    // owasp layer
    alerts.push(...this.checkInjection(data));
    alerts.push(...this.checkSchemaViolation(data));

    // aerospace Layer 
    alerts.push(...this.checkPhysicalLimits(data));
    alerts.push(...this.checkRateOfChange(data));
    alerts.push(...this.checkFlatline(data));

    // store reading for next comparison
    this.previousReading = { ...data };

    return alerts;
  }

  // OWASP A03: Injection
  // Scan every value for malicious strings/patterns
  checkInjection(data) {
    const alerts = [];
    for (const [field, value] of Object.entries(data)) {
      if (typeof value === 'string') {
        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.test(value)) {
            alerts.push({
              severity: 'CRITICAL',
              category: 'OWASP-A03-Injection',
              field,
              value,
              message: `Injection pattern detected in field "${field}": ${value}`,
            });
            break;
          }
        }
      }
    }
    return alerts;
  }

  // OWASP A01: Broken Access Control / Schema Violation
  // Flag any fields that shouldn't exist in a telemetry packet
  checkSchemaViolation(data) {
    const alerts = [];
    for (const field of Object.keys(data)) {
      if (!KNOWN_FIELDS.includes(field)) {
        alerts.push({
          severity: 'HIGH',
          category: 'OWASP-A01-Schema-Violation',
          field,
          value: data[field],
          message: `Unknown field "${field}" found in telemetry packet — possible tampering`,
        });
      }
    }
    return alerts;
  }

  // Is this value within the physically possible range?
  checkPhysicalLimits(data) {
    const alerts = [];
    for (const [field, limits] of Object.entries(PHYSICAL_LIMITS)) {
      const value = data[field];
      if (typeof value !== 'number') continue;
      if (value < limits.min || value > limits.max) {
        alerts.push({
          severity: 'HIGH',
          category: 'AEROSPACE-Physical-Limit',
          field,
          value,
          message: `${field} value ${value} is outside physical limits [${limits.min}, ${limits.max}]`,
        });
      }
    }
    return alerts;
  }

  // Did any value change too fast between readings?
  checkRateOfChange(data) {
    const alerts = [];
    if (!this.previousReading) return alerts;

    for (const [field, maxDelta] of Object.entries(MAX_DELTA)) {
      const current = data[field];
      const previous = this.previousReading[field];
      if (typeof current !== 'number' || typeof previous !== 'number') continue;

      const delta = Math.abs(current - previous);
      if (delta > maxDelta) {
        alerts.push({
          severity: 'HIGH',
          category: 'AEROSPACE-Rate-Of-Change',
          field,
          value: current,
          message: `${field} changed by ${delta.toFixed(2)} in one reading (max allowed: ${maxDelta}) — possible spoofing`,
        });
      }
    }
    return alerts;
  }

  // If a sensor reports the EXACT same value 5+ times in a row,
  // it's probably frozen/spoofed.
  checkFlatline(data) {
    const alerts = [];
    const FLATLINE_THRESHOLD = 5;

    for (const field of Object.keys(PHYSICAL_LIMITS)) {
      const value = data[field];
      if (typeof value !== 'number') continue;

      if (!this.flatlineTrackers[field]) {
        this.flatlineTrackers[field] = { lastValue: null, count: 0 };
      }

      const tracker = this.flatlineTrackers[field];

      if (value === tracker.lastValue) {
        tracker.count++;
        if (tracker.count === FLATLINE_THRESHOLD) {
          alerts.push({
            severity: 'MEDIUM',
            category: 'AEROSPACE-Flatline',
            field,
            value,
            message: `${field} has reported the exact same value (${value}) ${FLATLINE_THRESHOLD} times — sensor may be spoofed or frozen`,
          });
        }
      } else {
        tracker.lastValue = value;
        tracker.count = 1;
      }
    }
    return alerts;
  }
}

module.exports = TelemetryDetector;