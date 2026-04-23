/**
 * plugin.js
 * OpenMCT plugin; registers an Alert Panel inside the dashboard.
 *
 * How to load this in OpenMCT:
 *   1. Copy this file into your openmct/src/plugins/ folder
 *   2. In openmct/index.html, add:
 *        <script src="plugin/src/plugin.js"></script>
 *        openmct.install(TelemetrySecurityPlugin());
 */

function TelemetrySecurityPlugin() {
  return function install(openmct) {

    const ALERT_SERVER = 'ws://localhost:8082';
    const SEVERITY_COLORS = {
      CRITICAL: '#e74c3c',
      HIGH:     '#e67e22',
      MEDIUM:   '#f1c40f',
      LOW:      '#3498db',
    };

    // Register a new view type in OpenMCT
    openmct.objectViews.addProvider({
      name: 'Security Alert Panel',
      key: 'security-alert-panel',
      cssClass: 'icon-object',
      canView(domainObject) {
        return domainObject.type === 'security-alerts';
      },
      view(domainObject) {
        let ws;
        let container;

        return {
          show(element) {
            // Build the panel UI
            container = document.createElement('div');
            container.style.cssText = `
              font-family: monospace;
              background: #0a0a0a;
              color: #e0e0e0;
              height: 100%;
              overflow-y: auto;
              padding: 12px;
              box-sizing: border-box;
            `;
            container.innerHTML = `
              <div style="font-size:14px;font-weight:bold;margin-bottom:12px;color:#aaa;">
                TELEMETRY SENTINEL — Security Monitor
              </div>
              <div id="alert-feed" style="display:flex;flex-direction:column;gap:8px;">
                <div style="color:#555;">Connecting to alert server...</div>
              </div>
            `;
            element.appendChild(container);

            //Connect to alert backend
            ws = new WebSocket(ALERT_SERVER);

            ws.onopen = () => {
              const feed = container.querySelector('#alert-feed');
              feed.innerHTML = '<div style="color:#555;">Monitoring active. Waiting for anomalies...</div>';
            };

            ws.onmessage = (event) => {
              const msg = JSON.parse(event.data);

              if (msg.type === 'history') {
                const feed = container.querySelector('#alert-feed');
                if (msg.alerts.length) {
                  feed.innerHTML = '';
                  msg.alerts.forEach(a => renderAlert(feed, a));
                }
              }

              if (msg.type === 'alerts') {
                const feed = container.querySelector('#alert-feed');
                // Remove placeholder text
                const placeholder = feed.querySelector('[data-placeholder]');
                if (placeholder) placeholder.remove();

                msg.alerts.forEach(a => {
                  renderAlert(feed, a);
                  // Auto-scroll to latest
                  feed.scrollTop = feed.scrollHeight;
                });
              }
            };

            ws.onclose = () => {
              const feed = container.querySelector('#alert-feed');
              const msg = document.createElement('div');
              msg.style.color = '#e74c3c';
              msg.textContent = 'Alert server disconnected.';
              feed.appendChild(msg);
            };
          },

          destroy() {
            if (ws) ws.close();
          }
        };
      }
    });

    //Helper: render a single alert card
    function renderAlert(feed, alert) {
      const color = SEVERITY_COLORS[alert.severity] || '#aaa';
      const card = document.createElement('div');
      card.style.cssText = `
        border-left: 3px solid ${color};
        background: #111;
        padding: 8px 12px;
        border-radius: 4px;
        animation: fadeIn 0.3s ease;
      `;
      card.innerHTML = `
        <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
          <span style="color:${color};font-weight:bold;font-size:12px;">
            [${alert.severity}] ${alert.category}
          </span>
          <span style="color:#555;font-size:11px;">${new Date(alert.timestamp).toLocaleTimeString()}</span>
        </div>
        <div style="font-size:12px;color:#ccc;">${alert.message}</div>
        <div style="font-size:11px;color:#555;margin-top:4px;">
          Field: <span style="color:#aaa">${alert.field}</span> &nbsp;|&nbsp;
          Value: <span style="color:#aaa">${JSON.stringify(alert.value)}</span>
        </div>
      `;
      feed.insertBefore(card, feed.firstChild); // newest at top
    }

    // Register a domain object type for the panel 
    openmct.types.addType('security-alerts', {
      name: 'Security Alert Panel',
      description: 'Live telemetry anomaly and security alerts',
      cssClass: 'icon-object',
      creatable: true,
      initialize(object) {
        object.composition = [];
      }
    });
  };
}