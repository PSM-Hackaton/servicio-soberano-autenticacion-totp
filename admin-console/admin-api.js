// Capa de cliente y lógica pura de la Consola Administrativa (0 dependencias npm).
// Soporta modo 'mock' (leyendo ../contracts/mocks/) y modo 'live' (API HTTPS real).

export const ROLES = Object.freeze({
  ADMINISTRADOR: 'Administrador',
  OPERADOR: 'Operador',
  AUDITOR: 'Auditor',
});

/** Matriz de permisos RBAC alineada a ARCHITECTURE.md y docs/analisis/analisis-tecnico.html */
export const PERMISSIONS = Object.freeze({
  [ROLES.ADMINISTRADOR]: Object.freeze({
    manageApps: true,
    revokeEnrollment: true,
    rotateKeys: true,
    verifyAudit: true,
    viewAnomalies: true,
  }),
  [ROLES.OPERADOR]: Object.freeze({
    manageApps: false,
    revokeEnrollment: true,
    rotateKeys: false,
    verifyAudit: true,
    viewAnomalies: true,
  }),
  [ROLES.AUDITOR]: Object.freeze({
    manageApps: false,
    revokeEnrollment: false,
    rotateKeys: false,
    verifyAudit: true,
    viewAnomalies: true,
  }),
});

/**
 * Devuelve los permisos del rol indicado (por defecto mínimo privilegio).
 * @param {string} rol
 */
export function getPermissions(rol) {
  return PERMISSIONS[rol] || PERMISSIONS[ROLES.AUDITOR];
}

/**
 * Parsea texto en formato de exposición Prometheus (`GET /metrics`) a métricas estructuradas.
 * @param {string} text
 */
export function parsePrometheusMetrics(text) {
  const gauges = {};
  const verifications = {};
  const latency = {};
  const requests = {};

  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?\d*\.?\d+(?:[eE][-+]?\d+)?|NaN)$/);
    if (!match) continue;
    const [, name, labelsRaw, valStr] = match;
    const value = valStr === 'NaN' ? null : Number(valStr);
    const labels = {};
    if (labelsRaw) {
      for (const part of labelsRaw.split(',')) {
        const m = part.trim().match(/^([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"$/);
        if (m) labels[m[1]] = m[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      }
    }

    if (name === 'totp_verifications_total' && labels.resultado) {
      verifications[labels.resultado] = value ?? 0;
    } else if (name === 'totp_http_request_duration_ms' && labels.ruta && labels.quantile) {
      latency[labels.ruta] = latency[labels.ruta] || {};
      latency[labels.ruta][`p${Math.round(Number(labels.quantile) * 100)}`] = value;
    } else if (name === 'totp_http_requests_total' && labels.ruta) {
      requests[labels.ruta] = value ?? 0;
    } else if (!labelsRaw) {
      gauges[name] = value;
    }
  }

  return { gauges, verifications, latency, requests };
}

/**
 * Verifica una cadena de eventos audit_log en memoria (útil para modo mock y auditoría offline).
 * @param {Array<{ id: number, prev_hash: string, hash: string }>} events
 */
export function verifyLocalAuditLinks(events) {
  const GENESIS = '0'.repeat(64);
  let expectedPrev = GENESIS;
  let checked = 0;
  for (const ev of events) {
    checked++;
    if (ev.prev_hash !== expectedPrev || !ev.hash || ev.hash.length < 32) {
      return { intact: false, checked_records: checked, broken_at_id: ev.id, last_hash: null };
    }
    expectedPrev = ev.hash;
  }
  return {
    intact: true,
    checked_records: checked,
    broken_at_id: null,
    last_hash: checked ? expectedPrev : null,
  };
}

/**
 * Crea un cliente para la Consola Administrativa con cambio dinámico entre Mocks y API Real.
 * @param {{ mode?: 'mock' | 'live', baseUrl?: string, mockBasePath?: string, fetchImpl?: typeof fetch }} [options]
 */
export function createAdminClient({
  mode = 'mock',
  baseUrl = 'https://localhost:8443',
  mockBasePath = '../contracts/mocks',
  fetchImpl = globalThis.fetch,
} = {}) {
  let currentMode = mode;
  let currentBaseUrl = baseUrl.replace(/\/+$/, '');
  let csrfToken = null;
  let session = null;

  // Estado mutable local para demostración interactiva en modo mock
  const mockState = {
    apps: null,
    enrollments: null,
    jwks: null,
    auditEvents: null,
    dashboard: null,
    metricsText: null,
    healthReady: null,
    tampered: false,
  };

  async function loadMockJson(filename) {
    const res = await fetchImpl(`${mockBasePath}/${filename}`);
    if (!res.ok) throw new Error(`No se pudo cargar mock ${filename} (${res.status})`);
    return res.json();
  }

  async function loadMockText(filename) {
    const res = await fetchImpl(`${mockBasePath}/${filename}`);
    if (!res.ok) throw new Error(`No se pudo cargar mock ${filename} (${res.status})`);
    return res.text();
  }

  async function ensureMockLoaded() {
    if (!mockState.apps) {
      const [apps, enrolls, jwks, audit, dash, metrics, ready] = await Promise.all([
        loadMockJson('admin-apps.json'),
        loadMockJson('admin-enrollments.json'),
        loadMockJson('jwks.json'),
        loadMockJson('admin-audit.json'),
        loadMockJson('admin-dashboard.json'),
        loadMockText('metrics.txt'),
        loadMockJson('health-ready.json'),
      ]);
      mockState.apps = apps.apps;
      mockState.enrollments = enrolls.enrollments;
      mockState.jwks = jwks;
      mockState.auditEvents = audit.events;
      mockState.dashboard = dash;
      mockState.metricsText = metrics;
      mockState.healthReady = ready;
    }
  }

  function appendMockAudit(actor, accion, objetivo, detalle) {
    const prev = mockState.auditEvents[mockState.auditEvents.length - 1];
    const id = (prev?.id || 0) + 1;
    const prevHash = prev?.hash || '0'.repeat(64);
    const pseudoHash = Array.from(
      new Uint8Array(32).map((_, i) => (id * 37 + accion.charCodeAt(i % accion.length) + i * 13) & 0xff),
    ).map((b) => b.toString(16).padStart(2, '0')).join('');
    mockState.auditEvents.push({
      id,
      ts: new Date().toISOString(),
      actor,
      accion,
      objetivo,
      detalle: JSON.stringify(detalle),
      prev_hash: prevHash,
      hash: pseudoHash,
    });
  }

  async function liveRequest(path, { method = 'GET', body, expectText = false } = {}) {
    const headers = { Accept: expectText ? 'text/plain' : 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (csrfToken && method !== 'GET') headers['X-CSRF-Token'] = csrfToken;

    const res = await fetchImpl(`${currentBaseUrl}${path}`, {
      method,
      headers,
      credentials: 'include',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));
      throw new Error(errBody.message || `Error HTTP ${res.status}`);
    }
    return expectText ? res.text() : res.json();
  }

  return {
    getMode: () => currentMode,
    getBaseUrl: () => currentBaseUrl,
    getSession: () => session,
    setConfig({ mode: m, baseUrl: url }) {
      if (m) currentMode = m;
      if (url) currentBaseUrl = url.replace(/\/+$/, '');
    },

    async login({ usuario, password, totp_code, mockRol }) {
      if (!usuario || !password) throw new Error('Usuario y contraseña obligatorios');
      if (!/^[0-9]{6,8}$/.test(String(totp_code || ''))) {
        throw new Error('Ingresa un código TOTP válido de 6 u 8 dígitos');
      }
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        const roleMap = {
          admin_seguridad: ROLES.ADMINISTRADOR,
          operador_mfa: ROLES.OPERADOR,
          auditor_institucional: ROLES.AUDITOR,
        };
        const rol = mockRol || roleMap[usuario] || ROLES.ADMINISTRADOR;
        csrfToken = `mock-csrf-${Date.now()}`;
        session = { usuario, rol, csrf_token: csrfToken };
        appendMockAudit(usuario, 'ADMIN_LOGIN', usuario, { rol, modo: 'mock' });
        return session;
      }
      const res = await liveRequest('/admin/api/login', {
        method: 'POST',
        body: { usuario, password, totp_code },
      });
      csrfToken = res.csrf_token;
      session = res;
      return res;
    },

    logout() {
      session = null;
      csrfToken = null;
    },

    async getOverview() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        return {
          healthReady: mockState.healthReady,
          anomalies: mockState.dashboard,
          metrics: parsePrometheusMetrics(mockState.metricsText),
          metricsRaw: mockState.metricsText,
        };
      }
      const [healthReady, anomalies, metricsRaw] = await Promise.all([
        liveRequest('/health/ready'),
        liveRequest('/admin/api/anomalies'),
        liveRequest('/metrics', { expectText: true }),
      ]);
      return {
        healthReady,
        anomalies,
        metrics: parsePrometheusMetrics(metricsRaw),
        metricsRaw,
      };
    },

    async getApps() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        return { apps: [...mockState.apps] };
      }
      return liveRequest('/admin/api/apps');
    },

    async createApp(payload) {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        const id = `app-${Date.now()}`;
        const clientId = payload.client_id || payload.nombre.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 32);
        const clientSecret = `sec_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
        const created = {
          id,
          nombre: payload.nombre,
          client_id: clientId,
          algoritmo: payload.algoritmo || 'SHA256',
          digitos: Number(payload.digitos || 6),
          periodo: Number(payload.periodo || 30),
          ventana: Number(payload.ventana ?? 1),
          max_intentos: Number(payload.max_intentos || 5),
          umbral_riesgo_bloqueo: Number(payload.umbral_riesgo_bloqueo || 75),
          modo_heuristica: payload.modo_heuristica || 'bloqueo',
          permitir_sha1: Boolean(payload.permitir_sha1),
          estado: 'activo',
          created_at: new Date().toISOString(),
        };
        mockState.apps.unshift(created);
        appendMockAudit(session?.usuario || 'admin', 'APP_REGISTERED', clientId, { algoritmo: created.algoritmo, digitos: created.digitos });
        return { app: created, client_id: clientId, client_secret: clientSecret };
      }
      return liveRequest('/admin/api/apps', { method: 'POST', body: payload });
    },

    async getEnrollments() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        return { enrollments: [...mockState.enrollments] };
      }
      return liveRequest('/admin/api/enrollments');
    },

    async revokeEnrollment(id) {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        const item = mockState.enrollments.find((e) => e.id === id);
        if (!item) throw new Error('Enrolamiento no encontrado');
        item.estado = 'revocado';
        item.revoked_at = new Date().toISOString();
        appendMockAudit(session?.usuario || 'admin', 'ENROLLMENT_REVOKED', id, { estado: 'revocado' });
        return { enrollment_id: id, estado: 'revocado', revoked_at: item.revoked_at };
      }
      return liveRequest(`/api/v1/enrollments/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },

    async getJwks() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        return { keys: [...mockState.jwks.keys] };
      }
      return liveRequest('/.well-known/jwks.json');
    },

    async rotateKeys() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        const prev = mockState.jwks.keys[0]?.kid || null;
        const nextIndex = mockState.jwks.keys.length + 1;
        const newKid = `key-20261126-${String(nextIndex).padStart(2, '0')}`;
        const rotatedAt = new Date().toISOString();
        mockState.jwks.keys.unshift({
          kty: 'OKP',
          crv: 'Ed25519',
          kid: newKid,
          use: 'sig',
          alg: 'EdDSA',
          x: `mockEd25519PubKey_${nextIndex}_${Date.now().toString(36)}`,
        });
        appendMockAudit(session?.usuario || 'admin', 'SIGNING_KEY_ROTATED', newKid, { previous_kid: prev });
        return { new_kid: newKid, previous_kid: prev, rotated_at: rotatedAt };
      }
      return liveRequest('/admin/api/keys/rotate', { method: 'POST', body: {} });
    },

    async getAudit() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        return { events: [...mockState.auditEvents] };
      }
      return liveRequest('/admin/api/audit');
    },

    async verifyAuditChain() {
      if (currentMode === 'mock') {
        await ensureMockLoaded();
        return verifyLocalAuditLinks(mockState.auditEvents);
      }
      return liveRequest('/admin/api/audit/verify-chain');
    },

    /** Solo para demostración en vivo ante el jurado en modo mock: altera un registro para probar detección */
    simulateMockAuditTamper() {
      if (currentMode !== 'mock' || !mockState.auditEvents?.length) return false;
      const idx = Math.min(1, mockState.auditEvents.length - 1);
      mockState.auditEvents[idx] = {
        ...mockState.auditEvents[idx],
        prev_hash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      };
      mockState.tampered = true;
      return true;
    },
  };
}
