# 07. Plan de Mitigación

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

### 7.1 Controles de Seguridad

| ID | Amenaza | Control de Seguridad | Prioridad | Estado |
|----|---------|----------------------|-----------|--------|
| **C01** | TH18 | Rate Limiting en 3 capas (WAF/GW/App) | P0 | Pend |
| **C02** | TH01 | JWT Secret Rotation + RS256 | P0 | Pend |
| **C03** | TH14 | Log Scrubbing + Encryption | P0 | Pend |
| **C04** | TH16 | External Secrets Operator + Vault | P0 | Pend |
| **C05** | TH06/25 | Input Validation Framework | P0 | Pend |
| **C06** | TH09 | Image Signing + Scanning | P1 | Pend |
| **C07** | TH24 | Security Contexts + AppArmor | P1 | Pend |
| **C08** | TH19/20 | Resource Limits + HPA | P1 | Pend |
| **C09** | TH02 | mTLS Strict Mode (Istio) | P1 | Pend |
| **C10** | TH26 | Network Policies + Admission Controllers | P1 | Pend |
| **C11** | Todos | Runtime Security (Falco) | P1 | Pend |
| **C12** | TH10/11 | Immutable Audit Logs | P2 | Pend |
| **C13** | TH03 | Session Encryption + HTTPOnly Cookies | P2 | Pend |
| **C14** | TH13/17 | Error Handling Framework | P2 | Pend |
| **C15** | TH27 | RBAC Review + Least Privilege | P2 | Pend |

**Prioridades:**
- **P0 (Crítico):** Implementación inmediata - Sprint 1-2 (4 semanas)
- **P1 (Alto):** Implementación próximo ciclo - Sprint 3-4 (8 semanas)
- **P2 (Medio):** Implementación planificada - Sprint 5-6 (12 semanas)

### 7.2 Controles por Categoría

#### CONTROLES PREVENTIVOS

- [x] **Autenticación multifactor (MFA)**
  - Implementar para acceso administrativo a K8s
  - Implementar para acceso a producción vía VPN
  - Herramienta: Duo Security / Google Authenticator

- [x] **Cifrado de datos en tránsito y en reposo**
  - TLS 1.3 obligatorio para todas las conexiones
  - Encryption at rest para PostgreSQL (LUKS)
  - Encryption at rest para Elasticsearch
  - mTLS entre todos los microservicios (Istio)

- [x] **Validación de entrada**
  - Schema validation con Zod/Joi en todos los endpoints
  - Prepared statements obligatorios (ESLint rule)
  - WAF rules para inyección SQL, XSS, XXE

- [x] **Principio de mínimo privilegio**
  - RBAC de K8s con roles específicos por equipo
  - Service accounts únicos por microservicio
  - Database users con permisos granulares (no root)
  - IAM roles con least privilege en cloud provider

- [x] **Segmentación de red**
  - Network Policies de Kubernetes (default deny all)
  - Security groups en cloud provider
  - Service Mesh authorization policies (Istio)
  - VLANs separadas para management vs data plane

- [x] **Hardening de containers**
  - Distroless base images
  - runAsNonRoot: true
  - readOnlyRootFilesystem: true
  - No privileged containers
  - Drop all capabilities, solo añadir necesarias

#### CONTROLES DETECTIVOS

- [x] **Logging de eventos de seguridad**
  - Kubernetes audit logs (todos los API calls)
  - Application logs con structured logging (JSON)
  - WAF logs de requests bloqueados
  - Database query logs (slow queries + failed auth)

- [x] **Monitorización con SIEM**
  - Elastic Security (parte de ELK Stack)
  - Correlation rules para detectar:
    * Intentos de autenticación fallidos (>10 en 5 min)
    * Acceso a recursos fuera de horario laboral
    * Cambios en Secrets/ConfigMaps
    * Privilege escalation attempts

- [x] **Alertas de anomalías**
  - Falco para runtime anomaly detection
  - Prometheus alertas en métricas anómalas
  - Istio telemetry para detectar traffic patterns inusuales

- [x] **Revisión de logs periódica**
  - Daily review de alertas SIEM
  - Weekly review de Kubernetes audit logs
  - Monthly security metrics dashboard review

- [x] **Vulnerability Scanning**
  - Trivy scanning en CI/CD pipeline
  - Clair scanning en container registry
  - Dependency scanning con Snyk/Dependabot
  - DAST con OWASP ZAP en staging

#### CONTROLES CORRECTIVOS

- [x] **Plan de respuesta a incidentes**
  - Runbooks documentados para cada tipo de incidente
  - Equipo on-call 24/7 con PagerDuty
  - Procedimiento de escalación definido
  - Communication templates para stakeholders

- [x] **Procedimientos de backup**
  - Velero para backups de Kubernetes (daily)
  - PostgreSQL pg_basebackup (continuous archiving + daily full)
  - RabbitMQ configuration backups
  - Elasticsearch snapshots a S3 (daily)
  - RPO (Recovery Point Objective): 1 hora
  - RTO (Recovery Time Objective): 4 horas

- [x] **Plan de recuperación**
  - Disaster recovery testing quarterly
  - Failover a región secundaria documentado
  - Restore procedures validados mensualmente
  - Crisis communication plan

### 7.3 Detalle de Controles Prioritarios (P0)

#### CONTROL C01: Rate Limiting Robusto

**Amenazas mitigadas:** TH18 (API Flooding)  
**Prioridad:** P0  
**Timeline:** Sprint 1 (2 semanas)  
**Responsable:** Equipo Platform/SRE

**Implementación en 3 capas:**

**CAPA 1 - WAF (Cloudflare/AWS WAF):**
- Rate limit: 100 requests/min por IP
- Geo-blocking de países de alto riesgo
- Challenge (CAPTCHA) si > 200 requests/min
- Bloqueo automático de IPs con >1000 req/min

**CAPA 2 - API Gateway (Kong):**

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: rate-limiting-global
plugin: rate-limiting
config:
  minute: 100
  hour: 5000
  policy: redis
  redis_host: redis.default.svc.cluster.local
  redis_port: 6379
  fault_tolerant: true
  hide_client_headers: false
```

**CAPA 3 - Application (Token Bucket):**

```javascript
const rateLimiter = new RateLimiter({
  tokensPerInterval: 10,
  interval: "second",
  fireImmediately: true
});

app.use(async (req, res, next) => {
  const userId = req.user.id;
  const allowed = await rateLimiter.removeTokens(userId, 1);
  if (!allowed) {
    return res.status(429).json({ error: "Too many requests" });
  }
  next();
});
```

**Métricas de éxito:**
- 99.9% de requests legítimos pasan sin bloqueo
- Detección de flooding en <10 segundos
- Mitigación automática sin intervención manual
- False positive rate <0.1%

---

#### CONTROL C02: JWT Secret Rotation + RS256

**Amenazas mitigadas:** TH01 (JWT Falsification)  
**Prioridad:** P0  
**Timeline:** Sprint 1 (2 semanas)  
**Responsable:** Equipo de Security + Backend

**Cambios:**

**1. Migrar de HS256 (symmetric) a RS256 (asymmetric):**
- Private key solo en Auth Service
- Public key distribuida a todos los servicios
- Imposible falsificar token sin private key

**2. Rotación automática de keys:**
- Nueva keypair cada 30 días
- Período de gracia de 7 días (ambas keys válidas)
- Script automatizado con Vault

**3. Almacenamiento seguro:**
- Private key en HashiCorp Vault
- NUNCA en variables de entorno
- NUNCA en ConfigMaps
- Acceso vía External Secrets Operator

**4. Claims validation estricta:**

```javascript
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: 'https://auth.example.com',
  audience: 'api.example.com',
  clockTolerance: 60
}, (err, decoded) => {
  if (err) throw new UnauthorizedError('Invalid token');
  
  // Validate required claims
  if (!decoded.sub || !decoded.roles) {
    throw new UnauthorizedError('Missing claims');
  }
  
  // Validate role is in allowed set
  const allowedRoles = ['user', 'admin', 'support'];
  if (!allowedRoles.includes(decoded.role)) {
    throw new UnauthorizedError('Invalid role');
  }
});
```

**Métricas de éxito:**
- 0 secrets expuestos en logs/configs
- Rotación automática sin downtime
- Audit trail de cada rotación

---

#### CONTROL C03: Log Scrubbing + Encryption

**Amenazas mitigadas:** TH14 (PII Exposure)  
**Prioridad:** P0  
**Timeline:** Sprint 1 (2 semanas)  
**Responsable:** Equipo de Observability

**Pipeline de logging:**

```
[Application]
    ↓ (structured logs, PII scrubbing)
[Fluentd/Fluent Bit]
    ↓ (additional scrubbing, encryption)
[Elasticsearch]
    ↓ (encryption at rest, RBAC)
[Kibana] (MFA, audit trail)
```

**Scrubbing rules (Fluentd):**

```ruby
<filter **>
  @type record_transformer
  enable_ruby true
  <record>
    # Redact emails
    message ${record["message"].gsub(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, '[EMAIL_REDACTED]')}
    
    # Redact credit cards
    message ${record["message"].gsub(/\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/, '[CC_REDACTED]')}
    
    # Redact SSNs
    message ${record["message"].gsub(/\d{3}-\d{2}-\d{4}/, '[SSN_REDACTED]')}
    
    # Redact JWTs
    message ${record["message"].gsub(/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, '[JWT_REDACTED]')}
    
    # Redact passwords
    message ${record["message"].gsub(/(password|passwd|pwd)[\s]*=[\s]*[^\s&]+/i, '\1=[REDACTED]')}
  </record>
</filter>
```

**Application-side structured logging:**

```javascript
// NUNCA loggear así:
logger.info(`Request: ${JSON.stringify(req.body)}`);

// Loggear así:
logger.info('User login attempt', {
  userId: req.body.userId, // OK: identifier
  action: 'login',
  timestamp: Date.now(),
  // NO loggear: email, password, tokens
});
```

**Elasticsearch encryption:**
- Encryption at rest: LUKS en volúmenes
- Encryption in transit: TLS 1.3
- RBAC: Solo security team tiene acceso full
- Audit logs de quién accede a qué queries

**Compliance checks:**
- Daily automated scan de logs buscando patterns de PII
- Alert si se detecta PII sin redactar
- Monthly audit de logs retention policy

**Métricas de éxito:**
- 0 PII detectado en logs en auditorías
- 100% de logs encriptados en tránsito y reposo
- Audit trail de todos los accesos a logs

---

#### CONTROL C04: External Secrets Operator + Vault

**Amenazas mitigadas:** TH16 (K8s Secrets Exposure), TH01 (JWT), TH04 (API Keys)  
**Prioridad:** P0  
**Timeline:** Sprint 2 (2 semanas)  
**Responsable:** Equipo Platform

**Arquitectura:**

```
[HashiCorp Vault / AWS Secrets Manager]
         ↓ (External Secrets Operator sync)
[Kubernetes Secrets] (short-lived, rotated)
         ↓ (mounted as files, NOT env vars)
[Application Pods]
```

**Implementación:**

**1. Setup Vault:**

```bash
# Enable K8s auth
vault auth enable kubernetes

# Configure K8s auth
vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

# Create policy
vault policy write app-secrets - <<EOF
path "secret/data/production/*" {
  capabilities = ["read"]
}
EOF

# Create role
vault write auth/kubernetes/role/app-role \
    bound_service_account_names=app-sa \
    bound_service_account_namespaces=production \
    policies=app-secrets \
    ttl=1h
```

**2. External Secret definition:**

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: postgres-secret
    creationPolicy: Owner
  data:
  - secretKey: password
    remoteRef:
      key: secret/data/production/postgres
      property: password
```

**3. Application mounting (NO env vars):**

```yaml
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: app-sa
  containers:
  - name: app
    volumeMounts:
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secrets
    secret:
      secretName: postgres-secret
```

**4. Application reading secret:**

```javascript
// NUNCA así:
const dbPassword = process.env.DB_PASSWORD;

// SÍ así:
import fs from 'fs';
const dbPassword = fs.readFileSync('/etc/secrets/password', 'utf8').trim();
```

**Rotación automática:**
- JWT secrets: cada 30 días
- DB passwords: cada 90 días (con downtime mínimo)
- API keys terceros: cada 60 días
- TLS certificates: cada 90 días (Let's Encrypt)

**Métricas de éxito:**
- 0 secrets hardcodeados en código
- 0 secrets en variables de entorno
- 100% de secrets rotados según schedule
- Audit trail de cada rotación

---

#### CONTROL C05: Input Validation Framework

**Amenazas mitigadas:** TH06 (SQL Injection), TH25 (IDOR), TH05 (Tampering)  
**Prioridad:** P0  
**Timeline:** Sprint 1-2 (3 semanas)  
**Responsable:** Equipos de desarrollo

**Stack de validación:**

**1. Schema validation (Zod/Joi):**

```typescript
import { z } from 'zod';

const OrderSchema = z.object({
  orderId: z.string().uuid(),
  userId: z.string().uuid(),
  items: z.array(z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().positive().max(1000)
  })).max(100),
  totalAmount: z.number().positive().max(1000000)
});

app.post('/api/orders', async (req, res) => {
  try {
    const validatedData = OrderSchema.parse(req.body);
    // Proceed with validated data
  } catch (error) {
    return res.status(400).json({ error: error.errors });
  }
});
```

**2. SQL Injection Prevention:**

```javascript
// NUNCA concatenar:
const query = `SELECT * FROM users WHERE id = ${userId}`;

// SIEMPRE usar prepared statements:
const query = 'SELECT * FROM users WHERE id = $1';
const result = await db.query(query, [userId]);

// O usar ORM (TypeORM, Prisma):
const user = await User.findOne({ where: { id: userId } });
```

**3. IDOR Prevention:**

```javascript
async function getOrder(orderId, userId) {
  const order = await db.query(
    'SELECT * FROM orders WHERE id = $1',
    [orderId]
  );
  
  if (!order) {
    throw new NotFoundError('Order not found');
  }
  
  // CRITICAL: Validate ownership
  if (order.userId !== userId) {
    throw new UnauthorizedError('Not your order');
  }
  
  return order;
}
```

**4. ESLint rules enforcement:**

```javascript
// .eslintrc.js
module.exports = {
  rules: {
    'no-sql-concat': 'error', // Custom rule
    'no-eval': 'error',
    'no-new-func': 'error'
  }
};
```

**5. WAF rules:**
- ModSecurity Core Rule Set (OWASP)
- SQL Injection patterns
- XSS patterns
- Path traversal patterns
- XML External Entity (XXE) patterns

**Checklist de implementación:**
- [ ] Schema validation en todos los POST/PUT endpoints
- [ ] Prepared statements obligatorios (CI check)
- [ ] Authorization checks en CRUD operations
- [ ] Audit logs de access denied
- [ ] Input sanitization en frontend (defense in depth)

**Métricas de éxito:**
- 0 SQL injection findings en pentests
- 0 IDOR findings en pentests
- 100% de endpoints con schema validation
- CI pipeline rechaza PRs con SQL concatenation

---

[← Anterior: Mapa de Ataque (ATT&CK)](06-mapa-attack.md) | [Siguiente: Matriz de Controles (NIST/ISO 27001) →](08-controles-nist-iso.md)