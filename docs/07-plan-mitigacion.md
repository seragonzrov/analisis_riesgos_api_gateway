# 07. Plan de Mitigación

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

### 7.1 Controles de Seguridad

| ID | Amenaza | Control de Seguridad | Prioridad | Estado |
|----|---------|----------------------|-----------|--------|
| **C01** | TH18, TH21 | Rate Limiting en 3 capas (WAF/GW/App) | P0 | Pend |
| **C02** | TH01, TH23 | JWT Secret Rotation + RS256 | P0 | Pend |
| **C03** | TH10, TH11, TH14 | Log Scrubbing + Encryption | P0 | Pend |
| **C04** | TH01, TH04, TH08, TH16 | External Secrets Operator + Vault | P0 | Pend |
| **C05** | TH05, TH06, TH25 | Input Validation Framework | P0 | Pend |
| **C06** | TH09 | Image Signing + Scanning | P1 | Pend |
| **C07** | TH09, TH22, TH24 | Security Contexts + AppArmor | P1 | Pend |
| **C08** | TH19, TH20 | Resource Limits + HPA | P1 | Pend |
| **C09** | TH02 | mTLS Strict Mode (Istio) | P1 | Pend |
| **C10** | TH26 | Network Policies + Admission Controllers | P1 | Pend |
| **C11** | TH07, TH21 + Todas | Runtime Security (Falco) | P1 | Pend |
| **C12** | TH10, TH11, TH12 | Immutable Audit Logs | P2 | Pend |
| **C13** | TH03, TH15 | Session Encryption + HTTPOnly Cookies | P2 | Pend |
| **C14** | TH13, TH17 | Error Handling Framework | P2 | Pend |
| **C15** | TH27 | RBAC Review + Least Privilege | P2 | Pend |

**Prioridades:**
- **P0 (Crítico):** Implementación inmediata - Sprint 1-2 (4 semanas)
- **P1 (Alto):** Implementación próximo ciclo - Sprint 3-4 (8 semanas)
- **P2 (Medio):** Implementación planificada - Sprint 5-6 (12 semanas)

---

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

---

### 7.3 Detalle de Controles

#### CONTROL C01: Rate Limiting Robusto

**Amenazas mitigadas:** TH18 (API Flooding/DDoS), TH21 (RabbitMQ Queue Flooding)  
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

**Amenazas mitigadas:** TH01 (JWT Falsification), TH23 (JWT Privilege Escalation)  
**Prioridad:** P0  
**Timeline:** Sprint 1 (2 semanas)  
**Responsable:** Equipo de Security + Backend

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

  if (!decoded.sub || !decoded.roles) {
    throw new UnauthorizedError('Missing claims');
  }

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

**Amenazas mitigadas:** TH10 (Falta de trazabilidad), TH11 (Logs eliminados o modificados), TH14 (PII Exposure in Logs)
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
  userId: req.body.userId,
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

**Métricas de éxito:**
- 0 PII detectado en logs en auditorías
- 100% de logs encriptados en tránsito y reposo
- Audit trail de todos los accesos a logs

---

#### CONTROL C04: External Secrets Operator + Vault

**Amenazas mitigadas:** TH01 (JWT secret theft), TH04 (API Key Theft), TH08 (ConfigMap/Secret Modification), TH16 (K8s Secrets Exposure)
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

**1. Setup Vault:**

```bash
vault auth enable kubernetes

vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

vault policy write app-secrets - <<EOF
path "secret/data/production/*" {
  capabilities = ["read"]
}
EOF

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
- DB passwords: cada 90 días
- API keys terceros: cada 60 días
- TLS certificates: cada 90 días (Let's Encrypt)

**Métricas de éxito:**
- 0 secrets hardcodeados en código
- 0 secrets en variables de entorno
- 100% de secrets rotados según schedule
- Audit trail de cada rotación

---

#### CONTROL C05: Input Validation Framework

**Amenazas mitigadas:**  TH05 (Request Parameter Tampering), TH06 (SQL Injection), TH25 (IDOR)  
**Prioridad:** P0  
**Timeline:** Sprint 1-2 (3 semanas)  
**Responsable:** Equipos de desarrollo

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
```

**3. IDOR Prevention:**

```javascript
async function getOrder(orderId, userId) {
  const order = await db.query('SELECT * FROM orders WHERE id = $1', [orderId]);

  if (!order) throw new NotFoundError('Order not found');

  // CRITICAL: Validate ownership
  if (order.userId !== userId) throw new UnauthorizedError('Not your order');

  return order;
}
```

**4. ESLint rules enforcement:**

```javascript
module.exports = {
  rules: {
    'no-sql-concat': 'error',
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

**Métricas de éxito:**
- 0 SQL injection findings en pentests
- 0 IDOR findings en pentests
- 100% de endpoints con schema validation
- CI pipeline rechaza PRs con SQL concatenation

---

#### CONTROL C06: Image Signing + Scanning

**Amenazas mitigadas:** TH09 (Imagen Docker infectada en registry)  
**Prioridad:** P1  
**Timeline:** Sprint 3 (2 semanas)  
**Responsable:** Equipo Platform/DevOps

**1. Image signing con Cosign:**

```bash
# Generar keypair
cosign generate-key-pair

# Firmar imagen
cosign sign --key cosign.key ghcr.io/org/app:v1.0.0

# Verificar firma
cosign verify --key cosign.pub ghcr.io/org/app:v1.0.0
```

**2. Admission controller para verificar firma:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-policy
webhooks:
- name: image-policy.example.com
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    operations: ["CREATE", "UPDATE"]
    resources: ["pods"]
  clientConfig:
    service:
      name: image-policy-webhook
      namespace: kube-system
      path: /validate
```

**3. Trivy scanning en CI/CD:**

```yaml
# GitHub Actions / GitLab CI
- name: Scan image
  run: |
    trivy image --exit-code 1 --severity CRITICAL ghcr.io/org/app:$TAG
```

**Criterio de aceptación:**
- [ ] 100% de imágenes firmadas con Cosign antes de entrar al registry
- [ ] Pipeline rechaza imágenes con vulnerabilidades CRITICAL
- [ ] Admission controller bloquea pods con imágenes no firmadas

**Esfuerzo estimado:** 12h | **Costo:** Open source (Cosign + Trivy)

---

#### CONTROL C07: Security Contexts + AppArmor

**Amenazas mitigadas:** TH09 (Imagen infectada en runtime), TH22 (Istio Control Plane saturado), TH24 (Container Escape)
**Prioridad:** P1  
**Timeline:** Sprint 3 (2 semanas)  
**Responsable:** Equipo Platform

**1. Security Context en todos los pods:**

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

**2. AppArmor profile:**

```bash
# Cargar perfil AppArmor en cada nodo
apparmor_parser -r /etc/apparmor.d/docker-default

# Anotar pod para usar perfil
annotations:
  container.apparmor.security.beta.kubernetes.io/app: runtime/default
```

**3. PodSecurity admission (K8s 1.25+):**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
```

**Criterio de aceptación:**
- [ ] 0 containers con `privileged: true` en producción
- [ ] 0 containers ejecutando como root
- [ ] Falco alerta ante intentos de escape

**Esfuerzo estimado:** 10h | **Costo:** Open source

---

#### CONTROL C08: Resource Limits + HPA

**Amenazas mitigadas:** TH19 (Microservice Resource Exhaustion), TH20 (DB Connection Pool Exhaustion)  
**Prioridad:** P1  
**Timeline:** Sprint 3 (2 semanas)  
**Responsable:** Equipo Platform/SRE

**1. Resource limits en todos los pods:**

```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

**2. Horizontal Pod Autoscaler:**

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

**3. PgBouncer para connection pooling:**

```ini
[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 20
```

**Criterio de aceptación:**
- [ ] CPU/Memory limits definidos en 100% de pods
- [ ] HPA activo en todos los deployments de producción
- [ ] PgBouncer delante de PostgreSQL con pool configurado

**Esfuerzo estimado:** 8h | **Costo:** Open source

---

#### CONTROL C09: mTLS Strict Mode (Istio)

**Amenazas mitigadas:** TH02 (Service Mesh Spoofing)  
**Prioridad:** P1  
**Timeline:** Sprint 3 (2 semanas)  
**Responsable:** Equipo Platform

**1. PeerAuthentication global en modo STRICT:**

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

**2. AuthorizationPolicy por servicio:**

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: orders-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: orders-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/api-gateway"]
  - to:
    - operation:
        methods: ["GET", "POST"]
```

**Criterio de aceptación:**
- [ ] 100% del tráfico service-to-service encriptado con mTLS
- [ ] Istio rechaza conexiones sin certificado válido
- [ ] Istio telemetry confirma 0 tráfico en texto plano entre servicios

**Esfuerzo estimado:** 6h | **Costo:** Open source (Istio ya instalado)

---

#### CONTROL C10: Network Policies + Admission Controllers

**Amenazas mitigadas:** TH26 (Bypass de políticas de Istio)  
**Prioridad:** P1  
**Timeline:** Sprint 4 (2 semanas)  
**Responsable:** Equipo Platform

**1. Default deny all en todos los namespaces:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

**2. Allow explícito solo entre servicios autorizados:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-orders-to-postgres
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: orders-service
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

**3. OPA Gatekeeper constraint:**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredNetworkPolicy
metadata:
  name: require-network-policy
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Namespace"]
```

**Criterio de aceptación:**
- [ ] Default deny activo en todos los namespaces de producción
- [ ] 0 pods pueden comunicarse sin NetworkPolicy explícita
- [ ] OPA Gatekeeper bloquea namespaces sin NetworkPolicy

**Esfuerzo estimado:** 10h | **Costo:** Open source

---

#### CONTROL C11: Runtime Security (Falco)

**Amenazas mitigadas:** TH07 (RabbitMQ Message Tampering), TH21 (Queue Flooding) — capa detectiva transversal a todas las amenazas  
**Prioridad:** P1  
**Timeline:** Sprint 4 (2 semanas)  
**Responsable:** Equipo Security/SRE

**1. Instalación con Helm:**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falco.jsonOutput=true \
  --set falco.logLevel=info \
  --namespace falco --create-namespace
```

**2. Reglas críticas:**

```yaml
- rule: Container Escape Attempt
  desc: Detecta intento de escape de container
  condition: >
    spawned_process and container and
    (proc.name in (nsenter, unshare) or
     fd.name startswith /proc/1/ns)
  output: >
    Container escape attempt (user=%user.name
    command=%proc.cmdline container=%container.name)
  priority: CRITICAL

- rule: K8s Secret Access
  desc: Acceso a Kubernetes Secrets desde proceso no autorizado
  condition: >
    ka.target.resource = secrets and
    ka.verb in (get, list, watch) and
    not ka.user.name in (system:serviceaccount:production:app-sa)
  output: >
    K8s Secret accessed (user=%ka.user.name
    secret=%ka.target.name)
  priority: WARNING

- rule: Unexpected Outbound Connection
  desc: Conexión saliente inesperada desde container
  condition: >
    outbound and container and
    not fd.sip in (allowed_outbound_ips)
  output: >
    Unexpected outbound connection (container=%container.name
    dest=%fd.sip:%fd.sport)
  priority: WARNING
```

**3. Alertas a PagerDuty:**

```yaml
program_output:
  enabled: true
  keep_alive: false
  program: "jq '{title: .rule, message: .output}' | curl -X POST https://events.pagerduty.com/v2/enqueue -H 'Content-Type: application/json' -d @-"
```

**Criterio de aceptación:**
- [ ] Falco corriendo en todos los nodos del cluster
- [ ] Alerta en <1 min ante container escape attempt
- [ ] Alerta en <1 min ante acceso anómalo a K8s Secrets
- [ ] Integración con PagerDuty funcionando

**Esfuerzo estimado:** 12h | **Costo:** Open source (Falco)

---

#### CONTROL C12: Immutable Audit Logs

**Amenazas mitigadas:** TH10 (Falta de trazabilidad), TH11 (Logs eliminados o modificados), TH12 (Transaction Repudiation)  
**Prioridad:** P2  
**Timeline:** Sprint 5 (2 semanas)  
**Responsable:** Equipo Observability

**1. WORM storage en Elasticsearch:**

```yaml
# Index Lifecycle Management (ILM)
PUT _ilm/policy/audit-logs-policy
{
  "policy": {
    "phases": {
      "hot": { "actions": { "rollover": { "max_age": "7d" } } },
      "warm": { "actions": { "readonly": {} } },
      "cold": {
        "min_age": "30d",
        "actions": { "freeze": {} }
      },
      "delete": { "min_age": "90d", "actions": { "delete": {} } }
    }
  }
}
```

**2. S3 WORM bucket para backup de logs:**

```bash
aws s3api put-bucket-object-lock-configuration \
  --bucket audit-logs-backup \
  --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":90}}}'
```

**3. K8s Audit Policy:**

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: Metadata
  resources:
  - group: ""
    resources: ["pods", "services"]
```

**Criterio de aceptación:**
- [ ] Logs en Elasticsearch con ILM en modo readonly después de 7 días
- [ ] Backup de logs en S3 con WORM policy de 90 días
- [ ] K8s audit logs habilitados para Secrets y ConfigMaps

**Esfuerzo estimado:** 10h | **Costo:** Costo de S3 storage (~$5-20/mes)

---

#### CONTROL C13: Session Encryption + HTTPOnly Cookies

**Amenazas mitigadas:** TH03 (Session Hijacking en Redis), TH15 (Redis Memory Dump Exposure)  
**Prioridad:** P2  
**Timeline:** Sprint 5 (2 semanas)  
**Responsable:** Equipo Backend

**1. Redis TLS:**

```bash
# redis.conf
tls-port 6380
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
tls-auth-clients yes
```

**2. Cookie flags seguros:**

```javascript
res.cookie('sessionId', sessionToken, {
  httpOnly: true,    // No accesible desde JavaScript
  secure: true,      // Solo HTTPS
  sameSite: 'strict', // Previene CSRF
  maxAge: 3600000,   // 1 hora
  path: '/'
});
```

**3. Encriptación de datos de sesión:**

```javascript
import crypto from 'crypto';

function encryptSession(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}:${cipher.getAuthTag().toString('hex')}`;
}
```

**Criterio de aceptación:**
- [ ] Redis acepta solo conexiones TLS
- [ ] 100% de cookies con flags httpOnly, secure y sameSite
- [ ] Session data encriptada en Redis

**Esfuerzo estimado:** 8h | **Costo:** Open source

---

#### CONTROL C14: Error Handling Framework

**Amenazas mitigadas:** TH13 (API Responses Verbosas), TH17 (Stack Traces en Producción)  
**Prioridad:** P2  
**Timeline:** Sprint 5 (2 semanas)  
**Responsable:** Equipos de desarrollo

**1. Global error handler:**

```javascript
app.use((err, req, res, next) => {
  // Log detallado interno
  logger.error('Internal error', {
    errorId: err.id,
    stack: err.stack,
    userId: req.user?.id,
    path: req.path
  });

  // Respuesta genérica al cliente
  const isProd = process.env.NODE_ENV === 'production';
  res.status(err.status || 500).json({
    error: isProd ? 'Internal server error' : err.message,
    errorId: err.id  // Para correlacionar con logs internos
  });
});
```

**2. Error types definidos:**

```typescript
class AppError extends Error {
  constructor(
    public message: string,
    public status: number,
    public id: string = crypto.randomUUID()
  ) {
    super(message);
  }
}

class NotFoundError extends AppError {
  constructor(msg = 'Resource not found') {
    super(msg, 404);
  }
}

class UnauthorizedError extends AppError {
  constructor(msg = 'Unauthorized') {
    super(msg, 401);
  }
}
```

**3. Sanitización de headers:**

```javascript
app.use(helmet({
  hidePoweredBy: true,       // Elimina X-Powered-By: Express
  noSniff: true,             // X-Content-Type-Options
  xssFilter: true,           // X-XSS-Protection
}));
```

**Criterio de aceptación:**
- [ ] 0 stack traces visibles en responses de producción
- [ ] 0 headers que expongan versiones de software
- [ ] Todos los errores loggean errorId para correlación

**Esfuerzo estimado:** 6h | **Costo:** Open source (helmet)

---

#### CONTROL C15: RBAC Review + Least Privilege

**Amenazas mitigadas:** TH27 (RBAC Misconfiguration / Over-privileged roles)  
**Prioridad:** P2  
**Timeline:** Sprint 6 (2 semanas)  
**Responsable:** Equipo Security/DevOps

**1. Audit de roles existentes:**

```bash
# Listar todos los ClusterRoleBindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | {name: .metadata.name, subjects: .subjects, role: .roleRef}'

# Detectar service accounts con permisos de cluster-admin
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
```

**2. Service account por microservicio (least privilege):**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: orders-service-sa
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: orders-service-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["orders-db-secret"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: orders-service-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: orders-service-sa
roleRef:
  kind: Role
  name: orders-service-role
  apiGroup: rbac.authorization.k8s.io
```

**3. Prohibir uso de default service account:**

```yaml
# OPA Gatekeeper constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoDefaultServiceAccount
metadata:
  name: no-default-sa
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

**Criterio de aceptación:**
- [ ] 0 service accounts con permisos cluster-admin no justificados
- [ ] Cada microservicio tiene su propio service account con permisos mínimos
- [ ] 0 pods usando el service account default

**Esfuerzo estimado:** 12h | **Costo:** Open source

---

[← Anterior: Mapa de Ataque (ATT&CK)](06-mapa-attack.md) | [Siguiente: Matriz de Controles (NIST/ISO 27001) →](08-controles-nist-iso.md)
