# 04. Análisis de Amenazas - Metodología STRIDE

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

### 4.1 Aplicación de STRIDE

**Categorías STRIDE:**

| Categoría | Descripción |
|-----------|-------------|
| **S** - Spoofing | Suplantación de identidad |
| **T** - Tampering | Manipulación de datos o código |
| **R** - Repudiation | Negación de acciones realizadas |
| **I** - Information Disclosure | Divulgación de información sensible |
| **D** - DoS | Denegación de servicio |
| **E** - Elevation of Privilege | Elevación de privilegios |

### 4.2 Matriz de Amenazas por Componente

| ID | Componente | Categoría | Descripción de la Amenaza | CVE/CWE |
|----|------------|-----------|---------------------------|---------|
| **TH01** | API Gateway | Spoofing | Token JWT falsificado con secreto débil | CWE-287 |
| **TH02** | Service Mesh | Spoofing | Microservicio malicioso se hace pasar por servicio legítimo sin cert válido | CWE-295 |
| **TH03** | Redis | Spoofing | Session hijacking vía session ID robado | CWE-384 |
| **TH04** | API Calls | Spoofing | API key theft desde código/logs | CWE-798 |
| **TH05** | API Gateway | Tampering | Manipulación de request params en vuelo | CWE-20 |
| **TH06** | PostgreSQL | Tampering | SQL Injection vía input no sanitizado | CWE-89 |
| **TH07** | RabbitMQ | Tampering | Modificación de mensajes en cola | CWE-345 |
| **TH08** | Kubernetes | Tampering | ConfigMap/Secret modification runtime | CWE-732 |
| **TH09** | Container Image | Tampering | Imagen Docker infectada en registry | CWE-494 |
| **TH10** | API Gateway | Repudiation | Falta de trazabilidad de acciones | CWE-778 |
| **TH11** | Microservices | Repudiation | Logs eliminados o modificados | CWE-117 |
| **TH12** | Transactions | Repudiation | Usuario niega haber realizado compra | CWE-284 |
| **TH13** | API Gateway | Info Discl | API responses verbosas exponen stack | CWE-209 |
| **TH14** | Logs | Info Discl | PII (emails, SSN) en logs sin encriptar | CWE-532 |
| **TH15** | Redis | Info Discl | Memory dump de Redis expone sesiones | CWE-316 |
| **TH16** | Kubernetes | Info Discl | Secrets en env vars accesibles vía API | CWE-526 |
| **TH17** | Error Messages | Info Discl | Stack traces en producción | CWE-209 |
| **TH18** | API Gateway | DoS | Request flooding satura recursos | CWE-770 |
| **TH19** | Microservices | DoS | Servicio consume toda CPU/memoria | CWE-400 |
| **TH20** | PostgreSQL | DoS | Connection pool exhaustion | CWE-404 |
| **TH21** | RabbitMQ | DoS | Queue flooding con mensajes maliciosos | CWE-770 |
| **TH22** | Istio | DoS | Control plane saturado (DOS) | CWE-400 |
| **TH23** | API Gateway | Elevation | JWT claim manipulation para admin role | CWE-269 |
| **TH24** | Kubernetes | Elevation | Container escape a nodo host | CWE-250 |
| **TH25** | Microservices | Elevation | IDOR permite acceso a recursos ajenos | CWE-639 |
| **TH26** | Service Mesh | Elevation | Bypass de políticas de Istio | CWE-863 |
| **TH27** | RBAC | Elevation | Role misconfiguration (over-privileged) | CWE-266 |

### 4.3 Detalle de Amenazas Principales

#### AMENAZA TH01: Token JWT Falsificado

**Categoría STRIDE:** Spoofing (Suplantación de Identidad)

**Descripción:**  
Un atacante obtiene el secreto JWT (HS256) o descubre una configuración débil que permite generar tokens válidos sin autenticación. Con el secreto, puede crear tokens con cualquier claim (user_id, roles) y autenticarse como cualquier usuario del sistema.

**Activos afectados:** A01 (Credenciales), A02 (Tokens JWT), T01 (API Gateway)

**Probabilidad:** Media

El secreto podría estar expuesto en:
- Variables de entorno loggeadas
- Código fuente en repositorio público
- ConfigMaps de K8s sin encriptar
- Backup dumps accidentales

**Impacto:** Alto
- Acceso completo a todos los endpoints protegidos
- Capacidad de actuar como cualquier usuario (incluyendo admins)
- Exfiltración de datos masiva
- Modificación de datos sin detección

**Técnicas ATT&CK relacionadas:**
- T1078 - Valid Accounts (usar credenciales legítimas falsificadas)
- T1550.001 - Use Alternate Authentication Material (tokens)
- T1552.001 - Credentials In Files (secreto en config files)

**Vector de ataque:**
1. Atacante encuentra secreto JWT en variable de entorno loggeada
2. Usa jwt.io o biblioteca JWT para crear token con claims arbitrarios
3. Inyecta token en header `Authorization: Bearer <token>`
4. API Gateway valida firma (correcta porque usa el secreto real)
5. Accede a recursos sin restricción

**Mitigación recomendada:** Ver sección 7 (Control C02)

---

#### AMENAZA TH06: SQL Injection

**Categoría STRIDE:** Tampering (Manipulación de Datos)

**Descripción:**  
Un endpoint de microservicio concatena input del usuario directamente en una query SQL sin sanitización, permitiendo inyección de código SQL arbitrario.

**Activos afectados:** A03 (Datos pedidos), A04 (Inventario), T05 (PostgreSQL)

**Probabilidad:** Baja (si se usan ORMs correctamente)

**Impacto:** Crítico
- Exfiltración completa de base de datos (UNION-based injection)
- Modificación de datos (UPDATE, DELETE)
- Elevación de privilegios (modificar roles en tabla users)
- Posible ejecución de comandos OS (vía funciones como xp_cmdshell en SQL Server)

**Técnicas ATT&CK relacionadas:**
- T1190 - Exploit Public-Facing Application
- T1213 - Data from Information Repositories (DB)
- T1485 - Data Destruction (DROP TABLE)

**Vector de ataque:**
1. Atacante identifica endpoint de búsqueda: `GET /api/orders?user_id=123`
2. Inyecta payload: `user_id=123' OR '1'='1`
3. Query vulnerable: `SELECT * FROM orders WHERE user_id = '123' OR '1'='1'`
4. Retorna TODAS las órdenes de todos los usuarios
5. Escala a exfiltración con UNION SELECT

**Mitigación recomendada:** Ver sección 7 (Control C05)

---

#### AMENAZA TH14: PII Exposure in Logs

**Categoría STRIDE:** Information Disclosure

**Descripción:**  
Los desarrolladores loggean requests completos para debugging, incluyendo PII como emails, nombres completos, direcciones, o incluso datos de tarjetas de crédito. Los logs se centralizan en Elasticsearch sin encriptación y son accesibles por múltiples equipos.

**Activos afectados:** A01 (Credenciales), A05 (Logs), T10 (Elasticsearch)

**Probabilidad:** Alta
- Muy común en aplicaciones web
- Los desarrolladores priorizan debugging sobre compliance
- Logs suelen tener retención larga (90+ días)

**Impacto:** Crítico (desde perspectiva de compliance)
- Violación de GDPR (Art. 5, 32)
- Multas de hasta 4% del revenue anual global
- Pérdida de confianza de clientes
- Auditorías regulatorias adversas
- Requisitos de notificación de brecha (72 horas)

**Técnicas ATT&CK relacionadas:**
- T1530 - Data from Cloud Storage Object (Elasticsearch)
- T1005 - Data from Local System

**Vector de ataque:**
1. Log statement: `logger.info(Request received: ${JSON.stringify(req.body)})`
2. Request contiene: `{ email: "user@example.com", password: "..." }`
3. Logs se centralizan en Elasticsearch
4. Atacante obtiene acceso a Kibana (credenciales débiles, no MFA)
5. Busca: `email:*@*` en Kibana
6. Exfiltra miles de emails y datos personales

**Mitigación recomendada:** Ver sección 7 (Control C03)

---

#### AMENAZA TH18: API Flooding / DDoS

**Categoría STRIDE:** Denial of Service

**Descripción:**  
Un atacante genera millones de requests al API Gateway, saturando recursos de CPU/memoria/red y haciendo el sistema inaccesible para usuarios legítimos.

**Activos afectados:** T01 (API Gateway), T06-T08 (Microservices), Todos usuarios

**Probabilidad:** Alta
- No requiere autenticación (endpoints públicos)
- Herramientas gratuitas disponibles (LOIC, Slowloris)
- Botnets disponibles para alquiler

**Impacto:** Crítico
- Sistema completamente inaccesible
- Pérdida directa de revenue (no hay transacciones)
- Daño reputacional
- Costos de cloud scaling descontrolado

**Técnicas ATT&CK relacionadas:**
- T1499.002 - Service Exhaustion Flood
- T1499.004 - Application or System Exploitation

**Vector de ataque:**
1. Atacante usa botnet de 10,000 IPs
2. Cada IP envía 100 req/sec a endpoints públicos
3. Total: 1,000,000 req/sec
4. API Gateway intenta procesar todas
5. CPU al 100%, memoria agotada
6. Health checks fallan
7. Sistema se cae completamente

**Mitigación recomendada:** Ver sección 7 (Control C01)

---

#### AMENAZA TH24: Container Escape

**Categoría STRIDE:** Elevation of Privilege

**Descripción:**  
Un atacante que ha comprometido un container explota una vulnerabilidad en el runtime (runC, containerd) para escapar al nodo host y obtener acceso root al sistema operativo subyacente.

**Activos afectados:** T12 (K8s Nodes), T03 (K8s Master), Todos los containers

**Probabilidad:** Baja
- Requiere CVE específico en runtime
- Configuraciones de seguridad pueden prevenir

**Impacto:** Alto
- Control total del nodo host
- Acceso a todos los containers en el nodo
- Posibilidad de acceder a secretos de kubelet
- Movimiento lateral a otros nodos
- Persistencia difícil de detectar

**Técnicas ATT&CK relacionadas:**
- T1611 - Escape to Host
- T1068 - Exploitation for Privilege Escalation

**Vector de ataque:**
1. Atacante ejecuta código en container (vía RCE en app)
2. Explota CVE-2019-5736 (runC vulnerability)
3. Sobrescribe binario de runC en host
4. Próxima ejecución de container da acceso root al host
5. Desde host, accede a `/var/lib/kubelet/pods/`
6. Lee secretos de otros pods
7. Pivotea a Kubernetes API con service account token robado

**Mitigación recomendada:** Ver sección 7 (Control C07)

---

#### AMENAZA TH25: IDOR (Insecure Direct Object Reference)

**Categoría STRIDE:** Elevation of Privilege

**Descripción:**  
La aplicación no valida que el usuario tenga ownership del recurso solicitado, permitiendo acceso simplemente cambiando un ID en la URL.

**Activos afectados:** A03 (Datos de pedidos), A01 (Datos de usuarios)

**Probabilidad:** Alta
- Muy común en APIs REST
- OWASP API Security Top 10 #1

**Impacto:** Crítico
- Acceso a información de otros usuarios
- Violación de confidencialidad
- Posible exfiltración masiva vía enumeración

**Técnicas ATT&CK relacionadas:**
- T1190 - Exploit Public-Facing Application
- T1087 - Account Discovery (enumeration)

**Vector de ataque:**
1. Usuario autenticado hace `GET /api/orders/12345`
2. Ve su propia orden
3. Cambia ID: `GET /api/orders/12346`
4. Backend NO valida ownership
5. Retorna orden de otro usuario
6. Atacante enumera: 12347, 12348, 12349...
7. Exfiltra todas las órdenes de todos los usuarios

**Mitigación recomendada:** Ver sección 7 (Control C05)

---

[← Anterior: Arquitectura y Trust Boundaries](03-arquitectura-trust-boundaries.md) | [Siguiente: Análisis de Riesgos - Metodología DREAD →](05-priorizacion-dread.md)