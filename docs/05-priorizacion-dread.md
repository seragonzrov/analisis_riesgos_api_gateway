# 05. Análisis de Riesgos - Metodología DREAD

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

### 5.1 Criterios DREAD

| Criterio | Descripción | Peso |
|----------|-------------|------|
| **D**amage | Daño potencial si se explota | 1.0 |
| **R**eproducibility | Facilidad de reproducción | 1.0 |
| **E**xploitability | Dificultad para explotar | 1.0 |
| **A**ffected Users | Cantidad de usuarios afectados | 1.0 |
| **D**iscoverability | Facilidad de descubrimiento | 1.0 |

**Escala:** 1-10 (1=mínimo, 10=máximo)

#### Interpretación de Escala

**Damage (Daño):**
- **10** = Compromiso completo del sistema
- **7-9** = Daño significativo a múltiples activos
- **4-6** = Daño moderado, activos limitados
- **1-3** = Daño mínimo, no crítico

**Reproducibility (Reproducibilidad):**
- **10** = Siempre funciona, 100% reproducible
- **7-9** = Funciona frecuentemente
- **4-6** = Funciona a veces, condiciones específicas
- **1-3** = Rara vez funciona, muy específico

**Exploitability (Explotabilidad):**
- **10** = Muy fácil, script kiddie puede hacerlo
- **7-9** = Fácil, herramientas disponibles
- **4-6** = Moderado, requiere conocimiento técnico
- **1-3** = Difícil, requiere expertise avanzado

**Affected Users (Usuarios Afectados):**
- **10** = Todos los usuarios del sistema
- **7-9** = Muchos usuarios
- **4-6** = Algunos usuarios
- **1-3** = Muy pocos usuarios

**Discoverability (Descubribilidad):**
- **10** = Muy fácil de encontrar, obvio
- **7-9** = Fácil, scanners automáticos
- **4-6** = Promedio, requiere análisis
- **1-3** = Difícil, requiere acceso privilegiado

### 5.2 Matriz de Riesgos

| ID | Amenaza | D | R | E | A | D | TOTAL | Nivel |
|----|---------|---|---|---|---|---|-------|-------|
| **TH18** | API Flooding / DDoS | 9 | 10 | 9 | 10 | 8 | **46/50** | CRÍTICO |
| **TH25** | IDOR - Acceso no autorizado | 7 | 9 | 9 | 8 | 9 | **42/50** | CRÍTICO |
| **TH06** | SQL Injection | 10 | 8 | 6 | 9 | 8 | **41/50** | CRÍTICO |
| **TH14** | PII Exposure in Logs | 10 | 9 | 6 | 8 | 7 | **40/50** | CRÍTICO |
| **TH09** | Container Image Tampering | 10 | 8 | 6 | 10 | 5 | **39/50** | ALTO |
| **TH01** | JWT Token Falsification | 9 | 9 | 5 | 9 | 7 | **39/50** | ALTO |
| **TH16** | K8s Secret Exposure | 10 | 8 | 5 | 9 | 6 | **38/50** | ALTO |
| **TH23** | JWT Privilege Escalation | 9 | 7 | 6 | 8 | 7 | **37/50** | ALTO |
| **TH03** | Session Hijacking (Redis) | 8 | 7 | 6 | 7 | 7 | **35/50** | ALTO |
| **TH19** | Microservice Resource Exh. | 8 | 7 | 7 | 8 | 6 | **36/50** | ALTO |
| **TH20** | DB Connection Pool Exhaust | 8 | 6 | 6 | 9 | 6 | **35/50** | ALTO |
| **TH24** | Container Escape to Host | 10 | 5 | 4 | 9 | 5 | **33/50** | ALTO |
| **TH02** | Service Mesh Spoofing | 8 | 5 | 5 | 8 | 5 | **31/50** | ALTO |
| **TH07** | RabbitMQ Message Tampering | 7 | 6 | 5 | 7 | 5 | **30/50** | ALTO |
| **TH05** | Request Parameter Tampering | 6 | 8 | 7 | 6 | 7 | **34/50** | ALTO |
| **TH13** | Verbose API Responses | 5 | 8 | 8 | 6 | 8 | **35/50** | ALTO |
| **TH10** | Lack of Audit Trail | 6 | 7 | 6 | 7 | 6 | **32/50** | ALTO |
| **TH11** | Log Tampering/Deletion | 7 | 6 | 5 | 8 | 5 | **31/50** | ALTO |
| **TH21** | RabbitMQ Queue Flooding | 7 | 7 | 6 | 7 | 6 | **33/50** | ALTO |
| **TH26** | Istio Policy Bypass | 8 | 5 | 4 | 8 | 5 | **30/50** | ALTO |
| **TH27** | RBAC Misconfiguration | 7 | 6 | 5 | 6 | 6 | **30/50** | ALTO |
| **TH08** | K8s ConfigMap Modification | 8 | 5 | 4 | 7 | 5 | **29/50** | MEDIO |
| **TH15** | Redis Memory Dump Exposure | 7 | 5 | 4 | 6 | 4 | **26/50** | MEDIO |
| **TH17** | Stack Traces in Production | 4 | 8 | 8 | 5 | 8 | **33/50** | ALTO |
| **TH22** | Istio Control Plane DOS | 8 | 4 | 4 | 8 | 4 | **28/50** | MEDIO |
| **TH04** | API Key Theft | 6 | 6 | 6 | 5 | 6 | **29/50** | MEDIO |
| **TH12** | Transaction Repudiation | 5 | 5 | 5 | 6 | 5 | **26/50** | MEDIO |

### 5.3 Escala de Severidad

- **CRÍTICO (40-50):** Remediar inmediatamente (Sprint actual)
- **ALTO (30-39):** Remediar ASAP (Próximo sprint)
- **MEDIO (20-29):** Remediar en 2-3 sprints
- **BAJO (10-19):** Monitorear y evaluar
- **MÍNIMO (1-9):** Aceptar riesgo documentado

**Distribución de amenazas:**
- **CRÍTICO:** 4 amenazas (TH18, TH25, TH06, TH14)
- **ALTO:** 18 amenazas
- **MEDIO:** 5 amenazas
- **BAJO:** 0 amenazas
- **MÍNIMO:** 0 amenazas

**TOTAL:** 27 amenazas identificadas

---

[← Anterior: Análisis de Amenazas - Metodología STRIDE](04-analisis-stride.md) | [Siguiente: Mapa de Ataque (ATT&CK) →](06-mapa-attack.md)