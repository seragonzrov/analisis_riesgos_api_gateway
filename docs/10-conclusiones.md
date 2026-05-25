# 10. Conclusiones y Recomendaciones

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

### 10.1 Resumen Ejecutivo

Este análisis de riesgos identificó **27 amenazas** en una arquitectura de API Gateway para microservicios, utilizando las metodologías **STRIDE** y **DREAD**.

**HALLAZGOS PRINCIPALES:**

#### 1. Superficie de Ataque Significativa
La arquitectura expone múltiples vectores de ataque desde el perímetro (internet) hasta la capa de datos. Cada componente representa un potencial punto de entrada que debe ser protegido.

#### 2. Amenazas Críticas Priorizadas
Se identificaron **4 amenazas CRÍTICAS** (score 40-50 DREAD):

| Amenaza | Score | Impacto Principal |
|---------|-------|-------------------|
| **TH18:** API Flooding / DDoS | 46/50 | Sistema completamente inaccesible |
| **TH25:** IDOR | 42/50 | Acceso a datos de otros usuarios |
| **TH06:** SQL Injection | 41/50 | Exfiltración total de base de datos |
| **TH14:** PII Exposure in Logs | 40/50 | Multas GDPR (4% revenue anual) |

Estas 4 amenazas requieren mitigación **INMEDIATA** (Sprint 1-2).

#### 3. Trust Boundaries Bien Definidos
La segmentación en **4 zonas de confianza** (Internet 0%, DMZ 30%, Service Mesh 70%, Data Layer 90%) permite aplicar controles de seguridad **proporcionales al nivel de riesgo** de cada capa.

#### 4. Defensa en Profundidad es Esencial
Ningún control único es suficiente. Se requieren **múltiples capas de seguridad**:
- **WAF** (perimetral)
- **API Gateway** (autenticación/autorización)
- **Service Mesh** (mTLS, policies)
- **Application** (input validation, authorization)
- **Runtime security** (Falco)
- **Data layer** (encryption, access control)

#### 5. Mapeo a MITRE ATT&CK
Se mapearon **28 técnicas ATT&CK**, cubriendo las **11 fases del kill chain** desde Initial Access hasta Impact. Esto permite entender cómo un atacante real encadenaría múltiples amenazas.

#### 6. Controles Alineados a Frameworks
Los **15 controles** propuestos están alineados a **NIST Cybersecurity Framework** e **ISO 27001**, facilitando auditorías de compliance.

#### 7. Riesgos Residuales Identificados
Se documentaron **7 riesgos** que persisten después de implementar controles, con estrategias de aceptación o transferencia justificadas.

**SITUACIÓN ACTUAL:**
- 27 amenazas identificadas
- 4 críticas, 16 altas, 7 medias
- 0 controles implementados actualmente
- Exposición significativa a ataques

**SITUACIÓN OBJETIVO (post-implementación):**
- 15 controles de seguridad implementados
- 4 amenazas críticas mitigadas a nivel MEDIO/BAJO
- 16 amenazas altas mitigadas
- 7 riesgos residuales documentados y aceptados
- Postura de seguridad robusta con defensa en profundidad

### 10.2 Recomendaciones Prioritarias

#### RECOMENDACIÓN #1: IMPLEMENTAR CONTROLES P0 EN SPRINT 1-2 (CRÍTICO)

Los **5 controles P0** mitigan las 4 amenazas críticas identificadas:

| Control | Timeline | Inversión | Impacto | Mitiga |
|---------|----------|-----------|---------|--------|
| **C01:** Rate Limiting 3 capas | 2 semanas | Baja | Crítico | TH18 (DDoS) |
| **C02:** JWT Secret Rotation + RS256 | 2 semanas | Media | Alto | TH01 (falsificación) |
| **C03:** Log Scrubbing + Encryption | 2 semanas | Baja | Crítico | TH14 (PII exposure) |
| **C04:** External Secrets Operator | 2 semanas | Media | Alto | TH16 (secrets exposure) |
| **C05:** Input Validation Framework | 3 semanas | Alta | Crítico | TH06 (SQL injection)<br/>TH25 (IDOR) |

**TOTAL INVERSIÓN P0:** ~6 semanas de equipo de 3 personas = ~18 semanas-persona

**ROI:**
- **Inversión:** ~$50K en ingeniería
- **Pérdida potencial:** $4.24M promedio de violación de datos (IBM 2023)
- **Multas GDPR:** 4% del revenue anual
- **ROI:** 53:1 a 84:1

#### RECOMENDACIÓN #2: ESTABLECER SECURITY CHAMPIONS PROGRAM

Cada equipo de desarrollo debe tener un **Security Champion** que:
- Revisa PRs con foco en seguridad
- Asiste a training mensual de seguridad
- Es punto de contacto para consultas de seguridad
- Participa en threat modeling de nuevas features

**Beneficio:** Shift security left, detectar problemas antes de producción.

#### RECOMENDACIÓN #3: IMPLEMENTAR CONTINUOUS SECURITY TESTING

Integrar en **CI/CD pipeline:**
- **SAST** (Static Analysis): SonarQube, Semgrep
- **DAST** (Dynamic Analysis): OWASP ZAP en staging
- **Dependency scanning:** Snyk, Dependabot
- **Image scanning:** Trivy en registry
- **Infrastructure scanning:** Checkov para IaC

**Gate de calidad:** PR no mergea si hay vulnerabilidades CRITICAL sin resolver.

#### RECOMENDACIÓN #4: ESTABLECER MÉTRICAS DE SEGURIDAD (KPIs)

Trackear **mensualmente:**

| Métrica | Baseline | Objetivo | Impacto |
|---------|----------|----------|---------|
| MTTD (Mean Time To Detect) | 4 horas | <15 min | Detección rápida |
| MTTR (Mean Time To Respond) | 12 horas | <1 hora | Respuesta ágil |
| Vuln. críticas sin patchear | 12 | 0% | Superficie reducida |
| Containers con image firmado | 0% | 100% | Supply chain seguro |
| Intentos de ataque bloqueados | - | Trend ↓ | Efectividad WAF |
| Uptime del API Gateway | 99.5% | 99.95% | Alta disponibilidad |

**Dashboard ejecutivo** con estas métricas en Grafana.

#### RECOMENDACIÓN #5: REALIZAR PENTESTS Y RED TEAM EXERCISES

**Cronograma:**
- **Pentest externo:** Trimestral (Q1, Q2, Q3, Q4)
- **Red team exercise:** Semestral (simular APT)
- **Bug bounty program:** Continuo (HackerOne, Bugcrowd)

**Beneficio:** Validar que los controles implementados realmente funcionan.

#### RECOMENDACIÓN #6: PREPARAR PARA AUDITORÍAS DE COMPLIANCE

**Roadmap de compliance:**

| Fecha | Hito | Descripción |
|-------|------|-------------|
| **Q2 2026** | Controles P0 | Implementación completa |
| **Q3 2026** | SOC 2 Type I | Design effectiveness |
| **Q4 2026** | SOC 2 Type II | Operational effectiveness |
| **Q1 2027** | ISO 27001 | Certification |

**Documentación requerida:**
- Este documento de análisis de riesgos
- Políticas de seguridad formales
- Runbooks de incident response
- Evidencia de controles (screenshots, configs, logs)

### 10.3 Próximos Pasos

#### INMEDIATO (Esta semana)
- [ ] Presentar este análisis a liderazgo técnico
- [ ] Obtener buy-in y presupuesto para controles P0
- [ ] Asignar ownership de cada control a un equipo
- [ ] Crear épicas en Jira para los 15 controles

#### SPRINT 1 (Semanas 1-2)
- [ ] Implementar C01: Rate Limiting
- [ ] Implementar C02: JWT Rotation
- [ ] Implementar C03: Log Scrubbing
- [ ] Weekly check-in de progreso

#### SPRINT 2 (Semanas 3-4)
- [ ] Implementar C04: External Secrets
- [ ] Implementar C05: Input Validation
- [ ] Pentest interno de controles P0

#### SPRINT 3-4 (Semanas 5-8)
- [ ] Implementar controles P1 (C06-C11)
- [ ] Setup Falco (runtime security)
- [ ] Container hardening

#### MENSUAL (Continuo)
- [ ] Re-evaluar threat model (nuevas amenazas?)
- [ ] Revisar métricas de seguridad
- [ ] Actualizar este documento con lecciones aprendidas

#### TRIMESTRAL (Continuo)
- [ ] Pentest externo
- [ ] Security awareness training para toda la compañía
- [ ] Review de riesgos residuales (aún son aceptables?)

#### ANUAL (Continuo)
- [ ] Red team exercise
- [ ] Disaster recovery drill
- [ ] Actualización mayor de este documento

---

[← Anterior: Riesgos Residuales](09-riesgos-residuales.md)