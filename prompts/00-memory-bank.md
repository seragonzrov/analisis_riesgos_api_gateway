# Memory Bank - Contexto para IA

**Proyecto:** Análisis de Riesgos API Gateway para Microservicios  
**Fecha:** Mayo 2026  
**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez

---

## Archivos de Contexto Necesarios

Para que la IA entienda completamente el proyecto, debe tener acceso a:

### Documentación Principal
- `docs/01-informacion-general.md` - Alcance, supuestos y descripción del sistema
- `docs/02-inventario-activos.md` - Lista completa de activos críticos (información y tecnológicos)
- `docs/03-arquitectura-trust-boundaries.md` - Diagrama de arquitectura con 4 trust boundaries
- `docs/04-analisis-stride.md` - 27 amenazas categorizadas por STRIDE
- `docs/05-priorizacion-dread.md` - Scoring DREAD de amenazas prioritarias
- `docs/06-mapa-attack.md` - Kill chain MITRE ATT&CK completo
- `docs/07-plan-mitigacion.md` - 15 controles de seguridad priorizados
- `docs/08-controles-nist-iso.md` - Mapeo a NIST Cybersecurity Framework e ISO 27001
- `docs/09-riesgos-residuales.md` - Riesgos aceptados y estrategias de tratamiento
- `docs/10-conclusiones.md` - Conclusiones y recomendaciones

### Plantillas y Referencias
- `templates/Plantilla_Analisis_Riesgos.pdf` - Plantilla oficial del curso ISI
- `references/NIST-SP-800-30.pdf` - Metodología de evaluación de riesgos

### Diagramas
- `diagrams/arquitectura.png` - Diagrama de arquitectura con todos los componentes
- `diagrams/attack-flow.png` - Kill chain MITRE ATT&CK
- `diagrams/componentes-tecnicos.png` - Componentes del sistema
- `diagrams/trust-boundaries.png` - 4 zonas de confianza visualizadas

---

## Escenario del Análisis

**Sistema:** API Gateway para Microservicios

**Tecnologías:**
- **API Gateway:** Kong / AWS API Gateway
- **Autenticación:** OAuth2 + JWT
- **Service Mesh:** Istio con mTLS
- **Orquestación:** Kubernetes
- **Microservicios:** Users, Inventory, Orders (Docker containers)
- **Datos:** PostgreSQL, RabbitMQ, Elasticsearch
- **Cache:** Redis
- **Logging:** ELK Stack
- **Seguridad Perimetral:** WAF (ModSecurity/AWS WAF)

**Trust Boundaries Identificados:**
1. **TB1:** Internet (Untrusted - 0% confianza)
2. **TB2:** DMZ (Semi-trusted - 30% confianza) - API Gateway, WAF, Redis
3. **TB3:** Service Mesh (Trusted - 70% confianza) - Istio, microservicios
4. **TB4:** Data Layer (Highly Restricted - 90% confianza) - PostgreSQL, RabbitMQ, Elasticsearch

---

## Metodologías Aplicadas

Las amenazas deben analizarse bajo las siguientes metodologías:

### STRIDE (Identificación de Amenazas)
- **S**poofing: Suplantación de identidad
- **T**ampering: Manipulación de datos/código
- **R**epudiation: Negación de acciones
- **I**nformation Disclosure: Divulgación de información
- **D**enial of Service: Denegación de servicio
- **E**levation of Privilege: Elevación de privilegios

### DREAD (Priorización de Riesgos)
Scoring 1-10 en cada dimensión:
- **D**amage: Daño potencial
- **R**eproducibility: Facilidad de reproducción
- **E**xploitability: Facilidad de explotación
- **A**ffected Users: Usuarios afectados
- **D**iscoverability: Facilidad de descubrimiento

Score total máximo: 50 puntos
- **Crítico:** 40-50
- **Alto:** 30-39
- **Medio:** 20-29

### MITRE ATT&CK
Mapear amenazas a técnicas específicas del framework ATT&CK for Cloud y ATT&CK for Containers.

---

## Formato de Salida Requerido

El output de la IA debe seguir la estructura definida en `templates/Plantilla_Analisis_Riesgos.pdf`, que incluye:

1. Información general y alcance
2. Inventario de activos
3. Arquitectura con trust boundaries
4. Análisis STRIDE (matriz completa)
5. Análisis DREAD (scoring detallado)
6. Mapeo MITRE ATT&CK
7. Plan de mitigación priorizado
8. Controles NIST/ISO 27001
9. Riesgos residuales
10. Conclusiones y recomendaciones

---

## Contexto Adicional

### Amenazas Críticas Identificadas (Top 4)

1. **TH18:** API Flooding / DDoS (Score 46/50)
2. **TH25:** IDOR - Acceso no autorizado (Score 42/50)
3. **TH06:** SQL Injection (Score 41/50)
4. **TH14:** PII Exposure in Logs (Score 40/50)

### Controles Prioritarios (P0)

1. **C01:** Rate Limiting en 3 capas (WAF + Gateway + Application)
2. **C02:** JWT Secret Rotation + RS256
3. **C03:** Log Scrubbing + Encryption
4. **C04:** External Secrets Operator + Vault
5. **C05:** Input Validation Framework

---

## Instrucciones para la IA

Cuando generes contenido para este proyecto:

1. **Mantén consistencia** con los IDs de amenazas (TH01-TH27), activos (A01-A10, T01-T14) y controles (C01-C15)
2. **Usa la terminología correcta** de las metodologías (STRIDE, DREAD, MITRE ATT&CK)
3. **Sigue el formato** de la plantilla oficial
4. **Incluye detalles técnicos** específicos de las tecnologías mencionadas
5. **Mapea cada amenaza** a CWE/CVE cuando sea aplicable
6. **Prioriza controles** basándote en los scores DREAD
7. **Documenta código** de implementación cuando sea relevante

---

**Última actualización:** 24/05/2026
