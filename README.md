# Análisis de Riesgos: API Gateway para Microservicios

**Grupo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026  
**Curso:** Introducción a la Seguridad Informática (ISI)  
**Escenario:** API Gateway para Microservicios (Kong/AWS + Kubernetes)

---

## Descripción del Proyecto

Este repositorio contiene el análisis completo de riesgos y threat modeling para un sistema de **API Gateway** en arquitectura de microservicios, aplicando las metodologías:

- **STRIDE** - Identificación de amenazas (27 amenazas)
- **DREAD** - Priorización de riesgos (4 amenazas críticas)
- **MITRE ATT&CK** - Mapeo de técnicas de ataque (kill chain completo)
- **NIST Cybersecurity Framework** - Controles de seguridad
- **ISO 27001** - Compliance y alineación de controles

---

## Alcance del Análisis

### Componentes Incluidos:
- **API Gateway:** Kong / AWS API Gateway
- **Autenticación:** OAuth2 + JWT
- **Orquestación:** Kubernetes cluster (masters + nodes)
- **Service Mesh:** Istio con mTLS
- **Microservicios:** Users Service, Inventory Service, Orders Service
- **Capa de Datos:** PostgreSQL, RabbitMQ, Elasticsearch
- **Cache:** Redis (sesiones + rate limiting)
- **Logging:** ELK Stack centralizado
- **Seguridad Perimetral:** WAF (ModSecurity/AWS WAF)

### Componentes Fuera de Alcance:
- Pipeline CI/CD (análisis separado)
- Aplicaciones móviles/web del cliente
- Servicios de terceros externos

---

## Resultados Principales

### Amenazas Identificadas
- **Total:** 27 amenazas distribuidas en STRIDE
- **Críticas (DREAD ≥40):** 4 amenazas
- **Altas (DREAD 30-39):** 18 amenazas
- **Medias (DREAD 20-29):** 5 amenazas

### Top 4 Amenazas Críticas
1. **TH18: API Flooding / DDoS** (Score 46/50) - Sistema inaccesible
2. **TH25: IDOR** (Score 42/50) - Acceso a datos de otros usuarios
3. **TH06: SQL Injection** (Score 41/50) - Exfiltración de base de datos
4. **TH14: PII Exposure in Logs** (Score 40/50) - Multas GDPR

### Plan de Mitigación
- **15 controles** propuestos
- **5 controles P0** (Sprint 1-2, 4 semanas)
- **ROI:** 84:1 ($80K inversión vs. $4.24M pérdida potencial)

---

## Estructura del Repositorio

```
analisis-riesgos-api-gateway/
├── README.md                                   # Este archivo
├── docs/
│   ├── 01-informacion-general.md               # Alcance y contexto del proyecto
│   ├── 02-inventario-activos.md                # 10 activos información + 14 tecnológicos
│   ├── 03-arquitectura-trust-boundaries.md     # 4 zonas de confianza
│   ├── 04-analisis-stride.md                   # 27 amenazas categorizadas
│   ├── 05-priorizacion-dread.md                # Scoring y Top 4 críticas
│   ├── 06-mapa-attack.md                       # Kill chain MITRE ATT&CK
│   ├── 07-plan-mitigacion.md                   # 15 controles con código
│   ├── 08-controles-nist-iso.md                # Mapeo a frameworks
│   ├── 09-riesgos-residuales.md                # 7 riesgos aceptados
│   └── 10-conclusiones.md                      # Recomendaciones y próximos pasos
├── diagrams/
│   ├── arquitectura.png                        # Diagrama de arquitectura
│   ├── trust-boundaries.png                    # 4 zonas de confianza
│   ├── attack-flow.png                         # Kill chain visual
│   └── componentes-tecnicos.png                # Componentes del sistema
├── presentation/
│   └── Presentacion_Oficial_API_Gateway.pptx   # 13 slides
├── prompts/
│   ├── 00-memory-bank.md                       # Contexto para la IA (ver sección IA)
│   ├── 01-informacion-general.txt              # Prompt: alcance y supuestos
│   ├── 02-inventario-activos.txt               # Prompt: inventario de activos
│   ├── 03-arquitectura-trust-boundaries.txt    # Prompt: arquitectura y zonas
│   ├── 04-analisis-stride.txt                  # Prompt: identificación de amenazas
│   ├── 05-priorizacion-dread.txt               # Prompt: scoring DREAD
│   ├── 06-mapa-attack.txt                      # Prompt: mapeo ATT&CK y kill chain
│   ├── 07-plan-mitigacion.txt                  # Prompt: controles de seguridad
│   ├── 08-controles-nist-iso.txt               # Prompt: mapeo a frameworks
│   ├── 09-riesgos-residuales.txt               # Prompt: riesgos residuales
│   └── 10-conclusiones.txt                     # Prompt: conclusiones y recomendaciones
├── templates/
│   └── Plantilla_Analisis_Riesgos.pdf          # Plantilla oficial del curso
├── tools/
│   └── matrices/
│       ├── DREAD_STRIDE_NIST_RESUMEN.xlsx      # DREAD, STRIDE, controles NIST, y resumen
│       ├── matriz_dread.xlsx                   # 27 amenazas exportadas en DREAD
│       ├── matriz_stride.xlsx                  # 27 amenazas exportadas en STRIDE
│       └── stride-threats.csv                  # 27 amenazas exportadas en DREAD y STRIDE
└── references/
    ├── NIST-SP-800-30.pdf                      # Guide for Risk Assessments
    ├── NIST-SP-800-53.pdf                      # Security Controls
    ├── NIST-SP-800-66.pdf                      # Guide for Cybersecurity Insurance
    ├── NIST-SP-800-207.pdf                     # Guide for Zero Trust Architecture
    └── MITRE-ATT&CK-Cloud.pdf                  # Framework for Cloud

```

---

## Herramientas de IA Utilizadas

### Declaración de Uso
Este proyecto utilizó asistencia de Inteligencia Artificial para:
- Estructuración del análisis según plantilla oficial
- Generación de escenarios de ataque detallados
- Código de implementación de controles de seguridad
- Mapeo a frameworks NIST/ISO 27001

### Herramientas Empleadas
- **Claude 4.6 Sonnet** (Anthropic) - Análisis STRIDE/DREAD, redacción técnica
- **ChatGPT GPT-4** (OpenAI) - Validación de controles NIST
- **GitHub Copilot** - Asistencia en código de implementación

### Prompts Documentados
Todos los prompts utilizados están documentados en la carpeta `prompts/` según requisitos del curso.

---

## Checklist de Entregables

| Entregable | Estado | Ubicación |
|------------|--------|-----------|
| ☑ | Diagrama de arquitectura con trust boundaries | `diagrams/` + `docs/03-arquitectura-trust-boundaries.md` |
| ☑ | Inventario de activos (información y tecnológico) | `docs/02-inventario-activos.md` |
| ☑ | Matriz STRIDE completa | `docs/04-analisis-stride.md` (27 amenazas) |
| ☑ | Análisis DREAD de amenazas prioritarias | `docs/05-priorizacion-dread.md` (Top 4) |
| ☑ | Mapa de técnicas ATT&CK | `docs/06-mapa-attack.md` (Kill chain completo) |
| ☑ | Plan de mitigación priorizado | `docs/07-plan-mitigacion.md` (15 controles) |
| ☑ | Controles documentados (NIST/ISO) | `docs/08-controles-nist-iso.md` |
| ☑ | Riesgos residuales identificados | `docs/09-riesgos-residuales.md` (7 riesgos) |
| ☑ | Conclusiones y recomendaciones | `docs/10-conclusiones.md` |

**Todos los entregables:** COMPLETOS

---

## Cronograma de Presentación

- **Fecha de entrega:** 26 de mayo de 2026
- **Duración:** 15 minutos
- **Formato:** Presentación PowerPoint + documento técnico

---

## Equipo

| Integrante | Rol | Email |
|------------|-----|-------|
| Juan Lamolle | Arquitectura, NIST/ISO | juan.lamolle@... |
| Serafín González | Análisis STRIDE, Mitigación | seragonzrov@gmail.com |
| Fernando Rodríguez | DREAD, MITRE ATT&CK | fernando.rodriguez@... |

---

## Referencias

### Frameworks Aplicados
- NIST SP 800-30 Rev. 1 - Guide for Conducting Risk Assessments
- NIST Cybersecurity Framework v1.1
- ISO/IEC 27001:2022 - Information Security Management
- MITRE ATT&CK for Cloud
- MITRE ATT&CK for Containers
- OWASP API Security Top 10 (2023)

### Guías Específicas de Tecnologías
- Kubernetes Security Best Practices
- Istio Security Concepts
- CIS Kubernetes Benchmark v1.8.0
- NIST SP 800-190 - Application Container Security Guide

### Recursos de Agesic (Uruguay)
- Guía de implementación del Marco de Ciberseguridad 5.0
- Metodología de evaluación de riesgo

---

## Licencia

Este proyecto es material académico desarrollado para el curso de Introducción a la Seguridad Informática.

---

## Contacto

Para consultas sobre este análisis:
- **Repositorio:** [GitHub - Análisis Riesgos API Gateway]
- **Email del grupo:** [pendiente]
- **Docente:** Álvaro Pastorini (apastorini@gmail.com)

---

**Última actualización:** 24 de mayo de 2026
