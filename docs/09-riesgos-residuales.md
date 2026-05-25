# 09. Riesgos Residuales
**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

| ID | Riesgo Residual | Prob. | Imp. | Justificación/Aceptación |
|----|-----------------|-------|------|--------------------------|
| **R01** | Zero-day en Kubernetes | Muy Baja | Crítico | **No hay defensa contra CVEs desconocidos.**<br/>**Mitigación:**<br/>• Patching rápido (<24h cuando se publique CVE)<br/>• Monitoreo intensivo de security advisories<br/>• Bug bounty program<br/>**Estrategia:** MITIGAR + ACEPTAR |
| **R02** | Insider threat (empleado malicioso) | Baja | Alto | **Empleados con acceso legítimo pueden causar daño.**<br/>**Mitigación:**<br/>• Least privilege estricto<br/>• Audit logs exhaustivos<br/>• Background checks en contratación<br/>• Separación de funciones<br/>**Estrategia:** MITIGAR + MONITOREAR |
| **R03** | Advanced Persistent Threat (APT) - nation-state actor | Muy Baja | Crítico | **Actores estatales con recursos ilimitados.**<br/>**Mitigación:**<br/>• Segmentación de red avanzada<br/>• Detección de anomalías con ML<br/>• Threat intelligence feeds<br/>**Estrategia:** MITIGAR + ACEPTAR parcialmente |
| **R04** | Supply chain attack en dependencias (npm, pip, Docker images) | Baja | Alto | **Dependencia comprometida en cadena de suministro.**<br/>**Mitigación:**<br/>• SBOM (Software Bill of Materials)<br/>• Dependency scanning continuo<br/>• Private registry mirrors<br/>• Lock files versionados<br/>**Estrategia:** MITIGAR |
| **R05** | DDoS volumétrico masivo (>100 Gbps) | Baja | Medio | **Ataque masivo satura incluso al cloud provider.**<br/>**Mitigación:**<br/>• Cloudflare/AWS Shield Advanced (SLA 100% uptime)<br/>• Over-provisioning de capacidad<br/>**Transferencia:**<br/>• Seguro de ciberseguridad<br/>**Estrategia:** TRANSFERIR + MITIGAR |
| **R06** | Social engineering (phishing) | Media | Medio | **Usuarios pueden caer en phishing de credenciales.**<br/>**Mitigación:**<br/>• Security awareness training trimestral<br/>• Simulaciones de phishing<br/>• MFA obligatorio (reduce impacto)<br/>**Estrategia:** MITIGAR |
| **R07** | Fallo de proveedor de cloud (regional outage) | Muy Baja | Alto | **Outage regional completo de AWS/GCP/Azure.**<br/>**Mitigación:**<br/>• Multi-AZ deployment<br/>• Backups en región secundaria<br/>• DR plan probado<br/>**Costo de multi-region no justificado actualmente.**<br/>**Estrategia:** MITIGAR + ACEPTAR |

**Estrategia de tratamiento:**
- **R01, R03:** MITIGAR + ACEPTAR (no eliminable completamente)
- **R02:** MITIGAR + MONITOREAR (controles compensatorios)
- **R04:** MITIGAR (scanning + SBOM)
- **R05:** TRANSFERIR (seguro de ciberseguridad) + MITIGAR
- **R06:** MITIGAR (training + MFA)
- **R07:** MITIGAR + ACEPTAR (multi-AZ suficiente, multi-region muy costoso)

---

[← Anterior: Matriz de Controles (NIST/ISO 27001)](08-controles-nist-iso.md) | [Siguiente: Conclusiones y Recomendaciones →](10-conclusiones.md)