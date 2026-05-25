# 08. Matriz de Controles (NIST/ISO 27001)

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

| ID | Control | Descripción | Referencia |
|----|---------|-------------|------------|
| **AC-1** | Access Control Policy | Política de control de acceso<br/>RBAC en K8s, Istio AuthZ | NIST AC-1<br/>ISO 27001 A.9 |
| **AC-2** | Account Management | Gestión de cuentas de usuario<br/>SSO, provisioning automatizado | NIST AC-2 |
| **AC-3** | Access Enforcement | Enforcement de permisos<br/>Admission controllers, OPA | NIST AC-3 |
| **AC-6** | Least Privilege | Principio de mínimo privilegio<br/>Service accounts únicos | NIST AC-6 |
| **AU-2** | Audit Events | Eventos de auditoría<br/>K8s audit logs, app logs | NIST AU-2<br/>ISO 27001 A.12 |
| **AU-6** | Audit Review/Analysis | Revisión periódica de logs<br/>SIEM correlation, alertas | NIST AU-6 |
| **AU-9** | Protection of Audit Info | Protección de logs<br/>Immutable storage, encryption | NIST AU-9 |
| **CA-2** | Security Assessments | Evaluaciones de seguridad<br/>Pentests trimestrales, audits | NIST CA-2 |
| **CA-7** | Continuous Monitoring | Monitorización continua<br/>Falco, Prometheus, SIEM | NIST CA-7 |
| **CM-2** | Baseline Configuration | Configuración baseline<br/>IaC con Terraform, GitOps | NIST CM-2<br/>ISO 27001 A.12 |
| **CM-3** | Configuration Change Ctrl | Control de cambios<br/>Pull requests, approvals | NIST CM-3 |
| **CM-7** | Least Functionality | Funcionalidad mínima<br/>Distroless images, remove shells | NIST CM-7 |
| **CP-9** | System Backup | Backups del sistema<br/>Velero, pg_basebackup, snapshots | NIST CP-9<br/>ISO 27001 A.12 |
| **IA-2** | User Identification | Autenticación de usuarios<br/>MFA, OAuth2, JWT | NIST IA-2<br/>ISO 27001 A.9 |
| **IA-5** | Authenticator Management | Gestión de autenticadores<br/>Password policies, key rotation | NIST IA-5 |
| **IR-4** | Incident Handling | Manejo de incidentes<br/>Runbooks, on-call, PagerDuty | NIST IR-4<br/>ISO 27001 A.16 |
| **IR-6** | Incident Reporting | Reporte de incidentes<br/>Templates, escalación | NIST IR-6 |
| **RA-5** | Vulnerability Scanning | Escaneo de vulnerabilidades<br/>Trivy, Clair, Snyk | NIST RA-5<br/>ISO 27001 A.12 |
| **SC-7** | Boundary Protection | Protección de perímetros<br/>WAF, Network Policies, Firewall | NIST SC-7<br/>ISO 27001 A.13 |
| **SC-8** | Transmission Confidential | Confidencialidad en tránsito<br/>TLS 1.3, mTLS | NIST SC-8<br/>ISO 27001 A.10 |
| **SC-12** | Cryptographic Key Mgmt | Gestión de claves criptográficas<br/>Vault, cert-manager, rotation | NIST SC-12 |
| **SC-13** | Cryptographic Protection | Uso de criptografía<br/>AES-256, RSA-2048+, SHA-256+ | NIST SC-13 |
| **SC-28** | Protection at Rest | Protección de datos en reposo<br/>LUKS, encrypted EBS volumes | NIST SC-28<br/>ISO 27001 A.10 |
| **SI-2** | Flaw Remediation | Remediación de vulnerabilidades<br/>Patching SLA: critical <7 días | NIST SI-2 |
| **SI-3** | Malicious Code Protection | Protección contra malware<br/>Image scanning, admission control | NIST SI-3 |
| **SI-4** | System Monitoring | Monitorización del sistema<br/>Falco, metrics, logs | NIST SI-4<br/>ISO 27001 A.12 |

---

[← Anterior: Plan de Mitigación](07-plan-mitigacion.md) | [Siguiente: Riesgos Residuales →](09-riesgos-residuales.md)