# 02. Inventario de Activos

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha:** Mayo 2026

---

## Activos de Información

| ID | Activo | Tipo Dato | Clasificación | Propietario |
|----|--------|-----------|---------------|-------------|
| **A01** | Credenciales de usuario | PII | **Crítico** | Users Svc |
| **A02** | Tokens JWT/OAuth | Auth | **Crítico** | API Gateway |
| **A03** | Datos de pedidos | Transac. | Alto | Orders Svc |
| **A04** | Información de inventario | Negocio | Medio | Inventory |
| **A05** | Logs de aplicación | Operativo | Medio | ELK Stack |
| **A06** | Configuración servicios | Config | Alto | K8s Config |
| **A07** | Secretos de Kubernetes | Credential | **Crítico** | K8s Secrets |
| **A08** | Claves API terceros | Credential | Alto | External |
| **A09** | Session data (Redis) | Sesión | Alto | Redis |
| **A10** | Mensajes en colas | Transac. | Alto | RabbitMQ |

---

## Activos Tecnológicos

| ID | Activo | Tipo | Criticidad | Notas |
|----|--------|------|------------|-------|
| **T01** | API Gateway | Software | **Crítico** | Punto entrada único |
| **T02** | Istio Control Plane | Software | **Crítico** | Gestiona mTLS |
| **T03** | Kubernetes Master | Infra | **Crítico** | Orquestación cluster |
| **T04** | Redis Cluster | Software | Alto | Sesiones y cache |
| **T05** | PostgreSQL DB | Software | **Crítico** | Base de datos principal |
| **T06** | Users Microservice | Software | **Crítico** | Gestión usuarios |
| **T07** | Orders Microservice | Software | Alto | Procesamiento órdenes |
| **T08** | Inventory Service | Software | Medio | Control stock |
| **T09** | RabbitMQ | Software | Alto | Message broker |
| **T10** | Elasticsearch | Software | Medio | Logging centralizado |
| **T11** | WAF | Software | Alto | Protección perimetral |
| **T12** | Kubernetes Nodes | Hardware | Alto | Workers del cluster |
| **T13** | Container Registry | Software | Alto | Almacena imágenes |
| **T14** | Load Balancer | Infra | Alto | Distribución tráfico |

---

## Activos Intangibles

| Activo | Impacto si Comprometido |
|--------|------------------------|
| **Reputación de la empresa** | Pérdida de confianza por brechas de seguridad |
| **Confianza de clientes** | Exposición de datos personales o financieros |
| **Propiedad intelectual** | Algoritmos de negocio en microservicios |
| **Disponibilidad del servicio** | Capacidad de generar revenue 24/7 |
| **Compliance regulatorio** | Cumplimiento GDPR, SOC2, PCI-DSS |

---

## Análisis de Criticidad

### Criterios de Clasificación

**Crítico:**
- Impacto directo en seguridad y disponibilidad del sistema completo
- Exposición de datos sensibles (credenciales, PII)
- Single point of failure

**Alto:**
- Impacto significativo en operaciones
- Exposición de datos de negocio
- Degradación severa del servicio

**Medio:**
- Impacto limitado
- Pérdida de visibilidad o metadata
- Degradación parcial del servicio

---

[← Anterior: Información General](01-informacion-general.md) | [Siguiente: Arquitectura y Trust Boundaries →](03-arquitectura-trust-boundaries.md)
