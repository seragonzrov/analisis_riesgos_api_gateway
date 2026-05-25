# 01. Información General del Proyecto

**Equipo:** Juan Lamolle, Serafín González, Fernando Rodríguez  
**Fecha de inicio:** 01/05/2026  
**Fecha de entrega:** 26/05/2026  
**Versión:** 1.0

---

## Descripción del Sistema

El sistema bajo análisis es una arquitectura de microservicios moderna que utiliza un **API Gateway** como punto de entrada único para todas las requests de clientes externos. La infraestructura está desplegada en **Kubernetes** y utiliza un **Service Mesh (Istio)** para la comunicación segura entre servicios internos.

### Componentes Principales

- **API Gateway:** Kong / AWS API Gateway con autenticación OAuth2/JWT
- **WAF:** Web Application Firewall para protección perimetral
- **Service Mesh:** Istio con mTLS para comunicación service-to-service
- **Microservicios:** Users Service, Inventory Service, Orders Service
- **Capa de datos:** PostgreSQL, RabbitMQ, Elasticsearch
- **Cache distribuido:** Redis
- **Orquestación:** Kubernetes cluster
- **Observabilidad:** ELK Stack (Elasticsearch, Logstash, Kibana)

---

## Alcance del Análisis

### Componentes Incluidos

- API Gateway (Kong/AWS API Gateway)
- Web Application Firewall (ModSecurity/AWS WAF)
- Service Mesh control plane (Istio)
- Microservicios backend (Users, Inventory, Orders)
- Kubernetes cluster (masters, nodes, RBAC)
- Capa de persistencia (PostgreSQL, RabbitMQ, Elasticsearch)
- Redis cache para sesiones y rate limiting
- Sistema de logging centralizado (ELK Stack)
- Comunicación service-to-service (mTLS)
- Mecanismos de autenticación y autorización

### Componentes Fuera de Alcance

| Componente | Razón de Exclusión |
|------------|-------------------|
| **Pipeline de CI/CD** (Jenkins/GitLab CI) | No está expuesto a internet y tiene controles separados |
| **Entornos de desarrollo local** | No contienen datos de producción |
| **Servicios de terceros externos** (APIs de partners) | Fuera de nuestro control directo |
| **Aplicaciones móviles/web del cliente** | Tema de análisis separado |

---

## Supuestos

- El sistema está desplegado en un cloud provider (AWS/GCP/Azure) con configuraciones de seguridad baseline del proveedor
- Existe un equipo de operaciones con acceso a los clusters de Kubernetes
- Los desarrolladores tienen acceso limitado vía RBAC de Kubernetes
- Se asume que el código de los microservicios sigue prácticas de desarrollo seguro (OWASP guidelines)
- Los certificados TLS/SSL son gestionados por un servicio como Let's Encrypt o AWS Certificate Manager
- Existe un plan de disaster recovery básico con backups regulares
- El tráfico entre zonas de disponibilidad está encriptado
- Se aplican security groups/network policies básicas del cloud provider

---

[← Volver al índice principal](../README.md) | [Siguiente: Inventario de Activos →](02-inventario-activos.md)
