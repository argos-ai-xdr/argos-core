# deploy/

Un Helm chart real por servicio, promovido vía Argo CD desde `argos-platform` (ADR-015) — nunca `helm install` manual contra `laboratory`/`osc`.

Este bootstrap incluye un chart completo y real como plantilla (`helm/normalizer/`); los otros ocho servicios siguen el mismo patrón (`Chart.yaml` + `values.yaml` + `Deployment`/`ServiceAccount`/`NetworkPolicy` compatibles con Pod Security `restricted`) y se generan cuando cada uno tenga imagen construida — no antes, para no versionar charts que despliegan una imagen que no existe.

`kustomize/` no tiene overlays propios todavía: los namespaces, RBAC y NetworkPolicy base ya viven en `argos-platform/kubernetes/`; este repositorio solo añadirá overlays si algún servicio necesita algo que no esté ya cubierto por esa base.
