# AutoConfine

[![Go Report Card](https://goreportcard.com/badge/github.com/ValentinTorassa/autoconfine)](https://goreportcard.com/report/github.com/ValentinTorassa/autoconfine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**AutoConfine** es un prototipo que genera perfiles seccomp de **mínimos privilegios** para contenedores [OCI](https://opencontainers.org/) a partir de una traza de syscalls. El objetivo es capturar esa traza observando el kernel con **eBPF**; esa parte todavía no está implementada (ver [Estado](#estado)).

> Los contenedores se ejecutan por defecto con perfiles seccomp que permiten ~300 syscalls. Una aplicación real usa típicamente entre 40 y 80. AutoConfine busca cerrar esa brecha automáticamente.

## Estado

Prototipo. Lo que funciona hoy es el procesamiento: generar el perfil desde una traza, validarlo, comparar y combinar trazas, y correr el contenedor con Podman aplicando el perfil.

- **La captura eBPF no está implementada.** `autoconfine learn` usa `NoopProbe`, que emite syscalls sintéticas (un ciclo fijo de diez syscalls comunes) en lugar de observar el contenedor. `EBPFProbe` existe como interfaz, pero su `Attach` devuelve un error.
- **`--audit` todavía no monitorea drift en vivo:** hoy solo registra que el modo audit se activó.
- Por eso, una traza o un reporte de reducción que salga de `learn` no describe una aplicación real.

## Modos de operación

| Modo | Comando | Función |
|---|---|---|
| Aprender | `autoconfine learn` | Registra las syscalls de un contenedor en una traza. Hoy la traza es sintética (ver [Estado](#estado)). |
| Generar | `autoconfine generate` | Convierte la traza en un perfil seccomp JSON compatible con OCI. |
| Aplicar | `autoconfine enforce` | Ejecuta el contenedor con Podman aplicando el perfil derivado. |
| Auditar | `autoconfine enforce --audit` | Pensado para alertar cuando aparece una syscall fuera del perfil aprendido (drift detection). Hoy solo registra que el modo está activo. |

## Nuevas funciones de análisis

| Comando | Uso | Descripción |
|---|---|---|
| `autoconfine summary trace.jsonl` | `autoconfine summary nginx.trace.jsonl --report report.md` | Estadísticas de reducción y reporte markdown. |
| `autoconfine validate` | `autoconfine validate nginx-seccomp.json` | Valida que el JSON seccomp sea parseable y tenga estructura mínima. |
| `autoconfine compare` | `autoconfine compare a.trace.jsonl b.trace.jsonl` | Diferencias entre dos trazas. Usar `--profiles` para comparar perfiles. |
| `autoconfine merge` | `autoconfine merge t1.jsonl t2.jsonl --out merged.jsonl` | Combina trazas de varias fases de aprendizaje. |

## Instalación

```bash
go install github.com/ValentinTorassa/autoconfine/cmd/autoconfine@latest
```

Requisitos de runtime (los de eBPF aplican cuando la sonda real esté implementada):

- Linux con kernel >= 5.8 (para eBPF CO-RE).
- Cabeceras del kernel o BTF disponible.
- Podman >= 4.0.
- Permisos suficientes para cargar programas eBPF (`CAP_BPF`, `CAP_PERFMON` o root).

## Uso rápido

```bash
# 1. Fase de aprendizaje
autoconfine learn --image nginx --duration 5m --out nginx.trace.jsonl

# 2. Generación del perfil
autoconfine generate nginx.trace.jsonl --out nginx-seccomp.json

# 3. Ejecución protegida
autoconfine enforce --profile nginx-seccomp.json -- podman run --rm nginx
```

## Arquitectura

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   learn     │────▶│  generate   │────▶│   enforce   │
│   (eBPF)    │     │ (seccomp)   │     │  (Podman)   │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                              ▼
                                        ┌─────────────┐
                                        │ drift audit │
                                        └─────────────┘
```

El diagrama es el diseño buscado. Hoy `learn` corre con la sonda simulada y `drift audit` no está conectado.

## Licencia

Apache 2.0 — ver [LICENSE](LICENSE).

---

Trabajo presentado al **Premio CAI Pre-Ingeniería 2026** por **Valentín Torassa Colombero**.
