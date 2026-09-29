# AutoConfine

[![Go Report Card](https://goreportcard.com/badge/github.com/ValentinTorassa/autoconfine)](https://goreportcard.com/report/github.com/ValentinTorassa/autoconfine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**AutoConfine** es un prototipo que genera perfiles seccomp de **mínimos privilegios** para contenedores [OCI](https://opencontainers.org/) a partir de una traza de syscalls. Puede capturar una traza real con eBPF para un contenedor Linux en cgroup v2, o una traza sintética explícita para pruebas.

> Los contenedores se ejecutan por defecto con perfiles seccomp que permiten ~300 syscalls. Una aplicación real usa típicamente entre 40 y 80. AutoConfine busca cerrar esa brecha automáticamente.

## Estado

Prototipo. Lo que funciona hoy es el procesamiento: generar el perfil desde una traza, validarlo, comparar y combinar trazas, y correr el contenedor con Podman aplicando el perfil.

- **Captura real experimental:** `learn --pid <PID host>` adjunta `raw_syscalls/sys_enter` con eBPF, filtra por el cgroup v2 del contenedor y marca cada evento `observed-ebpf`. Necesita permiso real para cargar eBPF; Docker rootless `--privileged` puede seguir sin tenerlo. Captura solo el intervalo observado de un contenedor ya arrancado; un perfil derivado de una sola muestra no prueba cobertura completa ni seguridad.
- **Simulación explícita:** `learn --synthetic` emite el ciclo de diez syscalls de prueba, marcado `synthetic`. No se confunde con una traza real.
- **Drift fuera de línea:** `drift --profile PERFIL TRAZA` reporta cada syscall observada fuera del perfil en JSONL y sale con código 2 si encuentra alguna. Rechaza trazas sintéticas o sin procedencia, salvo `--allow-synthetic` para pruebas. `enforce --audit` todavía no monitorea drift en vivo: solo registra que se activó ese modo.
- La captura real de momento resuelve nombres de syscalls solo en Linux amd64. Una syscall sin nombre conocido queda como `syscall_N`; revisar antes de generar un perfil seccomp. El objeto eBPF precompilado se regenera con `clang -O2 -g -target bpf -c internal/bpf/syscalls.bpf.c -o internal/bpf/syscalls_bpfel.o`.

## Modos de operación

| Modo | Comando | Función |
|---|---|---|
| Aprender | `autoconfine learn --image alpine:3.20 --pid PID --duration 30s` | Observa las syscalls de un contenedor en ejecución mediante eBPF. `--synthetic` es solo para pruebas. |
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
| `autoconfine drift` | `autoconfine drift --profile nginx-seccomp.json segunda-traza.jsonl` | Compara eventos observados con el perfil, sin ejecutar el contenedor. |

## Instalación

```bash
go install github.com/ValentinTorassa/autoconfine/cmd/autoconfine@latest
```

Requisitos de captura real:

- Linux amd64 con cgroup v2, raw tracepoints y ring buffer eBPF.
- Contenedor ya en ejecución y su PID **host** (por ejemplo, `docker inspect -f '{{.State.Pid}}' CONTAINER`). No usar un PID del host fuera de un cgroup de contenedor.
- Permisos efectivos para cargar programas eBPF. Podman >= 4.0 solo para `enforce`.

## Uso rápido

```bash
# 1. Fase de aprendizaje
autoconfine learn --image nginx --pid HOST_PID --duration 5m --out nginx.trace.jsonl

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

El diagrama muestra el flujo implementado hasta `enforce`. La captura real y el análisis de drift fuera de línea funcionan; el monitoreo de drift en vivo al aplicar un perfil sigue pendiente.

## Prueba de captura real del 29/09/2026

En un contenedor Alpine desechable sobre un Docker rootful, se adjuntó la sonda al
cgroup del contenedor y se ejecutó una carga sintética de `cat`/`ls` dentro de él.
La traza registró **712 eventos eBPF observados**, **47 syscalls únicas**, cero
nombres desconocidos. `generate` produjo un perfil que `validate` aceptó; `drift`
devolvió 0/712 eventos fuera de ese mismo perfil. Al retirar `openat` del perfil
para la prueba, `drift` reportó 9 eventos `openat` y salió con código 2. Esto
demuestra captura y comparación de una carga corta, no cobertura de una app real.

## Licencia

Apache 2.0 — ver [LICENSE](LICENSE).

---

Trabajo presentado al **Premio CAI Pre-Ingeniería 2026** por **Valentín Torassa Colombero**.
