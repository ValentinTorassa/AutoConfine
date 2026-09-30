# AutoConfine

[![Go Report Card](https://goreportcard.com/badge/github.com/ValentinTorassa/autoconfine)](https://goreportcard.com/report/github.com/ValentinTorassa/autoconfine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**AutoConfine** es un prototipo que genera perfiles seccomp de **mínimos privilegios** para contenedores [OCI](https://opencontainers.org/) a partir de una traza de syscalls. Puede capturar una traza real con eBPF para un contenedor Linux en cgroup v2, o una traza sintética explícita para pruebas.

> Los contenedores se ejecutan por defecto con perfiles seccomp que permiten ~300 syscalls. Una aplicación real usa típicamente entre 40 y 80. AutoConfine busca cerrar esa brecha automáticamente.

## Estado

Prototipo. Lo que funciona hoy es el procesamiento (generar el perfil desde una traza, validarlo, comparar y combinar trazas, correr el contenedor con Podman aplicando el perfil) y una captura eBPF real que todavía es experimental.

- **Captura desde el arranque (recomendada):** `learn --from-start` crea el contenedor con `podman create` + `podman init` (el runtime OCI arma el contenedor y su cgroup, y el proceso init queda esperando), adjunta la sonda `raw_syscalls/sys_enter` a ese cgroup y recién entonces hace `podman start`. Así la traza incluye el `execve` del entrypoint y todo lo que hace al arrancar. Se descartan las syscalls previas a ese `execve` (son del runtime, y el perfil recién se aplica desde ahí). Si la sonda no se puede activar, el contenedor no se arranca. Al terminar se borra, salvo `--keep`.
- **Adjuntarse a uno en ejecución:** `learn --pid <PID host>` sigue disponible, con un aviso: **no** captura el arranque, y un perfil derivado puede impedir que el contenedor vuelva a arrancar. `generate` también lo advierte.
- **Cobertura de la sonda:** coincide con el cgroup del contenedor y con sus descendientes (`bpf_get_current_ancestor_cgroup_id`), así que los procesos que el contenedor mueve a sub-cgroups también cuentan. Si el ring buffer se llena, un contador por CPU lo registra y `learn` falla en lugar de guardar una traza incompleta. Cada evento lleva la marca de tiempo del kernel, `comm`, `phase: observed-ebpf` y `capture_mode` (`from-exec`, `attached` o `synthetic`).
- **Simulación explícita:** `learn --synthetic` emite el ciclo de diez syscalls de prueba, marcado `synthetic`. `generate` y `drift` rechazan esas trazas (y las que no tienen procedencia) salvo `--allow-synthetic`.
- **Drift fuera de línea:** `drift --profile PERFIL TRAZA` reporta cada syscall observada fuera del perfil en JSONL y sale con código 2 si encuentra alguna. `enforce --audit` todavía no monitorea drift en vivo: solo registra que se activó ese modo.
- **Límites honestos:** la captura resuelve nombres de syscalls solo en Linux amd64 (una desconocida queda como `syscall_N` y `generate` se niega a usarla). Un perfil sale de lo que se observó en ese intervalo: no prueba cobertura completa ni seguridad. El modo `--from-start` con ancestros y contador de pérdidas **no se probó todavía en vivo** después de este cambio (requiere root); la prueba del 29/09 de más abajo usó el modo `--pid`.
- **Objeto eBPF:** `internal/bpf/syscalls_bpfel.o` está versionado para que `go install` no necesite clang. `make bpf` lo regenera sin rutas absolutas y CI verifica que coincida con la fuente.

## Modos de operación

| Modo | Comando | Función |
|---|---|---|
| Aprender | `autoconfine learn --image alpine:3.20 --from-start --duration 30s` | Crea el contenedor, adjunta la sonda eBPF y lo arranca. `--pid PID` se adjunta a uno ya en ejecución (sin su arranque); `--synthetic` es solo para pruebas. |
| Generar | `autoconfine generate` | Convierte la traza en un perfil seccomp JSON compatible con OCI. Rechaza trazas sintéticas salvo `--allow-synthetic`. |
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

- Linux amd64 con cgroup v2, raw tracepoints, ring buffer eBPF y `bpf_get_current_ancestor_cgroup_id` en programas de tracing (kernel 5.10 o posterior, aproximadamente).
- Permisos efectivos para cargar programas eBPF: root, o `CAP_BPF` + `CAP_PERFMON`.
- Podman >= 4.0 para `learn --from-start` y para `enforce`. Docker no tiene un equivalente de `podman init`, así que con Docker solo queda `--pid` (con el aviso de que falta el arranque).

## Uso rápido

```bash
# 1. Fase de aprendizaje: crea el contenedor, se adjunta y recién ahí lo arranca.
#    Lo que va después de -- son opciones de `podman create` (antes de la imagen).
sudo autoconfine learn --image nginx --from-start --duration 5m --out nginx.trace.jsonl -- -p 8080:80

# 2. Generación del perfil
autoconfine generate nginx.trace.jsonl --out nginx-seccomp.json

# 3. Ejecución protegida (también sirven `-- podman --rm nginx` o `-- run --rm nginx`)
autoconfine enforce --profile nginx-seccomp.json -- podman run --rm nginx
```

Con `--pid` en lugar de `--from-start`, obtener el PID **host** con `podman inspect -f '{{.State.Pid}}' CONTENEDOR` (o `docker inspect`). No usar un PID del host fuera de un cgroup de contenedor: la sonda lo rechaza.

Desarrollo: `make test` (con `-race`), `make vet`, `make bpf` / `make bpf-check`, y `make run-learn` para una captura real de nginx con `sudo`.

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
cgroup del contenedor (modo `--pid`, antes de agregar `--from-start`) y se ejecutó
una carga sintética de `cat`/`ls` dentro de él.
La traza registró **712 eventos eBPF observados**, **47 syscalls únicas**, cero
nombres desconocidos. `generate` produjo un perfil que `validate` aceptó; `drift`
devolvió 0/712 eventos fuera de ese mismo perfil. Al retirar `openat` del perfil
para la prueba, `drift` reportó 9 eventos `openat` y salió con código 2. Esto
demuestra captura y comparación de una carga corta, no cobertura de una app real.

## Licencia

Apache 2.0 — ver [LICENSE](LICENSE).

---

Trabajo presentado al **Premio CAI Pre-Ingeniería 2026** por **Valentín Torassa Colombero**.
