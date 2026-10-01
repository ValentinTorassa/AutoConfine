# AutoConfine

[![Go Report Card](https://goreportcard.com/badge/github.com/ValentinTorassa/autoconfine)](https://goreportcard.com/report/github.com/ValentinTorassa/autoconfine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**AutoConfine** es un prototipo que genera perfiles seccomp de **mínimos privilegios** para contenedores [OCI](https://opencontainers.org/) a partir de una traza de syscalls. Puede capturar una traza real con eBPF para un contenedor Linux en cgroup v2, o una traza sintética explícita para pruebas.

> Los contenedores se ejecutan por defecto con perfiles seccomp que permiten ~300 syscalls. Una aplicación real usa típicamente entre 40 y 80. AutoConfine busca cerrar esa brecha automáticamente.

## Estado

Prototipo. Lo que funciona hoy es el procesamiento (generar el perfil desde una traza, validarlo, comparar y combinar trazas, correr el contenedor con Podman aplicando el perfil), una captura eBPF real que todavía es experimental y, sobre esa misma sonda, el monitoreo de drift en vivo mientras se aplica un perfil (más experimental todavía: no se corrió contra un kernel real).

- **Captura desde el arranque (recomendada):** `learn --from-start` crea el contenedor con `podman create` + `podman init` (el runtime OCI arma el contenedor y su cgroup, y el proceso init queda esperando), adjunta la sonda `raw_syscalls/sys_enter` a ese cgroup y recién entonces hace `podman start`. Así la traza incluye el `execve` del entrypoint y todo lo que hace al arrancar. Se descartan las syscalls previas a ese `execve` (son del runtime, y el perfil recién se aplica desde ahí). Si la sonda no se puede activar, el contenedor no se arranca. Al terminar se borra, salvo `--keep`.
- **Adjuntarse a uno en ejecución:** `learn --pid <PID host>` sigue disponible, con un aviso: **no** captura el arranque, y un perfil derivado puede impedir que el contenedor vuelva a arrancar. `generate` también lo advierte.
- **Cobertura de la sonda:** coincide con el cgroup del contenedor y con sus descendientes (`bpf_get_current_ancestor_cgroup_id`), así que los procesos que el contenedor mueve a sub-cgroups también cuentan. Si el ring buffer se llena, un contador por CPU lo registra y `learn` falla en lugar de guardar una traza incompleta (`enforce --monitor` sale con error y avisa que el resumen puede faltar syscalls). Al cortar la captura todavía se leen los eventos que quedaban en el ring buffer. Cada evento lleva la marca de tiempo del kernel, `comm`, `phase: observed-ebpf` y `capture_mode` (`from-exec`, `attached` o `synthetic`).
- **Simulación explícita:** `learn --synthetic` emite el ciclo de diez syscalls de prueba, marcado `synthetic`. `generate` y `drift` rechazan esas trazas (y las que no tienen procedencia) salvo `--allow-synthetic`.
- **Drift fuera de línea:** `drift --profile PERFIL TRAZA` reporta cada syscall observada fuera del perfil en JSONL y sale con código 2 si encuentra alguna.
- **Drift en vivo:** `enforce --monitor` corre el contenedor con el perfil usando la misma secuencia que `learn --from-start` (`podman create` con el perfil, `podman init`, sonda adjunta al cgroup, `podman start --attach` en primer plano). Cada syscall desde el `execve` del entrypoint que no está en el perfil se reporta en el momento como una línea JSONL (el esquema de `drift`, más `action` y `errno`) en stderr, o en `--out` (stdout queda para el contenedor). Cuando el contenedor termina (Ctrl-C le llega a través de podman, que lo reenvía), imprime un resumen por syscall con cantidad, primer PID/`comm` y hora, y sale con código 2 si hubo alguna. Si la sonda no se activa, el contenedor se borra sin arrancar.
- **Por qué `sys_exit`:** seccomp decide antes del tracepoint `sys_enter`, y una syscall denegada con `SCMP_ACT_ERRNO` nunca llega a él, pero sí vuelve por `sys_exit` (`kernel/entry/common.c`). Por eso `--monitor` carga un segundo programa en `sys_exit` que lee el número de syscall de `pt_regs->orig_ax`. `--audit` aplica en cambio una copia temporal del perfil con `SCMP_ACT_LOG` como acción por defecto: la syscall fuera del perfil se ejecuta (y el kernel la registra) en lugar de fallar, y la sonda la ve en `sys_enter`, donde aparecen también las que no vuelven, como `exit_group`. `learn` sigue usando solo `sys_enter`.
- **Límites honestos:** la captura resuelve nombres de syscalls solo en Linux amd64 (una desconocida queda como `syscall_N` y `generate` se niega a usarla). Un perfil sale de lo que se observó en ese intervalo: no prueba cobertura completa ni seguridad. El modo `--from-start` con ancestros y contador de pérdidas **no se probó todavía en vivo** después de este cambio (requiere root); la prueba del 29/09 de más abajo usó el modo `--pid`. El monitoreo en vivo (`--monitor`, `--audit`) y el programa de `sys_exit` **tampoco se corrieron en vivo**: la secuencia está probada con un Podman y una sonda falsos, el objeto se compila y se parsea, y el offset de `orig_ax` (120) se comprobó contra el BTF del kernel, pero ningún programa nuevo pasó todavía por el verificador de un kernel real. `--monitor` no ve las syscalls anteriores al `execve` del entrypoint ni las que el perfil resuelve matando o señalizando al proceso (avisa si la acción por defecto no es `SCMP_ACT_ERRNO`), no conecta stdin (no sirve para `-it`) y `podman create` no acepta `-d`.
- **Objeto eBPF:** `internal/bpf/syscalls_bpfel.o` está versionado para que `go install` no necesite clang. `make bpf` lo regenera sin rutas absolutas y CI verifica que coincida con la fuente.

## Modos de operación

| Modo | Comando | Función |
|---|---|---|
| Aprender | `autoconfine learn --image alpine:3.20 --from-start --duration 30s` | Crea el contenedor, adjunta la sonda eBPF y lo arranca. `--pid PID` se adjunta a uno ya en ejecución (sin su arranque); `--synthetic` es solo para pruebas. |
| Generar | `autoconfine generate` | Convierte la traza en un perfil seccomp JSON compatible con OCI. Rechaza trazas sintéticas salvo `--allow-synthetic`. |
| Aplicar | `autoconfine enforce` | Ejecuta el contenedor con Podman aplicando el perfil derivado. |
| Monitorear | `autoconfine enforce --monitor` | Aplica el perfil y reporta en vivo cada syscall que deniega (drift detection); resumen al final y código 2 si hubo alguna. Requiere root y Podman. |
| Auditar | `autoconfine enforce --audit` | Igual, pero sin bloquear: el perfil se aplica con `SCMP_ACT_LOG` por defecto y se reporta cada syscall fuera de él. |

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
- Podman >= 4.0 para `learn --from-start` y para `enforce`. Docker no tiene un equivalente de `podman init`, así que con Docker solo queda `learn --pid` (con el aviso de que falta el arranque) y `enforce` sin monitoreo.
- `enforce --monitor` y `--audit` necesitan lo mismo que la captura: root (o `CAP_BPF` + `CAP_PERFMON`) y Podman.

## Uso rápido

```bash
# 1. Fase de aprendizaje: crea el contenedor, se adjunta y recién ahí lo arranca.
#    Lo que va después de -- son opciones de `podman create` (antes de la imagen).
sudo autoconfine learn --image nginx --from-start --duration 5m --out nginx.trace.jsonl -- -p 8080:80

# 2. Generación del perfil
autoconfine generate nginx.trace.jsonl --out nginx-seccomp.json

# 3. Ejecución protegida (también sirven `-- podman --rm nginx` o `-- run --rm nginx`)
autoconfine enforce --profile nginx-seccomp.json -- podman run --rm nginx

# 4. Ejecución protegida con monitoreo en vivo: cada syscall denegada sale en
#    drift.jsonl en el momento; Ctrl-C detiene nginx y muestra el resumen.
#    Con --audit en lugar de --monitor no se deniega nada, solo se reporta.
sudo autoconfine enforce --profile nginx-seccomp.json --monitor --out drift.jsonl -- podman run --rm nginx
```

Con `--pid` en lugar de `--from-start`, obtener el PID **host** con `podman inspect -f '{{.State.Pid}}' CONTENEDOR` (o `docker inspect`). No usar un PID del host fuera de un cgroup de contenedor: la sonda lo rechaza.

Desarrollo: `make test` (con `-race`), `make vet`, `make bpf` / `make bpf-check`, `make run-learn` para una captura real de nginx con `sudo`, y `make run-monitor` / `make run-audit` para correr nginx con el perfil resultante y el monitoreo en vivo (también con `sudo`; son la forma de probar en vivo lo que los tests cubren con fakes).

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

El diagrama muestra el flujo implementado. El drift audit existe en dos formas: `drift`, fuera de línea sobre una traza (probado con la captura real de abajo), y `enforce --monitor` / `--audit`, en vivo mientras el perfil está aplicado, con la misma sonda de `learn` (probado solo con fakes, ver los límites de arriba).

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
