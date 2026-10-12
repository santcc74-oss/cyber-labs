# Laboratorio 02 · Triage de un endpoint Windows

> **English summary:** I triaged my own Windows workstation like a SOC analyst would: running processes, network connections, and persistence (startup entries). I reviewed Autoruns, ruled out "Not Verified" alerts as false positives using package signature evidence, and wrote a reusable 10-command PowerShell triage checklist.

**Fecha:** 11 de octubre de 2026
**Herramientas:** Windows PowerShell (como administrador), Autoruns (Microsoft Sysinternals)
**Objetivo:** responder rápido tres preguntas ante un equipo reportado como "extraño":

1. **¿Qué está corriendo?** (procesos)
2. **¿Con quién se comunica?** (conexiones de red)
3. **¿Qué arranca solo al encender?** (persistencia, el truco que usa el malware para volver tras un reinicio)

---

## 1. Checklist de triage (10 comandos)

Todos los comandos son de solo lectura y se probaron en Windows 11 con PowerShell 5.1. Conviene ejecutarlos como administrador y desde una carpeta propia (`cd $HOME\Documents`), no desde `C:\Windows\system32`.

| # | Pregunta | Comando | Qué sería sospechoso |
|---|---|---|---|
| 1 | ¿Qué consume más CPU? | `Get-Process \| Sort-Object CPU -Descending \| Select-Object -First 10 Name, Id, CPU, Path` | Un proceso desconocido con CPU alta y constante (por ejemplo, un minero de criptomonedas) |
| 2 | ¿Qué corre fuera de las carpetas normales? | `Get-Process \| Where-Object { $_.Path -and $_.Path -notlike 'C:\Windows\*' -and $_.Path -notlike 'C:\Program Files*' } \| Select-Object Name, Id, Path` | Nombres de sistema (como `svchost.exe`) fuera de `System32`, o nombres aleatorios en `AppData\Local\Temp` |
| 3 | ¿Con quién habla cada programa? | `Get-NetTCPConnection -State Established \| Select-Object RemoteAddress, RemotePort, @{n='Programa';e={(Get-Process -Id $_.OwningProcess).Name}}` | Programas que no deberían usar internet, puertos poco comunes (4444, 8081), muchas conexiones a una IP desconocida |
| 4 | ¿Qué puertos están abiertos esperando conexiones? | `Get-NetTCPConnection -State Listen \| Select-Object LocalAddress, LocalPort, @{n='Programa';e={(Get-Process -Id $_.OwningProcess).Name}}` | Un puerto abierto en `0.0.0.0` (accesible desde la red) por un programa que no reconoces |
| 5 | ¿Qué servicios de terceros están corriendo? | `Get-CimInstance Win32_Service \| Where-Object { $_.State -eq 'Running' -and $_.PathName -notlike '*\Windows\*' } \| Select-Object Name, PathName` | Servicios con nombre genérico o ejecutable en carpetas de usuario |
| 6 | ¿Qué tareas programadas no son de Microsoft? | `Get-ScheduledTask \| Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } \| Select-Object TaskName, TaskPath, State` | Tareas que ejecutan scripts (`powershell`, `.vbs`, `.bat`) o archivos desde `Temp` |
| 7 | ¿Qué arranca al iniciar sesión? | `'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' \| ForEach-Object { Get-ItemProperty $_ }` | Entradas sin nombre claro, apuntando a `AppData` o `Temp` (técnica MITRE ATT&CK **T1547.001**) |
| 8 | ¿Qué cuentas existen? | `Get-LocalUser \| Select-Object Name, Enabled, LastLogon` | Cuentas nuevas que nadie creó, o cuentas desactivadas que se volvieron a activar |
| 9 | ¿Hubo inicios de sesión fallidos? | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20` | Muchos fallos seguidos de un inicio exitoso (evento **4624**): posible contraseña adivinada |
| 10 | ¿Crearon usuarios o borraron registros? | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,1102} -MaxEvents 10` | **4720** = usuario creado; **1102** = registro de seguridad borrado (alguien cubriendo huellas) |

> Los comandos 9 y 10 leen el registro de seguridad de Windows: **sin permisos de administrador devuelven vacío**, aunque sí haya eventos. Un resultado vacío solo cuenta si se ejecutaron como administrador.

---

## 2. Revisión de persistencia con Autoruns

Autoruns es una herramienta gratuita de Microsoft que muestra todo lo que arranca solo con Windows. Para filtrar el ruido se activan **Options → Hide Microsoft Entries** y **Hide Windows Entries**.

### 2.1 Pestaña Logon (llave `Run` del usuario)

Encontré 7 programas configurados para arrancar al iniciar sesión. **Todos tenían firma digital verificada** de empresas conocidas (Microsoft, Google, Notion Labs, Opera, Riot Games).

Varios estaban en `AppData`. Eso **no es sospechoso por sí solo**: muchas apps modernas se instalan solo para el usuario, sin pedir permisos de administrador. Sería sospechoso si se juntaran varias señales: ubicación en `AppData` o `Temp`, sin firma, sin descripción y con un nombre aleatorio.

**Resultado:** sin hallazgos.

### 2.2 Packaged Apps: la "alerta" en rosado

Autoruns marcó en rosado, como **"(Not Verified)"**, varias apps ubicadas en `C:\Program Files\WindowsApps\`. A primera vista parecía alarmante.

**Hipótesis:** son apps empaquetadas (Microsoft Store o instaladores MSIX). Su firma está en el paquete completo, no dentro de cada ejecutable, así que Autoruns no la encuentra.

**Comprobación:** en lugar de asumirlo, le pedí la evidencia a Windows:

```powershell
Get-AppxPackage | Where-Object { $_.InstallLocation -like '*WindowsApps*' } | Group-Object SignatureKind | Select-Object Name, Count
```

| Tipo de firma | Cantidad | Significado |
|---|---|---|
| `Store` | 138 | Instaladas desde la Microsoft Store, firmadas por Microsoft |
| `Developer` | 18 | Instaladas con el instalador oficial del fabricante, por fuera de la tienda |

Las 18 de tipo `Developer` las revisé una por una según **quién las firmó**: todas tenían publicadores legítimos (Microsoft Corporation, win.rar GmbH y Anthropic, PBC).

Dos casos que no eran obvios:

- **`aimgr`**: el nombre no dice qué es. Está firmado por Microsoft Corporation y su carpeta termina en `8wekyb3d8bbwe`, el identificador de publicador que llevan todas las apps de Microsoft. Si un paquete dice ser de Microsoft pero no tiene ese identificador, sí habría que investigarlo.
- **`AweZip` (BreeZip)**: su firmante aparece como un código (`CN=477B7FBA-…`). Es normal en apps de la tienda, porque Microsoft firma con el número de registro del desarrollador. Firma tipo `Store`: legítima. Observación: está configurada para arrancar sola, algo que un descompresor no necesita. Se recomienda desactivarlo o desinstalarlo si no se usa.

**Resultado:** falsos positivos, descartados con evidencia.

### 2.3 Pendiente

- Revisar en Autoruns las pestañas **Scheduled Tasks** y **Services** con los filtros activos y el escaneo completo (estado *Ready*).

---

## 3. Lecciones aprendidas

- **Rosado no significa malware.** "Not Verified" es una pista, no una conclusión. El trabajo del analista es confirmar o descartar con evidencia.
- **El nombre engaña; la ruta y el firmante no.** Para juzgar un programa importan más su ubicación y quién lo firmó que cómo se llama.
- **"Firmado" no es lo mismo que "necesario".** Una app legítima puede sobrar en el arranque y aumentar la superficie de ataque.
- **Ojo con las salidas cortadas.** `Format-Table` oculta columnas si no caben en la ventana. Pedir menos columnas o un resumen (`Group-Object`) evita perder justo el dato importante.
- **Solo observar.** En un triage primero se documenta y después se decide. Desactivar entradas sin entenderlas puede romper programas o destruir evidencia.

## Conclusión

El equipo revisado **no muestra indicios de compromiso** en las áreas analizadas (inicio de sesión y apps empaquetadas). Queda pendiente revisar las tareas programadas y los servicios para cerrar el análisis de persistencia. El checklist de la sección 1 queda como herramienta reutilizable para futuros casos.
