# Laboratorio 01 · Verificación de integridad con hashes SHA-256

> **English summary:** I verified the integrity of an Ubuntu Server ISO by comparing its SHA-256 hash with the official checksum list, and showed the avalanche effect with two near-identical files.

**Fecha:** 3 de octubre de 2026
**Herramientas:** Windows PowerShell (`Get-FileHash`, `Select-String`)
**Objetivo:** comprobar que un archivo descargado no fue dañado ni alterado antes de usarlo.

---

## 1. Verificación de la imagen de Ubuntu

Descargué Ubuntu Server 26.04.1 LTS y la lista oficial de hashes (`SHA256SUMS`) desde `releases.ubuntu.com/26.04/`. Luego calculé el hash de mi archivo y lo comparé con el publicado.

| Archivo | Hash esperado (oficial) | Hash obtenido (mi archivo) | Resultado |
|---|---|---|---|
| `ubuntu-26.04.1-live-server-amd64.iso` | `cc8a95cde20f6ced61a322420de00f10cc3c90ced545daa46cb9c1a117f1d927` | `cc8a95cde20f6ced61a322420de00f10cc3c90ced545daa46cb9c1a117f1d927` | ✅ Coinciden: archivo íntegro |

Comando usado:

```powershell
$iso = Get-ChildItem .\ubuntu-*-live-server-amd64.iso | Select-Object -First 1
$real = (Get-FileHash $iso.FullName -Algorithm SHA256).Hash
$esperado = ((Select-String -Path .\SHA256SUMS -Pattern $iso.Name -SimpleMatch).Line -split ' ')[0]
$esperado -eq $real   # True
```

### Lo que aprendí al hacerlo

Mi primera comparación dio `False` aunque la descarga estaba bien. La causa: `SHA256SUMS` traía dos versiones (26.04 y 26.04.1), y mi comando tomó la línea equivocada. Lo corregí buscando el **nombre exacto** de mi archivo. Lección: un hash solo sirve si lo comparas con la línea correcta. Hay que verificar nombre y versión, no solo que "se parezca".

## 2. Efecto avalancha

Creé dos mensajes que solo se diferencian en un dígito del monto.

| Archivo | Contenido | Hash SHA-256 |
|---|---|---|
| `a.txt` | Transferir 100000 a cuenta 4821 | `97f04f10c824dd8da8aec9ae6f4085e5f5daeb5b52e87729f1d2578012d51657` |
| `b.txt` | Transferir 900000 a cuenta 4821 | `d6467ebd9dbc299b0554b19da6243fbf28ca883cb705d37924c6658b8ba50448` |

Cambió un solo carácter y el hash cambió por completo. Por eso un banco puede detectar si alguien alteró el monto de una transferencia.

## 3. ¿Qué es un ataque a la cadena de suministro?

<!-- Consejo: reescribe este párrafo con tus propias palabras antes de publicarlo. -->

Un ataque a la cadena de suministro ocurre cuando un atacante no ataca directamente a su víctima, sino a algo en lo que la víctima confía: un proveedor, una actualización de software o un instalador. Por ejemplo, si alguien reemplaza el instalador oficial de un programa por uno modificado, todas las personas que lo descarguen quedarían comprometidas sin saberlo. Un caso conocido es el de SolarWinds (2020), en el que una actualización legítima traía código malicioso y afectó a miles de organizaciones. Verificar el hash contra la fuente oficial es una defensa sencilla: si el archivo fue alterado, el hash no coincide.

## Conclusión

La verificación con SHA-256 confirma la **integridad** de un archivo, uno de los tres pilares de la seguridad (confidencialidad, integridad y disponibilidad). Es un paso rápido que conviene hacer siempre antes de instalar software, sobre todo en entornos críticos como la banca.
