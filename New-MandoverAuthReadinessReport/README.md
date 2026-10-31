# New-MandoverAuthReadinessReport

Informe HTML gratuito que muestra **cuántos usuarios de tu tenant de Microsoft Entra están preparados para la retirada del SMS y la voz como métodos de autenticación**, y quiénes no.

*English summary at the end.*

Microsoft retira el SMS y la voz propios de Entra ID. Quien solo tenga SMS o voz como MFA tendrá que registrar un passkey, con un aviso bloqueante y sin opción de omitirlo. Este script te dice cuántas personas están en esa situación y te da la lista.

## Qué obtienes

Un único fichero HTML, sin dependencias externas, con:

- Un aviso con las fechas publicadas por Microsoft y los días que quedan.
- Tarjetas: usuarios analizados, **preparados**, **solo SMS o voz**, **sin ningún método MFA**, **admins que dependen solo de SMS o voz** y **resistentes a phishing**.
- Una barra de preparación y las barras de usuarios por método de autenticación.
- Al pulsar cualquier tarjeta, tramo o método, la **lista de usuarios**, con buscador.
- Interruptor ES / EN dentro del propio informe.

Es de solo lectura: no cambia nada en el tenant.

## Requisitos

| Requisito | Detalle |
|---|---|
| Licencia | Microsoft Entra ID **P1 o P2** (por ejemplo, incluida en Microsoft 365 Business Premium, E3 y E5). Sin ella, Microsoft rechaza la consulta. |
| PowerShell | Windows PowerShell 5.1 o PowerShell 7 |
| Módulo | `Microsoft.Graph.Authentication` (no hace falta el SDK completo de Graph) |
| Permiso de Graph | `AuditLog.Read.All` (delegado). Un administrador debe concederlo la primera vez. |
| Rol de la cuenta | Reports Reader, Security Reader, Security Administrator, Global Reader o superior |

> Los módulos de Windows PowerShell 5.1 y de PowerShell 7 se instalan en carpetas distintas. Instala el módulo desde la misma ventana desde la que vas a ejecutar el script.

Instalación del módulo (solo la primera vez):

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## Instalación y uso

> **Windows PowerShell 5.1: permitir la ejecución de scripts.** En Windows cliente, la política de ejecución viene en `Restricted` y bloquea todos los scripts, también los instalados desde la Gallery («la ejecución de scripts está deshabilitada en este sistema»). Se cambia una sola vez, sin ser administrador:
>
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```
>
> Si `Get-ExecutionPolicy -List` muestra una política en `MachinePolicy` o `UserPolicy`, la impone una directiva de grupo y este comando no la cambia. Consulta con tu administrador. En PowerShell 7 no hace falta.

Elige una de estas tres formas.

### 1. Instalarlo desde la PowerShell Gallery

```powershell
Install-Script -Name New-MandoverAuthReadinessReport -Scope CurrentUser
New-MandoverAuthReadinessReport
```

El script instalado se ejecuta **por su nombre**, sin `.\` ni ruta. Si es la primera vez que instalas un script, PowerShell puede preguntarte si quieres añadir la carpeta de scripts a la variable `PATH`. Responde que sí y, si no lo reconoce, cierra y abre la ventana de PowerShell.

### 2. Solo descargar el fichero, sin instalarlo

```powershell
Save-Script -Name New-MandoverAuthReadinessReport -Path .\Mandover
.\Mandover\New-MandoverAuthReadinessReport.ps1
```

Descarga el script desde la Gallery a la carpeta que indiques. Puedes revisarlo y ejecutarlo cuando quieras, sin tocar el `PATH`.

### 3. Descargarlo desde GitHub

1. Entra en la [carpeta del script en GitHub](https://github.com/mandover-tools/powershell-tools/tree/main/New-MandoverAuthReadinessReport).
2. Abre `New-MandoverAuthReadinessReport.ps1` y pulsa el botón de descarga (*Download raw file*).
3. Desbloquea el fichero y ejecútalo:

```powershell
Unblock-File .\New-MandoverAuthReadinessReport.ps1
.\New-MandoverAuthReadinessReport.ps1
```

Windows marca como bloqueados los ficheros que se descargan con el navegador. Sin `Unblock-File`, Windows PowerShell 5.1 puede negarse a ejecutarlo con el mensaje «no está firmado digitalmente».

---

Se abre una ventana de inicio de sesión de Microsoft. Al terminar se guarda el HTML en `Documentos\Mandover` y se abre en el navegador.

| Parámetro | Para qué sirve |
|---|---|
| `-Language en` | Idioma inicial del informe (`es` o `en`). Se puede cambiar dentro del propio informe. |
| `-OutputFolder "C:\Informes"` | Carpeta donde se guarda el HTML. |
| `-NoOpen` | No abre el HTML al terminar. |
| `-Pause` | Espera a que pulses Intro antes de cerrar la ventana. Se activa solo si lo lanzas desde el Explorador. |

## Privacidad y permisos

- **Todo se ejecuta en tu equipo.** El script no envía datos a Mandover ni a ningún otro servidor, y no incluye telemetría.
- Solo habla con Microsoft Graph, con dos consultas de lectura: `GET /reports/authenticationMethods/userRegistrationDetails` y, de forma opcional, `GET /organization?$select=displayName` para mostrar el nombre del tenant.
- El HTML no hace ninguna petición a Internet al abrirse. Contiene enlaces a mandover.com y a la documentación de Microsoft, que solo se abren cuando los pulsas. El enlace a mandover.com lleva etiquetas de campaña y ningún dato de tu tenant.
- Puedes leer el código completo antes de ejecutarlo.

## Cómo se calcula

- **Preparado:** al menos un método MFA que no es SMS ni voz (Authenticator, app OATH, token, FIDO2, passkey, Windows Hello o certificado).
- **Solo SMS o voz:** su único MFA es telefónico. El correo y las preguntas de seguridad no cuentan, porque solo sirven para el restablecimiento de contraseña.
- **Sin MFA:** ningún método MFA registrado.
- Los tres grupos suman el total de usuarios analizados.
- **Resistente a phishing:** FIDO2, passkey, Windows Hello for Business o certificado. Microsoft Authenticator no cuenta.

## Calendario de Microsoft

Según la [documentación de Microsoft](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement) a 31 de octubre de 2026:

| Fecha | Qué ocurre |
|---|---|
| 1 de septiembre de 2026 | Los passkeys pasan a ser el método por defecto. |
| 1 de febrero de 2027 | Se retiran el SMS y la voz para usuarios internos e invitados internos. |
| 1 de julio de 2027 | Se retiran para Global Administrators y usuarios externos. |

Después de cada fecha, quien solo tenga SMS o voz tendrá que registrar un passkey. **Confirma las fechas en la documentación de Microsoft**, porque pueden cambiar.

## Limitaciones

- Microsoft **no incluye en este informe las cuentas deshabilitadas ni las eliminadas recientemente.**
- Los datos pueden tener **hasta 36 horas de retraso**.
- El informe **no refleja el MFA aplicado fuera de Microsoft Entra ID** (proveedor externo o federado). En esos tenants, «Sin MFA» puede salir inflado.
- El informe de Microsoft agrupa SMS y voz bajo el método teléfono y **no los distingue**.
- «Admin» significa que la cuenta tiene algún rol de administrador. No distingue Global Administrators del resto.

## Problemas frecuentes

| Mensaje | Causa y solución |
|---|---|
| «no está firmado digitalmente» | Windows marca los ficheros descargados con el navegador. Ejecuta `Unblock-File` sobre el fichero. |
| «la ejecución de scripts está deshabilitada» | Política de ejecución `Restricted`. Mira `Get-ExecutionPolicy -List`. Si no la impone una directiva de grupo, ejecuta `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`. |
| «no se reconoce el término New-MandoverAuthReadinessReport» | La carpeta de scripts no está en el `PATH` de esta ventana. Cierra y abre PowerShell, o ejecuta el script con su ruta completa. |
| «Falta el módulo Microsoft.Graph.Authentication» | Instálalo desde la misma ventana de PowerShell que usas para ejecutar el script. |
| «No se puede crear un canal seguro SSL/TLS» al usar `Install-Script` o `Save-Script` | Windows PowerShell 5.1 con PowerShellGet antiguo. Ejecuta primero `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` o usa PowerShell 7. |
| Error de ensamblado (assembly) al iniciar sesión | Conflicto con otros módulos cargados (Exchange Online, Az…). Abre una ventana nueva y ejecuta `Update-Module Microsoft.Graph.Authentication`. |
| «no tiene licencia Microsoft Entra ID P1 o P2» | Microsoft exige P1 o P2 para este informe. |
| 403 de acceso denegado | Falta el consentimiento de `AuditLog.Read.All` o el rol de la cuenta. |

## Sobre Mandover

Este informe es solo el principio. [Mandover](https://mandover.com) es una aplicación para administradores de entornos híbridos Microsoft 365 y Active Directory.

---

## English summary

**New-MandoverAuthReadinessReport** is a free, read-only PowerShell script that generates a self-contained HTML report showing how many users in your Microsoft Entra tenant are ready for Microsoft's retirement of SMS and voice authentication, and who is not. It needs Entra ID P1 or P2, PowerShell 5.1 or 7, the `Microsoft.Graph.Authentication` module and the delegated `AuditLog.Read.All` permission. It runs locally, sends no data anywhere except to Microsoft Graph, and has no telemetry. Microsoft leaves disabled and recently deleted accounts out of the report, data can lag by up to 36 hours, and MFA enforced outside Entra ID is not reflected.

Install with `Install-Script -Name New-MandoverAuthReadinessReport -Scope CurrentUser`, download only with `Save-Script -Name New-MandoverAuthReadinessReport -Path .\Mandover`, or download the `.ps1` from GitHub and run `Unblock-File` on it before use.
