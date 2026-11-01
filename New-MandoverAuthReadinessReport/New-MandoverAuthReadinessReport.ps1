<#PSScriptInfo

.VERSION 1.0.1

.GUID e99f000c-55df-47ff-924f-325ce262a09e

.AUTHOR Mandover

.COMPANYNAME Mandover

.COPYRIGHT (c) 2026 Mandover

.TAGS Entra EntraID MFA Authentication Passkeys FIDO2 SMS Voice Microsoft365 M365 Graph Report Security Mandover Windows

.LICENSEURI https://github.com/mandover-tools/powershell-tools/blob/main/LICENSE

.PROJECTURI https://github.com/mandover-tools/powershell-tools/tree/main/New-MandoverAuthReadinessReport

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
1.0.1 - The report now covers internal users (tenant members) only; guest accounts are always left out. Removed the phishing-resistant card. Notice wording aligned with Microsoft's documentation. Released under the MIT license.
1.0.0 - First public release. Readiness report for Microsoft's retirement of SMS and voice authentication in Entra ID.

.PRIVATEDATA

#>

#Requires -Version 5.1

<#
.SYNOPSIS
    Generates a self-contained HTML report showing how ready a Microsoft Entra tenant is for the retirement of SMS and voice authentication.

.DESCRIPTION
    Reads the authentication methods registration report from Microsoft Graph (reports/authenticationMethods/userRegistrationDetails)
    and writes a single HTML file with no external dependencies. It answers one question: how many users are ready for
    Microsoft's retirement of SMS and voice authentication, and who is not.
      - Notice with Microsoft's published dates and the days left.
      - Cards: ready users, SMS or voice only, no MFA, and admins relying only on SMS or voice.
        Every card, bar segment and method opens the list of users.
      - ES / EN switch inside the report.
    Read-only: it changes nothing in the tenant. It runs locally and sends no data anywhere except to Microsoft Graph.
    Microsoft leaves disabled and recently deleted accounts out of this report. Only internal users (tenant members) are analysed; guest accounts are always left out.

.PARAMETER OutputFolder
    Folder where the HTML file is saved. Default: Documents\Mandover

.PARAMETER Language
    Initial language of the report (es or en). It can be switched inside the report.

.PARAMETER NoOpen
    Do not open the HTML file when finished.

.PARAMETER Pause
    Wait for Enter before closing. It is enabled automatically when the script is started from File Explorer.

.PARAMETER TaglineEs
    Header text in Spanish (optional).

.PARAMETER TaglineEn
    Header text in English (optional).

.NOTES
    Delegated permission: AuditLog.Read.All (the minimum documented by Microsoft for userRegistrationDetails). An administrator must grant consent the first time.
    Roles: Reports Reader, Security Reader, Security Administrator, Global Reader or higher.
    Microsoft license required: Microsoft Entra ID P1 or P2.
    Script license: MIT.
    Module: Microsoft.Graph.Authentication (the full Microsoft Graph SDK is not needed).
    Save this file as UTF-8 with BOM for Windows PowerShell 5.1.

.LINK
    https://mandover.com

.EXAMPLE
    New-MandoverAuthReadinessReport

.EXAMPLE
    New-MandoverAuthReadinessReport -Language en -NoOpen
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = '',
    [ValidateSet('es', 'en')][string]$Language = 'es',
    [switch]$NoOpen,
    [switch]$Pause,
    [string]$TaglineEs = '',
    [string]$TaglineEn = ''
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------------------------
# Pausa para poder leer los mensajes cuando el script se lanza con clic derecho > "Ejecutar con
# PowerShell" (la ventana se cerraría sola al terminar). También se activa con -Pause.
# ----------------------------------------------------------------------------------------------
function Test-ShouldPause {
    if ($Pause) { return $true }
    try {
        $parentId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID" -ErrorAction Stop).ParentProcessId
        return ((Get-Process -Id $parentId -ErrorAction Stop).ProcessName -eq 'explorer')
    }
    catch { return $false }
}
function Wait-ForKeyIfNeeded {
    if (Test-ShouldPause) {
        Write-Host ''
        [void](Read-Host 'Pulsa Intro para cerrar esta ventana')
    }
}
if (-not $OutputFolder) {
    $docs = [Environment]::GetFolderPath('MyDocuments')
    if (-not $docs) { $docs = $HOME }
    $OutputFolder = Join-Path $docs 'Mandover'
}
trap {
    if (Test-ShouldPause) {
        Write-Host ''
        Write-Host ($_ | Out-String) -ForegroundColor Red
        Wait-ForKeyIfNeeded
    }
    break
}

# ----------------------------------------------------------------------------------------------
# Utilidades Graph
# ----------------------------------------------------------------------------------------------
function Invoke-GraphWithRetry {
    param([Parameter(Mandatory)][string]$Uri)
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri
        }
        catch {
            $msg = $_.Exception.Message
            $transient = $msg -match '429|TooManyRequests|503|504|ServiceUnavailable|GatewayTimeout'
            if (-not $transient -or $attempt -eq 4) { throw }
            Start-Sleep -Seconds ([math]::Pow(2, $attempt))
        }
    }
}

function Get-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    $page = 0
    while ($Uri) {
        $page++
        Write-Progress -Activity 'Leyendo Microsoft Graph' -Status "Página $page ($($items.Count) registros)"
        $resp = Invoke-GraphWithRetry -Uri $Uri
        foreach ($i in $resp['value']) { $items.Add($i) }
        $Uri = $resp['@odata.nextLink']
    }
    Write-Progress -Activity 'Leyendo Microsoft Graph' -Completed
    return , $items
}

function Get-GraphErrorText {
    # Invoke-MgGraphRequest deja el cuerpo de la respuesta de error fuera de Exception.Message; lo recuperamos.
    param([Parameter(Mandatory)]$ErrorRecord)
    $text = [string]$ErrorRecord.Exception.Message
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $text += ' ' + [string]$ErrorRecord.ErrorDetails.Message }
    }
    catch { Write-Verbose 'Sin ErrorDetails.' }
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $resp.Content) { $text += ' ' + [string]$resp.Content.ReadAsStringAsync().Result }
    }
    catch { Write-Verbose 'Sin cuerpo de respuesta.' }
    return $text
}

# ----------------------------------------------------------------------------------------------
# Conexión
# ----------------------------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    $edition = if ($PSVersionTable.PSEdition -eq 'Core') { 'PowerShell' } else { 'Windows PowerShell' }
    Write-Host ''
    Write-Host "Falta el módulo Microsoft.Graph.Authentication en $edition $($PSVersionTable.PSVersion)." -ForegroundColor Yellow
    Write-Host 'Los módulos de Windows PowerShell 5.1 y de PowerShell 7 están en carpetas distintas: hay que instalarlo desde la misma ventana desde la que ejecutas este script:' -ForegroundColor Yellow
    Write-Host '    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' -ForegroundColor Cyan
    Write-Host 'Si pide instalar NuGet o confiar en el repositorio PSGallery, acepta.' -ForegroundColor Yellow
    Wait-ForKeyIfNeeded
    return
}
Import-Module Microsoft.Graph.Authentication

$scopes = @('AuditLog.Read.All')

try {
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
    }
    catch {
        Write-Host ''
        Write-Host 'No se pudo iniciar sesión en Microsoft Graph.' -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor DarkGray
        Write-Host 'Si el mensaje habla de un ensamblado (assembly) o de una versión, suele ser un conflicto con otros módulos cargados (Exchange Online, Az...).' -ForegroundColor Yellow
        Write-Host 'Cierra esta ventana, abre una nueva solo con este script y actualiza el módulo: Update-Module Microsoft.Graph.Authentication' -ForegroundColor Yellow
        Wait-ForKeyIfNeeded
        return
    }
    $ctx = Get-MgContext
    $tenantId = [string]$ctx.TenantId
    $base = 'https://graph.microsoft.com/v1.0'

    # Nombre del tenant (opcional: si falta permiso se usa el identificador)
    $tenantName = $tenantId
    try {
        $org = Invoke-GraphWithRetry -Uri "$base/organization?`$select=displayName"
        if ($org['value'] -and $org['value'][0]['displayName']) { $tenantName = [string]$org['value'][0]['displayName'] }
    }
    catch { Write-Verbose 'No se pudo leer el nombre del tenant; se usará el identificador.' }

    # ------------------------------------------------------------------------------------------
    # Datos de registro de métodos
    # ------------------------------------------------------------------------------------------
    Write-Host "Tenant: $tenantName ($tenantId)" -ForegroundColor Cyan
    Write-Host 'Leyendo el informe de registro de métodos de autenticación...' -ForegroundColor Cyan
    try {
        $rows = Get-GraphPaged -Uri "$base/reports/authenticationMethods/userRegistrationDetails?`$top=999"
    }
    catch {
        $m = Get-GraphErrorText $_
        $code = [regex]::Match($m, '"code"\s*:\s*"([^"]+)"').Groups[1].Value
        $reqId = [regex]::Match($m, '"request-id"\s*:\s*"([^"]+)"').Groups[1].Value
        $detail = if ($code) { "Graph: $code (request-id $reqId)" } else { $m.Substring(0, [math]::Min(300, $m.Length)) }
        if ($m -match 'NonPremium|premium license') {
            Write-Host ''
            Write-Host 'No se puede generar el panel: este tenant no tiene licencia Microsoft Entra ID P1 o P2.' -ForegroundColor Yellow
            Write-Host 'Microsoft exige P1 o P2 para el informe de registro de métodos de autenticación.' -ForegroundColor Yellow
            Write-Host 'P1 se incluye, por ejemplo, en Microsoft 365 Business Premium, E3 y E5.' -ForegroundColor Yellow
            Write-Host $detail -ForegroundColor DarkGray
            Wait-ForKeyIfNeeded
            return
        }
        elseif ($m -match 'Forbidden|403|Authorization_RequestDenied|Insufficient') {
            Write-Host ''
            Write-Host 'Acceso denegado (403) al informe de métodos de autenticación. Causas posibles:' -ForegroundColor Yellow
            Write-Host '  1) El tenant no tiene Entra ID P1 o P2.' -ForegroundColor Yellow
            Write-Host '  2) Falta el permiso AuditLog.Read.All consentido (lo concede un administrador la primera vez).' -ForegroundColor Yellow
            Write-Host '  3) La cuenta no tiene un rol Reports Reader, Security Reader, Security Administrator, Global Reader o superior.' -ForegroundColor Yellow
            Write-Host $detail -ForegroundColor DarkGray
            Wait-ForKeyIfNeeded
            return
        }
        else { throw }
    }

    # ------------------------------------------------------------------------------------------
    # Normalización
    # ------------------------------------------------------------------------------------------
    $users = foreach ($r in $rows) {
        $methods = [string[]]@($r['methodsRegistered'] | Where-Object { $_ })
        $default = $r['userPreferredMethodForSecondaryAuthentication']
        if (-not $default) { $default = $r['defaultMfaMethod'] }
        $updated = ''
        if ($r['lastUpdatedDateTime']) { $updated = ([datetime]$r['lastUpdatedDateTime']).ToUniversalTime().ToString('yyyy-MM-dd') }

        [pscustomobject]@{
            name                = [string]$r['userDisplayName']
            upn                 = [string]$r['userPrincipalName']
            type                = ([string]$r['userType']).ToLowerInvariant()
            admin               = [bool]$r['isAdmin']
            methods             = $methods
            defaultMethod       = [string]$default
            mfaRegistered       = [bool]$r['isMfaRegistered']
            mfaCapable          = [bool]$r['isMfaCapable']
            ssprEnabled         = [bool]$r['isSsprEnabled']
            ssprRegistered      = [bool]$r['isSsprRegistered']
            ssprCapable         = [bool]$r['isSsprCapable']
            passwordlessCapable = [bool]$r['isPasswordlessCapable']
            lastUpdated         = $updated
        }
    }
    $users = @($users)
    # Solo usuarios internos (miembros del tenant): los invitados se excluyen siempre.
    $guestsExcluded = @($users | Where-Object { $_.type -eq 'guest' }).Count
    $users = @($users | Where-Object { $_.type -ne 'guest' })
    Write-Host ("Usuarios analizados: {0}" -f $users.Count) -ForegroundColor Green
    if ($guestsExcluded -gt 0) {
        Write-Host ("Invitados excluidos: {0}" -f $guestsExcluded) -ForegroundColor DarkGray
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

# ----------------------------------------------------------------------------------------------
# Generación del HTML
# ----------------------------------------------------------------------------------------------
$meta = [pscustomobject]@{
    tenantId             = $tenantId
    tenantName           = $tenantName
    generated            = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    lang                 = $Language
    taglineEs            = $TaglineEs
    taglineEn            = $TaglineEn
    guestsExcluded       = [int]$guestsExcluded
}

# Logotipo de Mandover (PNG recortado, incrustado en base64 para que el HTML sea un único fichero)
$LogoBase64 = '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'

function ConvertTo-SafeJson($obj) {
    $json = ConvertTo-Json -InputObject $obj -Depth 5 -Compress
    # Evita cerrar el <script> y separadores de línea Unicode problemáticos en JS
    return $json.Replace('</', '<\/').Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
}

$template = @'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mandover · SMS and voice retirement readiness</title>
<style>
:root{--bg:#0B1E38;--surf:#0F2A4A;--surf2:#14355d;--brand:#233DFF;--light:#97C9FC;--gray:#979DAD;--ok:#2ECC71;--warn:#F2A93B;--bad:#EA5A5F;--line:rgba(151,201,252,.16);--txt:#E8EEF8;color-scheme:dark}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--txt);font:13px/1.45 'Poppins','Segoe UI',system-ui,sans-serif}
.wrap{max-width:1320px;margin:0 auto;padding:22px 24px 40px}
header{background:var(--surf);border:1px solid var(--line);border-radius:14px;padding:14px 20px;margin-bottom:22px}
.top{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px 20px}
.brandrow{display:flex;flex-wrap:wrap;align-items:center;gap:10px 18px}
.logo-link{display:block;border-radius:8px}
.logo{display:block;height:60px;width:auto}
.promo{font-size:14px;font-weight:500;color:var(--txt);max-width:600px;line-height:1.35}
.cta{display:inline-flex;align-items:center;gap:6px;background:var(--brand);color:#fff;text-decoration:none;border-radius:99px;font-weight:600;font-size:12px;padding:7px 16px;white-space:nowrap}
.cta:hover{filter:brightness(1.15)}
.logo-link:focus-visible,.cta:focus-visible{outline:2px solid var(--light);outline-offset:2px}
.hr{height:1px;background:var(--line);margin:12px 0 10px}
h1{margin:2px 0 0;font-size:22px;font-weight:700}
.meta{color:var(--gray);font-size:12px;margin-top:4px}
.meta b{color:var(--light);font-weight:500}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:99px;padding:3px;background:var(--bg)}
.seg button{border:0;background:transparent;color:var(--gray);font:inherit;font-weight:600;padding:5px 16px;border-radius:99px;cursor:pointer}
.seg button[aria-pressed="true"]{background:var(--brand);color:#fff}
.seg button:focus-visible,.card:focus-visible,.brow:focus-visible,.btn:focus-visible,.x:focus-visible{outline:2px solid var(--light);outline-offset:2px}
h2{font-size:16px;font-weight:600;margin:26px 0 12px;color:var(--light)}
.hint{color:var(--gray);font-size:12px;margin:-4px 0 14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:14px}
.card{position:relative;text-align:left;background:var(--surf);border:1px solid var(--line);border-radius:14px;padding:13px 16px 13px 20px;color:inherit;font:inherit;cursor:pointer;overflow:hidden;min-height:116px;display:flex;flex-direction:column;gap:2px;box-shadow:0 2px 8px rgba(0,0,0,.18)}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent,var(--brand))}
.card:hover,.brow:hover{background:var(--surf2)}
.card.ok{--accent:var(--ok)}.card.warn{--accent:var(--warn)}.card.bad{--accent:var(--bad)}
.lbl{font-size:12px;font-weight:500;color:var(--light)}
.val{font-size:28px;font-weight:700;line-height:1.15}
.sub{font-size:11px;color:var(--gray)}
.tag{display:inline-flex;align-items:center;gap:6px;align-self:flex-start;font-size:11px;font-weight:500;padding:1px 9px;border-radius:99px;background:rgba(255,255,255,.07);margin-top:auto}
.tag::before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor}
.tag.ok{color:var(--ok)}.tag.warn{color:var(--warn)}.tag.bad{color:var(--bad)}
.panel{background:var(--surf);border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:0 2px 8px rgba(0,0,0,.18)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(380px,100%),1fr));gap:14px}
.panel h3{margin:0 0 10px;font-size:13px;font-weight:600;color:var(--light)}
.brow{display:grid;grid-template-columns:minmax(220px,1.7fr) 1fr 104px;gap:10px;align-items:center;width:100%;text-align:left;background:transparent;border:0;border-radius:8px;padding:6px 6px;color:inherit;font:inherit;cursor:pointer}
.bl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.track{display:block;height:10px;border-radius:99px;background:rgba(151,201,252,.12);overflow:hidden}
.fill{display:block;height:100%;background:var(--brand);border-radius:99px}
.bn{text-align:right;font-variant-numeric:tabular-nums;color:var(--light)}
.mini{font-size:10px;font-weight:500;margin-left:6px;padding:0 7px;border-radius:99px;background:rgba(255,255,255,.07)}
.mini.ok{color:var(--ok)}.mini.warn{color:var(--warn)}
.foot{margin-top:28px;color:var(--gray);font-size:11px;line-height:1.7}
.mono,td.mono{font-family:Consolas,'Cascadia Mono','Courier New',monospace;font-size:12px}
@media (max-width:600px){.brow{grid-template-columns:1fr auto}.track{display:none}.bl{white-space:normal}}
/* Modal */
.ov{position:fixed;inset:0;background:rgba(5,14,28,.78);display:none;align-items:center;justify-content:center;z-index:10;padding:16px}
.ov.open{display:flex}
.modal{width:min(1240px,100%);max-height:90vh;display:flex;flex-direction:column;background:var(--surf);border:1px solid var(--line);border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.5)}
.mh{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:14px 18px;border-bottom:1px solid var(--line)}
.mh h3{margin:0;font-size:16px;font-weight:600;flex:1 1 260px}
.mh h3 small{display:block;color:var(--gray);font-size:12px;font-weight:400;margin-top:2px}
.mh input{background:var(--bg);border:1px solid var(--line);border-radius:99px;color:var(--txt);font:inherit;padding:7px 14px;min-width:240px}
.btn{border:0;border-radius:99px;background:var(--brand);color:#fff;font:inherit;font-weight:600;padding:8px 18px;cursor:pointer}
.btn.sec{background:transparent;border:1px solid var(--line);color:var(--light)}
.btn:disabled{opacity:.45;cursor:default}
.tw{overflow:auto;flex:1}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
td.wrapc{white-space:normal;min-width:220px}
th{position:sticky;top:0;background:var(--surf2);color:var(--light);font-weight:500;font-size:11px;z-index:1}
tbody tr:hover{background:rgba(151,201,252,.06)}
.yn{display:inline-flex;align-items:center;gap:6px;font-size:12px}
.yn::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--gray)}
.yn.y::before{background:var(--ok)}.yn.n::before{background:var(--bad)}
.mf{padding:9px 18px;color:var(--gray);font-size:11px;border-top:1px solid var(--line)}
.empty{padding:36px;text-align:center;color:var(--gray)}
.alert{display:flex;flex-wrap:wrap;gap:16px 28px;align-items:center;justify-content:space-between;background:var(--surf);border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:14px;padding:14px 20px;margin-bottom:18px}
.adt{flex:1 1 380px}
.adt b{font-size:14px;color:var(--txt)}
.adt p{margin:4px 0 8px;color:var(--gray);font-size:12px}
.more{color:var(--light);font-size:12px;font-weight:600;text-decoration:none}
.more:hover{text-decoration:underline}
.more:focus-visible{outline:2px solid var(--light);outline-offset:2px}
.dates{display:flex;flex-wrap:wrap;gap:12px 28px}
.dt{display:flex;align-items:center;gap:12px}
.dn{font-size:30px;font-weight:700;color:var(--warn);line-height:1;font-variant-numeric:tabular-nums}
.dl{font-size:11px;color:var(--gray);line-height:1.4}
.dl b{color:var(--txt);font-weight:600}
.stack{display:flex;gap:3px;height:44px;border-radius:10px;overflow:hidden}
.seg-b{border:0;color:#0B1E38;font:inherit;font-weight:700;font-size:12px;cursor:pointer;min-width:6px;padding:0}
.seg-b:hover{filter:brightness(1.12)}
.legend{margin-top:12px;display:flex;flex-direction:column;gap:2px}
.lg{display:grid;grid-template-columns:14px 1fr auto;gap:10px;align-items:center;width:100%;text-align:left;background:transparent;border:0;border-radius:8px;padding:7px 6px;color:inherit;font:inherit;cursor:pointer}
.lg:hover{background:var(--surf2)}
.grid6{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.dot{width:10px;height:10px;border-radius:50%}
.seg-b:focus-visible,.lg:focus-visible{outline:2px solid var(--light);outline-offset:2px}
</style>
</head>
<body>
<div class="wrap" id="app"></div>
<div class="ov" id="ov" role="dialog" aria-modal="true"><div class="modal" id="modal"></div></div>
<script>
(function(){
'use strict';
const DATA = __DATA__;
const META = __META__;
const LOGO = 'data:image/png;base64,__LOGO__';
const SITE = 'https://mandover.com/?utm_source=auth-panel&utm_medium=report&utm_campaign=sms-voice-readiness';
const MSDOC = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement';
let lang = META.lang === 'en' ? 'en' : 'es';

const L = {
 es:{
  tagline:'Este panel es solo el principio. Descubre todo lo que Mandover puede hacer por tu entorno M365 y AD.',
  title:'Preparación para la retirada de SMS y voz', sub:'Autenticación del tenant', generated:'Generado', tenant:'Tenant',
  scopeNote:'Microsoft no incluye en este informe las cuentas deshabilitadas ni las eliminadas recientemente',
  guestNote:'Solo usuarios internos (miembros del tenant). Invitados excluidos: {n}',
  hintClick:'Pulsa una tarjeta, un tramo de la barra o un método para ver qué usuarios son.',
  b_title:'Microsoft retira el SMS y la voz propios de Entra ID',
  b_text:'Quien solo tenga SMS o voz como MFA tendrá que registrar un passkey para seguir iniciando sesión. El aviso será bloqueante y sin opción de omitirlo.',
  b_who1:'Todos los usuarios, excepto Global Administrators y usuarios externos', b_who2:'Global Administrators y usuarios externos', b_d1:'1 feb 2027', b_d2:'1 jul 2027', b_days:'días', b_done:'Ya vigente', b_more:'Ver el calendario de Microsoft',
  s_summary:'Estado del tenant', s_ready:'Preparación para el 1 de febrero de 2027', s_methods:'Usuarios por método de autenticación',
  c_all:'Usuarios analizados', c_ready:'Preparados', c_smsOnly:'Dependen solo de SMS o voz', c_noMfa:'Sin ningún método MFA', c_adminSms:'Admins que dependen solo de SMS o voz',
  l_ready:'Preparados', l_smsOnly:'Solo SMS o voz', l_noMfa:'Sin MFA',
  h_all:'Cuentas incluidas en el análisis.',
  h_ready:'Tienen al menos un método MFA que no es SMS ni voz (Authenticator, app OATH, token, FIDO2, passkey, Windows Hello o certificado).',
  h_smsOnly:'Su único MFA disponible es SMS o llamada de voz. El correo y las preguntas de seguridad no cuentan, porque solo sirven para SSPR. Tendrán que registrar un passkey.',
  h_noMfa:'No tienen ningún método MFA registrado. Para registrar un passkey hace falta pasar antes por MFA, así que son los más difíciles de migrar.',
  h_adminSms:'Cuentas con rol de administrador cuyo único MFA es SMS o voz. Son la prioridad.',
  ok:'OK', review:'Revisar', critical:'Crítico', ofUsers:'de los usuarios', ofAdmins:'de los administradores',
  weak:'SMS / voz',
  search:'Buscar por nombre o UPN…', close:'Cerrar', showing:'Mostrando {a} de {b}', cap:'Se muestran los primeros {n}; usa el buscador para acotar.',
  noRows:'No hay usuarios en esta lista.',
  col_name:'Nombre', col_upn:'UPN', col_type:'Tipo', col_admin:'Admin', col_methods:'Métodos registrados', col_updated:'Informe actualizado',
  yes:'Sí', no:'No', member:'Miembro', guest:'Invitado',
  n1:'Preparado = al menos un método MFA que no es SMS ni voz. Solo SMS o voz = su único MFA es telefónico. Sin MFA = ningún método MFA (el correo y las preguntas de seguridad solo sirven para SSPR). Los tres grupos suman el total.',
  n2:'El informe de Microsoft agrupa SMS y voz bajo el método teléfono y no los distingue. Las fechas son las publicadas por Microsoft; confírmalas en su documentación, porque pueden cambiar. Los datos del informe pueden tener hasta 36 horas de retraso y no reflejan el MFA aplicado fuera de Microsoft Entra ID (proveedor externo o federado).',
  n3:'Fuente: Microsoft Graph · reports/authenticationMethods/userRegistrationDetails. Panel de solo lectura generado por Mandover.'
 },
 en:{
  tagline:'This panel is just the beginning. Discover everything Mandover can do for your M365 and AD environment.',
  title:'SMS and voice retirement readiness', sub:'Tenant authentication', generated:'Generated', tenant:'Tenant',
  scopeNote:'Microsoft leaves disabled and recently deleted accounts out of this report',
  guestNote:'Internal users only (tenant members). Guests excluded: {n}',
  hintClick:'Click a card, a bar segment or a method to see which users they are.',
  b_title:'Microsoft is retiring its own SMS and voice authentication in Entra ID',
  b_text:'Anyone whose only MFA is SMS or voice will have to register a passkey to keep signing in. The prompt will be blocking, with no way to skip it.',
  b_who1:'All users except Global Administrators and external users', b_who2:'Global Administrators and external users', b_d1:'1 Feb 2027', b_d2:'1 Jul 2027', b_days:'days', b_done:'Already in effect', b_more:"See Microsoft's timeline",
  s_summary:'Tenant status', s_ready:'Readiness for 1 February 2027', s_methods:'Users by authentication method',
  c_all:'Users analysed', c_ready:'Ready', c_smsOnly:'Rely only on SMS or voice', c_noMfa:'No MFA method at all', c_adminSms:'Admins relying only on SMS or voice',
  l_ready:'Ready', l_smsOnly:'SMS or voice only', l_noMfa:'No MFA',
  h_all:'Accounts included in the analysis.',
  h_ready:'Have at least one MFA method that is not SMS or voice (Authenticator, OATH app, token, FIDO2, passkey, Windows Hello or certificate).',
  h_smsOnly:'Their only available MFA is SMS or a voice call. Email and security questions do not count, because they only work for SSPR. They will have to register a passkey.',
  h_noMfa:'No MFA method registered. Registering a passkey requires passing MFA first, so they are the hardest to migrate.',
  h_adminSms:'Admin-role accounts whose only MFA is SMS or voice. These are the priority.',
  ok:'OK', review:'Review', critical:'Critical', ofUsers:'of users', ofAdmins:'of admins',
  weak:'SMS / voice',
  search:'Search by name or UPN…', close:'Close', showing:'Showing {a} of {b}', cap:'Showing the first {n}; use the search box to narrow down.',
  noRows:'There are no users in this list.',
  col_name:'Name', col_upn:'UPN', col_type:'Type', col_admin:'Admin', col_methods:'Registered methods', col_updated:'Report updated',
  yes:'Yes', no:'No', member:'Member', guest:'Guest',
  n1:'Ready = at least one MFA method that is not SMS or voice. SMS or voice only = their only MFA is by phone. No MFA = no MFA method (email and security questions only work for SSPR). The three groups add up to the total.',
  n2:'The Microsoft report groups SMS and voice under the phone method and does not tell them apart. Dates are those published by Microsoft; confirm them in their documentation, as they may change. Report data can lag by up to 36 hours and does not reflect MFA enforced outside Microsoft Entra ID (third-party or federated).',
  n3:'Source: Microsoft Graph · reports/authenticationMethods/userRegistrationDetails. Read-only panel generated by Mandover.'
 }
};
const t = k => (L[lang][k] !== undefined ? L[lang][k] : k);

const ML = {
 mobilePhone:['SMS / llamada móvil','SMS / mobile call'], alternateMobilePhone:['Móvil alternativo (SMS / llamada)','Alternate mobile (SMS / call)'], officePhone:['Teléfono de oficina (llamada)','Office phone (call)'],
 email:['Correo electrónico (solo SSPR)','Email (SSPR only)'], securityQuestion:['Preguntas de seguridad (solo SSPR)','Security questions (SSPR only)'],
 microsoftAuthenticatorPush:['Authenticator (notificación)','Authenticator (push)'], microsoftAuthenticatorPasswordless:['Authenticator (sin contraseña)','Authenticator (passwordless)'],
 softwareOneTimePasscode:['App OATH / TOTP','OATH / TOTP app'], hardwareOneTimePasscode:['Token OATH hardware','Hardware OATH token'], temporaryAccessPass:['Pase de acceso temporal','Temporary Access Pass'],
 fido2:['Llave FIDO2','FIDO2 key'], windowsHelloForBusiness:['Windows Hello para empresas','Windows Hello for Business'],
 passKeyDeviceBound:['Passkey (dispositivo)','Passkey (device-bound)'], passKeyDeviceBoundAuthenticator:['Passkey (Authenticator)','Passkey (Authenticator)'], passKeyDeviceBoundWindowsHello:['Passkey (Windows Hello)','Passkey (Windows Hello)'],
 certificateBasedAuthentication:['Certificado (CBA)','Certificate (CBA)']
};
const mlabel = m => ML[m] ? ML[m][lang === 'en' ? 1 : 0] : m;
const WEAK = {mobilePhone:1, alternateMobilePhone:1, officePhone:1};
const NONMFA = {email:1, securityQuestion:1, temporaryAccessPass:1};
const mfaM = u => u.methods.filter(m => !NONMFA[m]);
const isReady = u => mfaM(u).some(m => !WEAK[m]);
const isSmsOnly = u => { const m = mfaM(u); return m.length > 0 && m.every(x => WEAK[x]); };
const isNoMfa = u => mfaM(u).length === 0;

const F = {
 all: () => true,
 ready: isReady,
 smsOnly: isSmsOnly,
 noMfa: isNoMfa,
 adminSms: u => u.admin && isSmsOnly(u)
};
function filt(key){
 if (F[key]) return F[key];
 const i = key.indexOf(':'), k = key.slice(0, i), v = key.slice(i + 1);
 if (k === 'm') return u => u.methods.indexOf(v) >= 0;
 return () => false;
}
const cache = {};
const count = key => (cache[key] !== undefined ? cache[key] : (cache[key] = DATA.filter(filt(key)).length));
const TOTAL = DATA.length;
const ADMINS = DATA.filter(u => u.admin).length;
const pct = (n, d) => (d ? (n / d * 100).toFixed(1) : '0.0') + '%';
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num = n => n.toLocaleString(lang === 'en' ? 'en-GB' : 'es-ES');
const daysTo = (y, m, d) => Math.ceil((Date.UTC(y, m, d) - Date.now()) / 864e5);

const CARDS = ['all', 'ready', 'smsOnly', 'noMfa', 'adminSms'];
const titleFor = key => F[key] ? t('c_' + key) : mlabel(key.slice(key.indexOf(':') + 1));

function card(key){
 const n = count(key);
 let cls = '', tag = '', sub;
 const sev = (key === 'smsOnly' || key === 'noMfa') ? 'warn' : (key === 'adminSms' ? 'bad' : '');
 if (sev){
  if (n === 0){ cls = 'ok'; tag = '<span class="tag ok">' + t('ok') + '</span>'; }
  else { cls = sev; tag = '<span class="tag ' + sev + '">' + t(sev === 'bad' ? 'critical' : 'review') + '</span>'; }
 }
 if (key === 'all') sub = '&nbsp;';
 else if (key === 'adminSms') sub = pct(n, ADMINS) + ' ' + t('ofAdmins');
 else sub = pct(n, TOTAL) + ' ' + t('ofUsers');
 return '<button class="card ' + cls + '" data-k="' + esc(key) + '" title="' + esc(t('h_' + key)) + '">' +
  '<span class="lbl">' + esc(t('c_' + key)) + '</span><span class="val">' + num(n) + '</span><span class="sub">' + sub + '</span>' + tag + '</button>';
}

function banner(){
 const d1 = daysTo(2027, 1, 1), d2 = daysTo(2027, 6, 1);
 const dt = (d, date, who) => '<div class="dt"><span class="dn">' + (d > 0 ? num(d) : '—') + '</span><span class="dl">' + (d > 0 ? t('b_days') : t('b_done')) + ' · <b>' + esc(date) + '</b><br>' + esc(who) + '</span></div>';
 return '<div class="alert"><div class="adt"><b>' + esc(t('b_title')) + '</b><p>' + esc(t('b_text')) + '</p>' +
  '<a class="more" href="' + MSDOC + '" target="_blank" rel="noopener noreferrer">' + esc(t('b_more')) + ' <span aria-hidden="true">&#8599;</span></a></div>' +
  '<div class="dates">' + dt(d1, t('b_d1'), t('b_who1')) + dt(d2, t('b_d2'), t('b_who2')) + '</div></div>';
}

function stack(){
 const segs = [['ready', 'var(--ok)'], ['smsOnly', 'var(--warn)'], ['noMfa', 'var(--bad)']];
 if (!TOTAL) return '<div class="empty">' + t('noRows') + '</div>';
 const bar = segs.filter(s => count(s[0]) > 0).map(s => {
  const n = count(s[0]), share = n / TOTAL;
  return '<button class="seg-b" data-k="' + s[0] + '" style="flex:' + n + ';background:' + s[1] + '" aria-label="' + esc(t('l_' + s[0]) + ': ' + num(n)) + '">' + (share >= 0.07 ? Math.round(share * 100) + '%' : '') + '</button>';
 }).join('');
 const legend = segs.map(s => {
  const n = count(s[0]);
  return '<button class="lg" data-k="' + s[0] + '"><span class="dot" style="background:' + s[1] + '"></span><span class="lgl">' + esc(t('l_' + s[0])) + '</span><span class="bn">' + num(n) + ' · ' + pct(n, TOTAL) + '</span></button>';
 }).join('');
 return '<div class="stack">' + bar + '</div><div class="legend">' + legend + '</div>';
}

function methodRows(){
 const tally = {};
 DATA.forEach(u => u.methods.forEach(m => { tally[m] = (tally[m] || 0) + 1; }));
 return Object.keys(tally).sort((a, b) => tally[b] - tally[a]).map(m => {
  const n = tally[m], w = n > 0 ? Math.max(1, n / (TOTAL || 1) * 100) : 0;
  const tg = WEAK[m] ? '<span class="mini warn">' + t('weak') + '</span>' : '';
  return '<button class="brow" data-k="m:' + esc(m) + '"><span class="bl">' + esc(mlabel(m)) + tg + '</span>' +
   '<span class="track"><span class="fill" style="width:' + w.toFixed(1) + '%"></span></span><span class="bn">' + num(n) + ' · ' + pct(n, TOTAL) + '</span></button>';
 }).join('');
}

function render(){
 document.documentElement.lang = lang;
 document.title = 'Mandover · ' + t('title');
 const tagline = (lang === 'en' ? META.taglineEn : META.taglineEs) || t('tagline');
 const scope = t('scopeNote') + ' · ' + t('guestNote').replace('{n}', num(META.guestsExcluded || 0));
 document.getElementById('app').innerHTML =
  '<header><div class="top"><div class="brandrow">' +
  '<a class="logo-link" href="' + SITE + '" target="_blank" rel="noopener noreferrer" aria-label="Mandover"><img class="logo" src="' + LOGO + '" alt="Mandover"></a>' +
  '<span class="promo">' + esc(tagline) + '</span>' +
  '<a class="cta" href="' + SITE + '" target="_blank" rel="noopener noreferrer">mandover.com <span aria-hidden="true">&#8599;</span></a></div>' +
  '<div class="seg" role="group" aria-label="Language"><button data-lang="es" aria-pressed="' + (lang === 'es') + '">ES</button><button data-lang="en" aria-pressed="' + (lang === 'en') + '">EN</button></div></div>' +
  '<div class="hr"></div><h1>' + esc(t('title')) + ' · ' + esc(t('sub')) + '</h1>' +
  '<div class="meta">' + t('tenant') + ': <b>' + esc(META.tenantName) + '</b> · <span class="mono">' + esc(META.tenantId) + '</span> · ' + t('generated') + ': <b>' + esc(META.generated) + '</b> · ' + esc(scope) + '</div></header>' +
  banner() +
  '<p class="hint">' + t('hintClick') + '</p>' +
  '<h2>' + t('s_summary') + '</h2><div class="grid grid6">' + CARDS.map(card).join('') + '</div>' +
  '<div class="cols" style="margin-top:26px">' +
   '<div><h2 style="margin-top:0">' + t('s_ready') + '</h2><div class="panel">' + stack() + '</div></div>' +
   '<div><h2 style="margin-top:0">' + t('s_methods') + '</h2><div class="panel">' + methodRows() + '</div></div></div>' +
  '<div class="foot">' + t('n1') + '<br>' + t('n2') + '<br>' + t('n3') + '</div>';
 if (cur) renderModal(false);
}

/* ---------- Lista de usuarios (modal, solo lectura) ---------- */
let cur = null, opener = null;
const CAP = 2000;
function rowsNow(){
 const f = filt(cur.key), q = cur.q.trim().toLowerCase();
 return DATA.filter(f).filter(u => !q || (u.name + ' ' + u.upn).toLowerCase().indexOf(q) >= 0);
}
const ynNeutral = v => '<span class="yn ' + (v ? 'y' : '') + '">' + t(v ? 'yes' : 'no') + '</span>';
function tbody(rs){
 if (!rs.length) return '<tr><td colspan="6" class="empty">' + t('noRows') + '</td></tr>';
 return rs.slice(0, CAP).map(u =>
  '<tr><td>' + esc(u.name) + '</td><td class="mono">' + esc(u.upn) + '</td><td>' + t(u.type === 'guest' ? 'guest' : 'member') + '</td><td>' + ynNeutral(u.admin) + '</td>' +
  '<td class="wrapc">' + esc(u.methods.map(mlabel).join(', ') || '—') + '</td><td>' + esc(u.lastUpdated || '—') + '</td></tr>').join('');
}
function counter(rs){
 let s = t('showing').replace('{a}', num(Math.min(rs.length, CAP))).replace('{b}', num(rs.length));
 if (rs.length > CAP) s += ' · ' + t('cap').replace('{n}', num(CAP));
 return s;
}
function renderModal(focusSearch){
 const rs = rowsNow();
 document.getElementById('modal').innerHTML =
  '<div class="mh"><h3>' + esc(titleFor(cur.key)) + '<small id="cnt">' + esc(counter(rs)) + '</small></h3>' +
  '<input id="q" type="search" placeholder="' + esc(t('search')) + '" value="' + esc(cur.q) + '" aria-label="' + esc(t('search')) + '">' +
  '<button class="btn sec x" id="cls">' + t('close') + '</button></div>' +
  '<div class="tw"><table><thead><tr><th>' + t('col_name') + '</th><th>' + t('col_upn') + '</th><th>' + t('col_type') + '</th><th>' + t('col_admin') + '</th><th>' + t('col_methods') + '</th><th>' + t('col_updated') + '</th></tr></thead>' +
  '<tbody id="tb">' + tbody(rs) + '</tbody></table></div>';
 document.getElementById('ov').classList.add('open');
 if (focusSearch) document.getElementById('q').focus();
}
function openList(key){ cur = { key: key, q: '' }; renderModal(true); }
function closeList(){
 cur = null;
 document.getElementById('ov').classList.remove('open');
 document.getElementById('modal').innerHTML = '';
 if (opener && opener.focus) opener.focus();
}
function refreshRows(){
 const rs = rowsNow();
 document.getElementById('tb').innerHTML = tbody(rs);
 document.getElementById('cnt').textContent = counter(rs);
}

/* ---------- Eventos ---------- */
document.getElementById('app').addEventListener('click', e => {
 const lg = e.target.closest('[data-lang]');
 if (lg){ lang = lg.getAttribute('data-lang'); render(); return; }
 const k = e.target.closest('[data-k]');
 if (k){ opener = k; openList(k.getAttribute('data-k')); }
});
document.getElementById('ov').addEventListener('click', e => {
 if (e.target.id === 'ov' || e.target.id === 'cls') closeList();
});
document.getElementById('ov').addEventListener('input', e => {
 if (e.target.id === 'q' && cur){ cur.q = e.target.value; refreshRows(); }
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && cur) closeList(); });

render();
})();
</script>
</body>
</html>
'@

$html = $template.Replace('__DATA__', (ConvertTo-SafeJson $users)).Replace('__META__', (ConvertTo-SafeJson $meta)).Replace('__LOGO__', $LogoBase64)

if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$idShort = if ($tenantId.Length -ge 8) { $tenantId.Substring(0, 8) } else { $tenantId }
$file = Join-Path $OutputFolder "Mandover-AuthReadiness-$idShort-$stamp.html"
[System.IO.File]::WriteAllText($file, $html, (New-Object System.Text.UTF8Encoding($true)))

Write-Host "Panel generado: $file" -ForegroundColor Green
if (-not $NoOpen) { Start-Process $file }
Wait-ForKeyIfNeeded
