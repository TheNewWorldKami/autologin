#Requires -Version 5.1
<#
.SYNOPSIS
    校园网自动登录：开机自启的后台常驻程序 + 菜单式管理界面。

.DESCRIPTION
    无参数运行 -> 打开菜单：
        后台在跑  -> 提供「关闭自动登录」
        后台没跑  -> 提供「修改账户/密码」「启动自动登录」

    后台进程（-Daemon）由登录时的计划任务拉起，常驻等待网络连接；
    一旦检测到网络连上，等 1 秒后确认是校园网且未登录，就用保存的账号登录。

.PARAMETER Daemon
    以后台常驻模式运行（由计划任务调用，正常不需要手动执行）。
#>
[CmdletBinding()]
param(
    [switch]$Daemon
)

$ErrorActionPreference = 'Stop'

$script:Root = $PSScriptRoot
if (-not $script:Root) { $script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:ConfigPath = Join-Path $script:Root 'config.json'
$script:DataDir = Join-Path $script:Root 'data'
$script:LogDir = Join-Path $script:DataDir 'logs'
$script:CredPath = Join-Path $script:DataDir 'creds.dat'
$script:PidPath = Join-Path $script:DataDir 'daemon.pid'
$script:TaskName = 'CaptiveAutoLogin'
$script:MutexName = 'Local\CaptiveAutoLoginDaemon'
$script:LogMaxBytes = 1048576

# ============================================================
# 配置
# ============================================================

function Get-DefaultConfig {
    return [pscustomobject]@{
        portal_host       = '192.168.100.200'
        session_url       = 'http://192.168.100.200:801/eportal/portal/online_list?callback=dr1003&jsVersion=4.1.3'
        login_url         = 'http://192.168.100.200/drcom/login'
        timeout_sec       = 8
        connect_delay_sec = 1
        login_fields      = [pscustomobject][ordered]@{
            callback      = 'dr1003'
            DDDDD         = '{username}'
            upass         = '{password}'
            '0MKKey'      = '123456'
            R1            = '0'
            R2            = ''
            R3            = '0'
            R6            = '0'
            para          = '00'
            v6ip          = ''
            terminal_type = '1'
            lang          = 'zh-cn'
            jsVersion     = '4.1.3'
            v             = '8249'
        }
    }
}

function Get-Config {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        $cfg = Get-DefaultConfig
        $cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
        return $cfg
    }
    return (Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
}

# ============================================================
# 目录 / 日志
# ============================================================

function Initialize-Paths {
    foreach ($d in @($script:DataDir, $script:LogDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        Initialize-Paths
        $file = Join-Path $script:LogDir 'autologin.log'
        if ((Test-Path -LiteralPath $file) -and ((Get-Item -LiteralPath $file).Length -gt $script:LogMaxBytes)) {
            Move-Item -LiteralPath $file -Destination "$file.1" -Force
        }
        Add-Content -LiteralPath $file -Value $line -Encoding UTF8
    } catch { }
}

# ============================================================
# 账号密码（DPAPI 加密，仅当前 Windows 用户可解密）
# ============================================================

function Save-Creds {
    param([string]$UserName, [string]$Password)
    $json = [ordered]@{ u = $UserName; p = $Password } | ConvertTo-Json -Compress
    $secure = ConvertTo-SecureString -String $json -AsPlainText -Force
    $cipher = ConvertFrom-SecureString -SecureString $secure
    Initialize-Paths
    Set-Content -LiteralPath $script:CredPath -Value $cipher -Encoding ASCII
}

function Get-Creds {
    if (-not (Test-Path -LiteralPath $script:CredPath)) { return $null }
    try {
        $cipher = (Get-Content -LiteralPath $script:CredPath -Raw).Trim()
        if (-not $cipher) { return $null }
        $secure = ConvertTo-SecureString -String $cipher
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $obj = $plain | ConvertFrom-Json
        if (-not $obj.u -or -not $obj.p) { return $null }
        return [pscustomobject]@{ UserName = [string]$obj.u; Password = [string]$obj.p }
    } catch {
        return $null
    }
}

# ============================================================
# HTTP
# ============================================================

function Invoke-GetRaw {
    param([string]$Uri, [int]$TimeoutSec = 8)
    try {
        $r = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSec -MaximumRedirection 0 -ErrorAction Stop
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { return [pscustomobject]@{ Status = 0; Body = '' } }
        return [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = '' }
    }
}

# ============================================================
# 校园网判定 / 登录
# ============================================================

function Test-SessionOnline {
    # $true=校园网且已登录，$false=校园网但未登录，$null=不是校园网
    param($Config)

    $resp = Invoke-GetRaw -Uri $Config.session_url -TimeoutSec ([int]$Config.timeout_sec)
    if (($resp.Status -ge 300) -and ($resp.Status -lt 400)) { return $false }
    if ($resp.Status -ne 200) { return $null }

    $text = [string]$resp.Body
    $start = $text.IndexOf('{')
    $end = $text.LastIndexOf('}')
    if ($start -lt 0 -or $end -le $start) { return $null }

    try {
        $obj = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json
    } catch {
        return $null
    }
    if ($null -eq $obj.result) { return $null }
    if ([int]$obj.result -ne 1) { return $false }

    foreach ($item in @($obj.list)) {
        if ($null -ne $item) { return $true }
    }
    return $false
}

function Invoke-Login {
    param($Config, $Cred)

    $loginHost = ''
    try { $loginHost = ([uri]$Config.login_url).Host } catch { return $false }
    if ($loginHost -ne [string]$Config.portal_host) {
        Write-Log ('登录地址 {0} 与门户主机不一致，已拒绝提交。' -f $loginHost) 'ERROR'
        return $false
    }

    $pairs = [ordered]@{}
    foreach ($prop in $Config.login_fields.PSObject.Properties) {
        $value = [string]$prop.Value
        $value = $value.Replace('{username}', $Cred.UserName).Replace('{password}', $Cred.Password)
        $pairs[$prop.Name] = $value
    }

    $parts = foreach ($key in $pairs.Keys) {
        '{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$pairs[$key])
    }
    $sep = '?'
    if ($Config.login_url.Contains('?')) { $sep = '&' }
    $url = $Config.login_url + $sep + ($parts -join '&')

    $resp = Invoke-GetRaw -Uri $url -TimeoutSec ([int]$Config.timeout_sec)
    if ($resp.Status -ne 200) {
        Write-Log ('登录请求返回 HTTP {0}。' -f $resp.Status) 'WARN'
    }

    Start-Sleep -Seconds 1
    return ((Test-SessionOnline -Config $Config) -eq $true)
}

function Invoke-AutoLogin {
    param($Config)

    $session = Test-SessionOnline -Config $Config
    if ($null -eq $session) {
        Write-Log '当前网络不是校园网，跳过登录。'
        return
    }
    if ($session -eq $true) {
        Write-Log '校园网已在线，无需登录。'
        return
    }

    $cred = Get-Creds
    if (-not $cred) {
        Write-Log '尚未设置账号密码，无法登录。' 'WARN'
        return
    }

    Write-Log '检测到校园网未登录，开始登录…'
    if (Invoke-Login -Config $Config -Cred $cred) {
        Write-Log '登录成功，网络已恢复。'
    } else {
        Write-Log '登录失败，请检查账号密码是否正确。' 'WARN'
    }
}

# ============================================================
# 后台常驻进程
# ============================================================

function Get-DaemonProcesses {
    # 找出本脚本的 -Daemon 进程（排除自己）。
    # 只认「--File "脚本路径" -Daemon」结尾的命令行，避免误伤命令行里恰好含这些文字的其它 shell。
    $result = @()
    $pattern = '(?i)-File\s+"[^"]*CaptiveAutoLogin\.ps1"\s+-Daemon\s*$'
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop
        foreach ($p in $procs) {
            if ([int]$p.ProcessId -eq $PID) { continue }
            if ([string]$p.CommandLine -match $pattern) {
                $result += [int]$p.ProcessId
            }
        }
    } catch { }
    return $result
}

function Test-DaemonRunning {
    if ((Get-DaemonProcesses).Count -gt 0) { return $true }
    if (-not (Test-Path -LiteralPath $script:PidPath)) { return $false }
    $raw = (Get-Content -LiteralPath $script:PidPath -Raw -ErrorAction SilentlyContinue)
    if (-not $raw) { return $false }
    $daemonPid = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$daemonPid)) { return $false }
    if ($daemonPid -le 0) { return $false }
    $proc = Get-Process -Id $daemonPid -ErrorAction SilentlyContinue
    if (-not $proc) { return $false }
    # 防止 PID 被系统复用后误判成自己的进程
    return ($proc.ProcessName -eq 'powershell')
}

function Start-Daemon {
    if (Test-DaemonRunning) { return $true }
    Remove-Item -LiteralPath $script:PidPath -Force -ErrorAction SilentlyContinue
    $scriptPath = Join-Path $script:Root 'CaptiveAutoLogin.ps1'
    $proc = Start-Process powershell.exe `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$scriptPath`"", '-Daemon') `
        -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 1500
    return (-not $proc.HasExited)
}

function Stop-Daemon {
    $targets = @{}
    foreach ($id in (Get-DaemonProcesses)) { $targets[$id] = $true }

    if (Test-Path -LiteralPath $script:PidPath) {
        $raw = (Get-Content -LiteralPath $script:PidPath -Raw -ErrorAction SilentlyContinue)
        $daemonPid = 0
        if ($raw -and [int]::TryParse($raw.Trim(), [ref]$daemonPid) -and $daemonPid -gt 0) {
            $proc = Get-Process -Id $daemonPid -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -eq 'powershell') { $targets[$daemonPid] = $true }
        }
        Remove-Item -LiteralPath $script:PidPath -Force -ErrorAction SilentlyContinue
    }

    foreach ($id in $targets.Keys) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
    return ($targets.Count -gt 0)
}

function Invoke-Daemon {
    $mutex = New-Object System.Threading.Mutex($false, $script:MutexName)
    if (-not $mutex.WaitOne(0)) { return }

    Initialize-Paths
    Set-Content -LiteralPath $script:PidPath -Value $PID -Encoding ASCII
    $config = Get-Config
    $delay = [Math]::Max(0, [int]$config.connect_delay_sec)
    Write-Log ('后台进程已启动（PID {0}），等待网络连接…' -f $PID)

    try {
        $wasUp = $false
        while ($true) {
            $up = [System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()
            if ($up -and (-not $wasUp)) {
                Write-Log '检测到网络已连接。'
                if ($delay -gt 0) { Start-Sleep -Seconds $delay }
                Invoke-AutoLogin -Config $config
            }
            $wasUp = $up
            Start-Sleep -Seconds 1
        }
    } finally {
        Remove-Item -LiteralPath $script:PidPath -Force -ErrorAction SilentlyContinue
        try { $mutex.ReleaseMutex() } catch { }
        try { $mutex.Dispose() } catch { }
    }
}

# ============================================================
# 开机自启（登录时拉起后台进程）
# ============================================================

function Install-AutoStart {
    $scriptPath = Join-Path $script:Root 'CaptiveAutoLogin.ps1'
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $argument = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Daemon' -f $scriptPath

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask -TaskName $script:TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description '校园网自动登录后台进程' `
        -Force | Out-Null
}

function Uninstall-AutoStart {
    try {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction Stop
    } catch { }
}

# ============================================================
# 交互界面
# ============================================================

function Read-PlainPassword {
    param([string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    if (-not $secure) { return '' }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Invoke-ChangeAccount {
    $existing = Get-Creds

    Write-Host ''
    Write-Host '--- 修改账户 / 密码 ---' -ForegroundColor Cyan

    $defaultUser = ''
    if ($existing) { $defaultUser = $existing.UserName }
    $user = Read-Host ('账号（回车保持不变：{0}）' -f $defaultUser)
    if ([string]::IsNullOrWhiteSpace($user)) { $user = $defaultUser }
    if ([string]::IsNullOrWhiteSpace($user)) {
        Write-Host '账号不能为空。' -ForegroundColor Red
        return
    }

    $pass1 = Read-PlainPassword '密码（输入时不显示）'
    if ([string]::IsNullOrEmpty($pass1)) {
        if ($existing) {
            $pass1 = $existing.Password
            Write-Host '保持原密码不变。' -ForegroundColor DarkGray
        } else {
            Write-Host '密码不能为空。' -ForegroundColor Red
            return
        }
    } else {
        $pass2 = Read-PlainPassword '再次输入密码确认'
        if ($pass1 -cne $pass2) {
            Write-Host '两次输入的密码不一致，未保存。' -ForegroundColor Red
            return
        }
    }

    Save-Creds -UserName $user -Password $pass1
    Write-Host ('已保存：账号 {0}' -f $user) -ForegroundColor Green
    Write-Host ''
}

function Invoke-StartAutoLogin {
    if (-not (Get-Creds)) {
        Write-Host '还没设置账号密码，请先选择「修改账户 / 密码」。' -ForegroundColor Yellow
        Write-Host ''
        return
    }

    try {
        Install-AutoStart
    } catch {
        Write-Host ('开机自启注册失败：{0}' -f $_.Exception.Message) -ForegroundColor Red
        Write-Host '后台进程仍会立即启动，但重启后不会自动运行。' -ForegroundColor Yellow
    }

    if (Start-Daemon) {
        Write-Host '已启动：每次连上校园网会自动登录。' -ForegroundColor Green
    } else {
        Write-Host '后台进程启动失败。' -ForegroundColor Red
    }
    Write-Host ''
}

function Invoke-StopAutoLogin {
    $stopped = Stop-Daemon
    Uninstall-AutoStart
    if ($stopped) {
        Write-Host '已关闭，开机也不再自动运行。' -ForegroundColor Green
    } else {
        Write-Host '已关闭开机自启（后台进程本来就没在运行）。' -ForegroundColor Green
    }
    Write-Host ''
}

function Show-Menu {
    while ($true) {
        $running = Test-DaemonRunning
        $cred = Get-Creds

        Write-Host ''
        Write-Host '====================================' -ForegroundColor DarkCyan
        Write-Host '        校园网自动登录' -ForegroundColor Cyan
        Write-Host '====================================' -ForegroundColor DarkCyan
        $stateText = '已关闭'
        $stateColor = 'Yellow'
        if ($running) { $stateText = '运行中'; $stateColor = 'Green' }
        Write-Host ('状态：{0}' -f $stateText) -ForegroundColor $stateColor
        if ($cred) {
            Write-Host ('账号：{0}' -f $cred.UserName) -ForegroundColor DarkGray
        } else {
            Write-Host '账号：未设置' -ForegroundColor DarkGray
        }
        Write-Host ''

        if ($running) {
            Write-Host '  [1] 关闭自动登录'
            Write-Host '  [0] 退出'
        } else {
            Write-Host '  [1] 修改账户 / 密码'
            Write-Host '  [2] 启动自动登录'
            Write-Host '  [0] 退出'
        }
        Write-Host ''

        $choice = Read-Host '请选择'
        if ($choice -eq '0') { return }

        if ($running) {
            if ($choice -eq '1') {
                Invoke-StopAutoLogin
            } else {
                Write-Host '无效选项。' -ForegroundColor Red
            }
        } else {
            switch ($choice) {
                '1' { Invoke-ChangeAccount }
                '2' { Invoke-StartAutoLogin }
                default { Write-Host '无效选项。' -ForegroundColor Red }
            }
        }
    }
}

# ============================================================
# 入口
# ============================================================

if ($Daemon) {
    Invoke-Daemon
    exit 0
}

Show-Menu
