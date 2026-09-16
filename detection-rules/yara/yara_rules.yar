/*
 * yara_rules.yar
 * AI-Powered Threat Detection System
 * YARA Rules for malware classification
 * MITRE ATT&CK Mapping Included
 */

import "pe"

/* ================================================
 * RANSOMWARE DETECTION RULES
 * MITRE ATT&CK: T1486 - Data Encrypted for Impact
 * ================================================ */

rule Ransomware_Extensions
{
    meta:
        description = "Detects ransomware by encrypted file extensions"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1486/"
        mitre_attack = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        category = "ransomware"

    strings:
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypto" ascii wide
        $ext4 = ".wncry" ascii wide
        $ext5 = ".ryuk" ascii wide
        $ext6 = ".locky" ascii wide
        $ext7 = ".crypt" ascii wide
        $ext8 = ".ddd" ascii wide
        $ext9 = ".good" ascii wide
        $ext10 = ".kevin" ascii wide
        $ext11 = "_enc" ascii wide
        $ext12 = ".payday" ascii wide

    condition:
        (2 of ($ext*)) and uint16(0) == 0x5A4D
}

rule Ransomware_Note
{
    meta:
        description = "Detects ransomware by ransom note content"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1486/"
        mitre_attack = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        category = "ransomware"

    strings:
        $note1 = "YOUR FILES ARE ENCRYPTED" ascii wide
        $note2 = "DECRYPT YOUR FILES" ascii wide
        $note3 = "BITCOIN" ascii wide
        $note4 = "PAY RANSOM" ascii wide
        $note5 = "YOUR COMPUTER HAS BEEN LOCKED" ascii wide
        $note6 = "FILES HAVE BEEN ENCRYPTED" ascii wide
        $note7 = "DO NOT ATTEMPT TO RECOVER" ascii wide
        $note8 = "TOR BROWSER" ascii wide
        $note9 = "payment" ascii wide
        $note10 = "decryption key" ascii wide
        $note11 = "wallet" ascii wide
        $note12 = "support@ransom" ascii wide

    condition:
        (2 of ($note*))
}

rule Ransomware_Encryption
{
    meta:
        description = "Detects ransomware encryption patterns"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1486/"
        mitre_attack = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        category = "ransomware"

    strings:
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "CryptDecrypt" ascii
        $crypto3 = "AES" ascii
        $crypto4 = "RSA" ascii
        $crypto5 = "rijndael" ascii
        $crypto6 = "EncryptFile" ascii
        $crypto7 = "encrypt" ascii fullword
        $crypto8 = "BCryptEncrypt" ascii
        $crypto9 = "CryptAcquireContextW" ascii
        $crypto10 = "CryptGenKey" ascii
        $crypto11 = "CryptExportKey" ascii
        $crypto12 = "CryptImportKey" ascii

        $api1 = "WriteFile" ascii fullword
        $api2 = "DeleteFileW" ascii fullword
        $api3 = "MoveFileW" ascii fullword
        $api4 = "FindFirstFileW" ascii fullword
        $api5 = "FindNextFileW" ascii fullword
        $api6 = "CreateFileW" ascii fullword

    condition:
        uint16(0) == 0x5A4D and (3 of ($crypto*) and 2 of ($api*))
}

rule Lockbit_Patterns
{
    meta:
        description = "Detects LockBit ransomware family"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1486/"
        mitre_attack = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        category = "ransomware"

    strings:
        $lockbit1 = "LockBit" ascii fullword
        $lockbit2 = "lockbit_" ascii
        $lockbit3 = "LockBit 2.0" ascii
        $lockbit4 = ".lockbit" ascii
        $lockbit5 = "README.lockbit" ascii
        $lockbit6 = "skidcrypt" ascii
        $mutex1 = "Mutex" ascii fullword
        $mutex2 = "LockBit_" ascii

    condition:
        uint16(0) == 0x5A4D and (2 of ($lockbit*) or (1 of ($lockbit*) and any of ($mutex*)))
}

rule Ryuk_Patterns
{
    meta:
        description = "Detects Ryuk ransomware family"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1486/"
        mitre_attack = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        category = "ransomware"

    strings:
        $ryuk1 = "Ryuk" ascii fullword
        $ryuk2 = "RYKUK" ascii
        $ryuk3 = ".ryk" ascii
        $ryuk4 = "README_for_decryption.txt" ascii
        $ryuk5 = "RyukReadme" ascii
        $ryuk6 = "Global\\Ryuk" ascii
        $ryuk7 = "HERMES" ascii fullword

    condition:
        uint16(0) == 0x5A4D and (2 of ($ryuk*) or (1 of ($ryuk*) and $ryuk6))
}

/* ================================================
 * TROJAN DETECTION RULES
 * MITRE ATT&CK: T1071 - Application Layer Protocol
 * ================================================ */

rule Trojan_C2_Beacon
{
    meta:
        description = "Detects trojan C2 beacon communication patterns"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1071/"
        mitre_attack = "T1071 - Application Layer Protocol"
        severity = "high"
        category = "trojan"

    strings:
        $http1 = "HTTP/1.1" ascii
        $http2 = "GET /" ascii
        $http3 = "POST /" ascii
        $useragent1 = "Mozilla/5.0" ascii
        $useragent2 = "curl/" ascii
        $beacon1 = "/beacon" ascii
        $beacon2 = "/connect" ascii
        $beacon3 = "/callback" ascii
        $beacon4 = "/checkin" ascii
        $beacon5 = "/data" ascii
        $beacon6 = "cmd" ascii fullword
        $beacon7 = "exec" ascii fullword
        $beacon8 = "sleep" ascii fullword
        $beacon9 = "task" ascii fullword

    condition:
        uint16(0) == 0x5A4D and ((any of ($http*) and any of ($beacon*) and 2 of ($beacon*)) or (any of ($useragent*) and ($beacon1 or $beacon2 or $beacon3 or $beacon4)))
}

rule Trojan_Persistence
{
    meta:
        description = "Detects trojan persistence mechanisms"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1547/"
        mitre_attack = "T1547.001 - Boot or Logon Autostart"
        severity = "high"
        category = "trojan"

    strings:
        $persist1 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $persist2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $persist3 = "RunOnce" ascii fullword
        $persist4 = "Task Scheduler" ascii
        $persist5 = "schtasks" ascii fullword
        $persist6 = "Startup" ascii fullword
        $persist7 = "AppInit_DLLs" ascii
        $persist8 = "Services" ascii fullword
        $persist9 = "\\Windows\\System32\\" ascii
        $persist10 = "CurrentVersion\\Run" ascii
        $persist11 = "Microsoft\\Windows\\CurrentVersion" ascii
        $persist12 = "Software\\Microsoft" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($persist*)
}

rule Trojan_LateralMove
{
    meta:
        description = "Detects trojan lateral movement capabilities"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1021/"
        mitre_attack = "T1021 - Remote Services"
        severity = "high"
        category = "trojan"

    strings:
        $smb1 = "\\admin$" ascii
        $smb2 = "\\c$" ascii
        $smb3 = "SMB" ascii
        $rm1 = "WMI" ascii fullword
        $rm2 = "Win32_Process" ascii
        $rm3 = "PsExec" ascii
        $rm4 = "psexec" ascii fullword
        $rm5 = "Service" ascii fullword
        $rm6 = "CreateService" ascii
        $rm7 = "RemoteDesktop" ascii
        $rm8 = "RDP" ascii fullword
        $rm9 = "TerminalServer" ascii
        $rm10 = "WTSQuerySessionInformation" ascii

    condition:
        uint16(0) == 0x5A4D and ((1 of ($smb*) and 1 of ($rm*)) or 2 of ($rm*))
}

rule Trojan_RegistryMod
{
    meta:
        description = "Detects trojan registry modification"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1547/"
        mitre_attack = "T1547.001 - Boot or Logon Autostart"
        severity = "high"
        category = "trojan"

    strings:
        $api1 = "RegCreateKeyExW" ascii
        $api2 = "RegSetValueExW" ascii
        $api3 = "RegOpenKeyExW" ascii
        $api4 = "RegDeleteKeyW" ascii
        $api5 = "RegDeleteValueW" ascii
        $api6 = "RegQueryValueExW" ascii
        $key1 = "CurrentVersion\\Run" ascii
        $key2 = "Software\\Microsoft\\Windows" ascii
        $key3 = "UserInit" ascii
        $key4 = "Shell" ascii fullword
        $key5 = "Security" ascii fullword

    condition:
        uint16(0) == 0x5A4D and ((2 of ($api*) and 1 of ($key*)) or (1 of ($api*) and 2 of ($key*)))
}

rule Trojan_ScreenshotCapture
{
    meta:
        description = "Detects trojan screenshot capture capabilities"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1056/"
        mitre_attack = "T1056 - Input Capture"
        severity = "medium"
        category = "trojan"

    strings:
        $api1 = "BitBlt" ascii fullword
        $api2 = "GetDC" ascii fullword
        $api3 = "CreateCompatibleDC" ascii
        $api4 = "CreateCompatibleBitmap" ascii
        $api5 = "StretchBlt" ascii fullword
        $api6 = "GetSystemMetrics" ascii
        $api7 = "CreateDIBSection" ascii
        $api8 = "SetWindowText" ascii
        $save1 = "SaveAs" ascii fullword
        $save2 = ".bmp" ascii
        $save3 = ".png" ascii
        $save4 = ".jpg" ascii

    condition:
        uint16(0) == 0x5A4D and (3 of ($api*) and 1 of ($save*))
}

/* ================================================
 * BACKDOOR DETECTION RULES
 * MITRE ATT&CK: T1059 - Command and Scripting Interpreter
 * ================================================ */

rule Backdoor_ReverseShell
{
    meta:
        description = "Detects reverse shell backdoors"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1059/"
        mitre_attack = "T1059 - Command and Scripting Interpreter"
        severity = "critical"
        category = "backdoor"

    strings:
        $socket1 = "socket" ascii fullword
        $socket2 = "SOCK_STREAM" ascii
        $socket3 = "AF_INET" ascii
        $socket4 = "connect(" ascii
        $socket5 = "bind(" ascii
        $socket6 = "listen(" ascii
        $socket7 = "accept(" ascii
        $socket8 = "recv(" ascii
        $socket9 = "send(" ascii
        $socket10 = "getsockopt" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $shell3 = "cmd.exe" ascii
        $shell4 = "powershell" ascii fullword
        $shell5 = "system(" ascii
        $shell6 = "exec(" ascii
        $shell7 = "dup2" ascii fullword
        $shell8 = "dup(" ascii
        $shell9 = "execl" ascii fullword
        $python = "pty.spawn" ascii

    condition:
        (uint16(0) == 0x5A4D and 2 of ($socket*) and 2 of ($shell*)) or (2 of ($socket*) and ($shell1 or $shell2 or $shell3)) or ($python and 2 of ($socket*))
}

rule Backdoor_SSH
{
    meta:
        description = "Detects SSH backdoors"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1059/"
        mitre_attack = "T1059.004 - Unix Shell"
        severity = "high"
        category = "backdoor"

    strings:
        $ssh1 = "SSH-2.0-OpenSSH" ascii fullword
        $ssh2 = "sshd" ascii fullword
        $ssh3 = "/etc/ssh" ascii
        $ssh4 = "/root/.ssh" ascii
        $ssh5 = "authorized_keys" ascii fullword
        $ssh6 = ".ssh" ascii fullword
        $ssh7 = "ssh-" ascii
        $ssh8 = "scp" ascii fullword

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and (2 of ($ssh*) and ($ssh1 or $ssh2))
}

rule Backdoor_CronJob
{
    meta:
        description = "Detects cron job backdoors"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1053/"
        mitre_attack = "T1053.003 - Cron"
        severity = "high"
        category = "backdoor"

    strings:
        $cron1 = "/etc/cron" ascii
        $cron2 = "/var/spool/cron" ascii
        $cron3 = "crontab" ascii fullword
        $cron4 = "cron.d" ascii
        $cron5 = "cron.daily" ascii
        $cron6 = "@reboot" ascii fullword
        $cron7 = "* * * * *" ascii
        $cron8 = "CRON" ascii fullword
        $cron9 = "/bin/sh" ascii

    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and (2 of ($cron*) or 1 of ($cron*) and $cron7)
}

rule Backdoor_Systemd
{
    meta:
        description = "Detects systemd service backdoors"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1543/"
        mitre_attack = "T1543.002 - Systemd Service"
        severity = "high"
        category = "backdoor"

    strings:
        $systemd1 = "[Unit]" ascii
        $systemd2 = "[Service]" ascii
        $systemd3 = "[Install]" ascii
        $systemd4 = "ExecStart=" ascii
        $systemd5 = "WantedBy=" ascii
        $systemd6 = "/etc/systemd/system" ascii
        $systemd7 = "/lib/systemd/system" ascii
        $systemd8 = "systemctl" ascii fullword
        $systemd9 = ".service" ascii fullword
        $systemd10 = "daemon-reload" ascii

    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and (3 of ($systemd*) and ($systemd1 or $systemd2 or $systemd3))
}

/* ================================================
 * WEBSHELL DETECTION RULES
 * MITRE ATT&CK: T1505.003 - Web Shell
 * ================================================ */

rule Webshell_PHP
{
    meta:
        description = "Detects PHP web shells"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        mitre_attack = "T1505.003 - Web Shell"
        severity = "critical"
        category = "webshell"

    strings:
        $php1 = "<?php" ascii
        $php2 = "sys_get_temp_dir" ascii
        $php3 = "system(" ascii
        $php4 = "shell_exec(" ascii
        $php5 = "passthru(" ascii
        $php6 = "exec(" ascii
        $php7 = "popen(" ascii
        $php8 = "proc_open(" ascii
        $php9 = "assert(" ascii
        $php10 = "base64_decode(" ascii
        $php11 = "eval(" ascii
        $php12 = "call_user_func" ascii
        $php13 = "create_function" ascii
        $php14 = "register_shutdown_function" ascii
        $php15 = "move_uploaded_file" ascii
        $php16 = "file_put_contents" ascii
        $php17 = "$_GET" ascii
        $php18 = "$_POST" ascii
        $php19 = "$_REQUEST" ascii
        $php20 = "$_COOKIE" ascii

    condition:
        $php1 and (2 of ($php3,$php4,$php5,$php6,$php7,$php8,$php9,$php10,$php11,$php12,$php13,$php14,$php15,$php16) or (1 of ($php3,$php4,$php5,$php6,$php7,$php8,$php9,$php10,$php11,$php12,$php13,$php14,$php15,$php16) and 2 of ($php17,$php18,$php19,$php20)) or $php2)
}

rule Webshell_ASP
{
    meta:
        description = "Detects ASP/ASP.NET web shells"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        mitre_attack = "T1505.003 - Web Shell"
        severity = "critical"
        category = "webshell"

    strings:
        $asp1 = "<%" ascii
        $asp2 = "Response.Write" ascii
        $asp3 = "Server.CreateObject" ascii
        $asp4 = "Execute" ascii fullword
        $asp5 = "cmd.exe" ascii
        $asp6 = "powershell" ascii fullword
        $asp7 = "Shell.Application" ascii
        $asp8 = "WScript.Shell" ascii
        $asp9 = "ScriptControl" ascii
        $asp10 = "Request" ascii fullword
        $asp11 = "Form" ascii fullword

    condition:
        $asp1 and ((2 of ($asp2,$asp3,$asp4,$asp5,$asp6,$asp7,$asp8,$asp9)) or (1 of ($asp2,$asp3,$asp4,$asp5,$asp6,$asp7,$asp8,$asp9) and $asp10 and $asp11))
}

rule Webshell_JSP
{
    meta:
        description = "Detects JSP web shells"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        mitre_attack = "T1505.003 - Web Shell"
        severity = "critical"
        category = "webshell"

    strings:
        $jsp1 = "<%" ascii
        $jsp2 = "Runtime.getRuntime()" ascii
        $jsp3 = "exec(" ascii
        $jsp4 = "ProcessBuilder" ascii
        $jsp5 = "getRuntime" ascii
        $jsp6 = "java.lang.Runtime" ascii
        $jsp7 = "request.getParameter" ascii
        $jsp8 = "PrintWriter" ascii
        $jsp9 = "outputStream" ascii
        $jsp10 = "getParameter" ascii
        $jsp11 = "cmd" ascii fullword

    condition:
        $jsp1 and (($jsp2 or $jsp5 or $jsp6 or $jsp7 or $jsp10) and (($jsp3 or $jsp4) or ($jsp8 and $jsp9) or $jsp11 or $jsp7))
}

/* ================================================
 * CRYPTOMINER DETECTION RULES
 * MITRE ATT&CK: T1496 - Resource Hijacking
 * ================================================ */

rule Cryptominer_XMR
{
    meta:
        description = "Detects XMRig cryptominer"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1496/"
        mitre_attack = "T1496 - Resource Hijacking"
        severity = "medium"
        category = "cryptominer"

    strings:
        $xmrig1 = "xmrig" ascii fullword
        $xmrig2 = "XMRig" ascii fullword
        $monero1 = "monero" ascii fullword
        $monero2 = "cryptonight" ascii fullword
        $monero3 = "Cryptonight" ascii fullword
        $monero4 = "kawpow" ascii fullword
        $monero5 = "rx/" ascii
        $pool1 = "pool" ascii fullword
        $pool2 = "mine" ascii fullword
        private $donate = "donate" ascii fullword

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and (2 of ($xmrig*) or (1 of ($monero*) and $pool1) or ($monero2 and $pool2) or ($donate and ($pool1 or $pool2)))
}

rule Cryptominer_PoolConnection
{
    meta:
        description = "Detects cryptominer pool connections"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1496/"
        mitre_attack = "T1496 - Resource Hijacking"
        severity = "medium"
        category = "cryptominer"

    strings:
        $pool1 = "pool.minexmr" ascii
        $pool2 = "pool.supportxmr" ascii
        $pool3 = "xmrpool" ascii
        $pool4 = "stratum" ascii fullword
        $pool5 = "stratum+tcp" ascii
        $pool6 = "stratum+ssl" ascii
        $pool7 = "ethpool" ascii
        $pool8 = "ethermine" ascii
        $pool9 = "nimiq" ascii fullword
        $pool10 = "nicehash" ascii fullword
        $pool11 = "miningpoolhub" ascii
        $pool12 = "googledrive" ascii fullword

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and (1 of ($pool*) or ($pool4 and 1 of ($pool1,$pool2,$pool3,$pool4,$pool5,$pool6,$pool7,$pool8,$pool9,$pool10,$pool11)))
}

rule Cryptominer_HighCPU
{
    meta:
        description = "Detects cryptominer high CPU usage patterns"
        author = "Threat Detection System"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1496/"
        mitre_attack = "T1496 - Resource Hijacking"
        severity = "low"
        category = "cryptominer"

    strings:
        $cpu1 = "GetProcessTimes" ascii
        $cpu2 = "GetSystemTimes" ascii
        $cpu3 = "GetThreadTimes" ascii
        $cpu4 = "QueryPerformanceCounter" ascii
        $cpu5 = "QueryPerformanceFrequency" ascii
        $cpu6 = "RDTSC" ascii
        $cpu7 = "rdtsc" ascii fullword
        $cpu8 = "GetCurrentProcess" ascii
        $cpu9 = "SetProcessPriorityBoost" ascii
        $cpu10 = "SetThreadPriority" ascii
        $cpu11 = "SCHED_FIFO" ascii
        $cpu12 = "sched_setaffinity" ascii

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and (3 of ($cpu*))
}