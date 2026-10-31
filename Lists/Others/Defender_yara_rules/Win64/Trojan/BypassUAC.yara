rule Trojan_Win64_BypassUAC_NE_2147920713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.NE!MTB"
        threat_id = "2147920713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "System\\CurrentControlSet\\Control\\Nls\\Calendars\\Japanese\\Era" ascii //weight: 2
        $x_2_2 = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.ex" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Ru" ascii //weight: 2
        $x_1_4 = "C:\\windows\\tem" ascii //weight: 1
        $x_1_5 = "$disable uac" ascii //weight: 1
        $x_1_6 = "$disable regedit" ascii //weight: 1
        $x_1_7 = "hentai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_NE_2147920713_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.NE!MTB"
        threat_id = "2147920713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 73 00 6f 00 75 00 72 00 63 00 65 00 5c 00 72 00 65 00 70 00 6f 00 73 00 5c 00 [0-80] 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-80] 2e 00 70 00 64 00 62 00}  //weight: 3, accuracy: Low
        $x_3_2 = {43 3a 5c 55 73 65 72 73 5c [0-32] 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c [0-80] 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c [0-80] 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_1_3 = "ettings\\Shell\\Open\\command" ascii //weight: 1
        $x_1_4 = "ateExecute" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\System32\\fod" ascii //weight: 1
        $x_1_6 = "cmd.exe /c start C:\\Windows\\System32\\cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BypassUAC_SX_2147956728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.SX!MTB"
        threat_id = "2147956728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botkiller" ascii //weight: 1
        $x_1_2 = "del /f /s /q" ascii //weight: 1
        $x_1_3 = "shutdown /r /f" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_5 = "schtasks /create /tn \"Microsoft\\Windows\\UpdateOrchestrator\\SecurityUpdate\" /tr \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_MK_2147961849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.MK!MTB"
        threat_id = "2147961849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8d 7c 24 38 4c 89 74 24 30 8b f0 4c 8d 05 c9 43 00 00 33 c0 b9 30}  //weight: 20, accuracy: High
        $x_15_2 = {4c 8b c3 66 c7 44 46 30 5c 00 48 8d 4e 32 48 8d 0c 41 ba 08 02 00 00 33 c0 66 89 01 48 2b cf 48 d1 f9}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_MK_2147961849_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.MK!MTB"
        threat_id = "2147961849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "85"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Injection successful:" ascii //weight: 10
        $x_20_2 = "botkiller_scan" ascii //weight: 20
        $x_15_3 = "Form Grabber started" ascii //weight: 15
        $x_20_4 = "CommandLineEventConsumer.Name=\"BotnetConsumer_" ascii //weight: 20
        $x_10_5 = "persistence" ascii //weight: 10
        $x_10_6 = "Process hidden:" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_GVB_2147972392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.GVB!MTB"
        threat_id = "2147972392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Re-run self as admin" ascii //weight: 1
        $x_1_2 = "Kill Defender" ascii //weight: 1
        $x_1_3 = "Windows Credential Vault" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\VMTools" ascii //weight: 1
        $x_1_5 = "powershell.exe -NoProfile -WindowStyle Hidden -Command \"Get-ItemProperty" ascii //weight: 1
        $x_1_6 = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii //weight: 1
        $x_1_7 = "powershell.exe -NoProfile -WindowStyle Hidden -Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct" ascii //weight: 1
        $x_1_8 = "powershell.exe -NoProfile -WindowStyle Hidden -Command \"Get-CimInstance Win32_StartupCommand" ascii //weight: 1
        $x_1_9 = "Remove-WmiObject -ErrorAction SilentlyContinue" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_11 = "download.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_MKA_2147974121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.MKA!MTB"
        threat_id = "2147974121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$d=$env:LOCALAPPDATA+'\\WinUpd';if(!(Test-Path $d)){md $d};$r=Get-ItemProperty $k;" wide //weight: 10
        $x_5_2 = "$nm=[Text.Encoding]::Unicode.GetString($fs);[IO.File]::WriteAllBytes($d+'\\'+$nm,$b)};" wide //weight: 5
        $x_3_3 = "Start-Process ($d+'\\'+[Text.Encoding]::Unicode.GetString((1..$r.HF.Length|%{$r.HF[$_-1] -bxor $x})))" wide //weight: 3
        $x_2_4 = "powershell.exe -ep bypass -w hidden -c \"$k='HKCU:\\Software\\Classes\\CLSID}\\Instance'" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_MKB_2147975270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.MKB!MTB"
        threat_id = "2147975270"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[TRIGGER] Launching UAC bypass triggers..." wide //weight: 10
        $x_5_2 = "[INFO] Already admin or UAC disabled - running payload directly (no UAC bypass needed)" wide //weight: 5
        $x_3_3 = "[INFO] Starting scheduled task (pattern: *NodeRemote*)..." wide //weight: 3
        $x_2_4 = "[SUCCESS] Payload ready at:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_A_2147977633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.A!MTB"
        threat_id = "2147977633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "=== PHASE 3 STEALTH INJECTION ENGINE ===" ascii //weight: 10
        $x_5_2 = "Global\\WndSvcHostMtx_v2" ascii //weight: 5
        $x_3_3 = "Shellcode thread executed." ascii //weight: 3
        $x_2_4 = "VirtualAlloc for shellcode failed." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_PAHM_2147977724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.PAHM!MTB"
        threat_id = "2147977724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System restore disabled" ascii //weight: 1
        $x_1_2 = "Boot recovery removed" ascii //weight: 1
        $x_2_3 = "DiscordRAT" wide //weight: 2
        $x_2_4 = "BotMain: elevated" ascii //weight: 2
        $x_1_5 = "keylog start|stop|dump" ascii //weight: 1
        $x_1_6 = "disableuac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BypassUAC_BA_2147978107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.BA!MTB"
        threat_id = "2147978107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all UAC bypass methods failedUAC bypass triggered" ascii //weight: 1
        $x_1_2 = "UAC bypass method failed, trying next" ascii //weight: 1
        $x_1_3 = "password" ascii //weight: 1
        $x_1_4 = ".cmd" ascii //weight: 1
        $x_2_5 = "@echo off" ascii //weight: 2
        $x_1_6 = "ping -n 4 127.0.0.1 >nul" ascii //weight: 1
        $x_1_7 = "del /f /q \"%~f0\" >nul 2>&1" ascii //weight: 1
        $x_1_8 = "Invoke-WebRequest -Uri $NefConURL -OutFile $nefZip -UseBasicParsing" ascii //weight: 1
        $x_1_9 = "$sidecarDir = Join-Path $env:ProgramData \"Monitorador\\Agent\\tools" ascii //weight: 1
        $x_1_10 = "set SCRIPT=%~dp0vdd-ctl.ps1" ascii //weight: 1
        $x_1_11 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\" %*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_UN_2147979615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.UN!MTB"
        threat_id = "2147979615"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\QGBoxHyperVRepair\\Release\\QGBoxHyperVRepair.pdb" ascii //weight: 2
        $x_1_2 = "%s\\curl.exe\" -L -s -o \"%s" ascii //weight: 1
        $x_1_3 = "bitsadmin.exe\" /transfer myJob_%u /download /priority foreground" ascii //weight: 1
        $x_1_4 = "AVIRA.SPOTLIGHT.SERVICE" ascii //weight: 1
        $x_1_5 = "AVASTBROWSERUPDATE" ascii //weight: 1
        $x_1_6 = "K7TSECURITY" ascii //weight: 1
        $x_1_7 = "Outlook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_PN_2147979800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.PN!MTB"
        threat_id = "2147979800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\vmware-vdiskmanager\\Release\\vmware-vdiskmanager.pdb" ascii //weight: 2
        $x_1_2 = "%s\\curl.exe\" -L -s -o \"%s" ascii //weight: 1
        $x_1_3 = "CIM_VirtualSystemSettingData" ascii //weight: 1
        $x_1_4 = "370E819D5FDCBCBD3748F9EC1C097938" ascii //weight: 1
        $x_1_5 = "certutil.exe\" -urlcache -split -f" ascii //weight: 1
        $x_1_6 = "bitsadmin.exe\" /transfer myJob_%u /download /priority foreground" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BypassUAC_AB_2147980398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BypassUAC.AB!MTB"
        threat_id = "2147980398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UACME method 41 - Elevated COM interface" ascii //weight: 1
        $x_1_2 = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" ascii //weight: 1
        $x_1_3 = "Elevation:Administrator!new" ascii //weight: 1
        $x_1_4 = "may already be hardened" ascii //weight: 1
        $x_1_5 = "Is the current process already elevated? Then this is not a bypass" ascii //weight: 1
        $x_1_6 = "On fully up-to-date Windows the vulnerable CMSTPLUA object" ascii //weight: 1
        $x_1_7 = "Target launched elevated" ascii //weight: 1
        $x_1_8 = "Masquerading as %%SystemRoot%%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

