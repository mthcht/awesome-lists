rule MonitoringTool_Win32_Actmon_7209_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Actmon"
        threat_id = "7209"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Actmon"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d e4 51 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 8d 4d e4 e8 ?? ?? ?? ?? 25 ff 00 00 00 85 c0 74 16 8b f4 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 68 dc 05 00 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? eb b2}  //weight: 1, accuracy: Low
        $x_1_2 = "wscript.exe boot.vbs" ascii //weight: 1
        $x_1_3 = {77 73 63 72 69 70 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Actmon_7209_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Actmon"
        threat_id = "7209"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Actmon"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 73 6b 72 6e 6c 61 64 2e 64 6c 6c 00 3f 48 6f 6f 6b 5f 53 65 74 32 40 40 59 41 48 48 48 40 5a 00 3f 48 6f 6f 6b 5f 53 65 74 40 40 59 41 48 48 48 40 5a 00 3f 48 6f 6f 6b 5f 53 74 61 72 74 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 61 72 74 5f 63 62 74 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 61 72 74 5f 67 65 74 6d 65 73 73 61 67 65 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 6f 70 40 40 59 41 48 58 5a 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 73 34 5f 5f 00 00 00 73 79 73 33 30 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Actmon_7209_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Actmon"
        threat_id = "7209"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Actmon"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {77 73 6b 72 6e 6c 62 2e 64 6c 6c 00 5f 53 54 5f 48 6f 6f 6b 41 6c 6c 41 70 70 73 40 31 32 00 5f 53 54 5f 52 61 77 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 40 38 00 5f 53 54 5f 52 61 77 4c 6f 61 64 4c 69 62 72 61 72 79 41 40 34 00}  //weight: 5, accuracy: High
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "PSAPI.dll" ascii //weight: 1
        $x_1_7 = "RegisterServiceProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Actmon_7209_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Actmon"
        threat_id = "7209"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Actmon"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {77 73 6b 72 6e 6c 61 63 2e 64 6c 6c 00 3f 41 72 65 54 61 73 6b 4b 65 79 73 44 69 73 61 62 6c 65 64 40 40 59 41 48 58 5a 00 3f 47 65 74 48 4b 4c 40 40 59 41 50 41 55 48 4b 4c 5f 5f 40 40 58 5a 00 3f 49 6e 73 74 61 6c 6c 54 61 73 6b 4b 65 79 73 40 40 59 41 48 48 40 5a 00}  //weight: 5, accuracy: High
        $x_1_2 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_3 = {50 6f 6c 69 63 69 65 73 5c 43 6f 6d 64 6c 67 33 32 00 4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b 00 00 4e 6f 43 6c 6f 73 65 00 4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 00 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 00 00 52 65 73 74 72 69 63 74 52 75 6e 00 4e 6f 44 72 69 76 65 73 00 00 00 00 4e 6f 52 75 6e}  //weight: 1, accuracy: High
        $x_1_5 = "[open(\"%1\")]" ascii //weight: 1
        $x_1_6 = "%s\\shell\\printto\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Actmon_7209_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Actmon"
        threat_id = "7209"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Actmon"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wskrnl" ascii //weight: 1
        $x_1_2 = {5b 46 34 5d 00 00 00 00 5b 46 33 5d 00 00 00 00 5b 46 32 5d 00 00 00 00 5b 46 31 5d 00 00 00 00 5b 41 4c 54 5d 00 00 00 5b 4d 55 4c 54 49 50 4c 59 5d 00 00 5b 43 54 52 4c 5d}  //weight: 1, accuracy: High
        $x_1_3 = {45 6d 61 69 6c 54 6f 00 59 4f 55 52 2d 45 4d 41 49 4c 40 2d 48 45 52 45 2d 2e 43 4f 4d 00}  //weight: 1, accuracy: High
        $x_1_4 = "Logging engine stopped" ascii //weight: 1
        $x_1_5 = "PwdActMonHash" ascii //weight: 1
        $x_1_6 = {5c 5c 41 64 6d 69 6e 2d 50 43 5c [0-8] 52 65 70 6f 72 74 73 5c}  //weight: 1, accuracy: Low
        $x_1_7 = "<ActMonPro5@actmonpro.com>" ascii //weight: 1
        $x_1_8 = "Exiting StopProcess(\"explorer.exe\") with failure" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule MonitoringTool_Win32_Actmon_7209_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Actmon"
        threat_id = "7209"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Actmon"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 63 74 4d 6f 6e [0-22] 4d 6f 6e 69 74 6f 72}  //weight: 10, accuracy: Low
        $x_2_2 = {5b 46 34 5d 00 00 00 00 5b 46 33 5d 00 00 00 00 5b 46 32 5d 00 00 00 00 5b 46 31 5d 00 00 00 00 5b 41 4c 54 5d 00 00 00 5b 4d 55 4c 54 49 50 4c 59 5d 00 00 5b 43 54 52 4c 5d}  //weight: 2, accuracy: High
        $x_1_3 = {45 6d 61 69 6c 54 6f 00 59 4f 55 52 2d 45 4d 41 49 4c 40 2d 48 45 52 45 2d 2e 43 4f 4d 00 00 00 31 30 30 34 31 30 30 00 53 65 6e 64 54 72 69 67 67 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "Logging engine stopped" ascii //weight: 1
        $x_1_5 = "\\\\Admin-PC\\ActMonReports\\" ascii //weight: 1
        $x_1_6 = "PwdActMonHash" ascii //weight: 1
        $x_2_7 = "<ActMonPro5@actmonpro.com>" ascii //weight: 2
        $x_1_8 = "Please report to support2@ActMon.com" ascii //weight: 1
        $x_1_9 = "CurrentControlSet\\Control\\Class\\{4D36E96B-E325-11CE-BFC1-08002BE10318}" ascii //weight: 1
        $x_1_10 = "\\\\Admin-PC\\StarrReports\\" ascii //weight: 1
        $x_1_11 = {5c 53 68 61 72 65 64 00 47 6c 6f 62 61 6c 5c 00 3c 44 4f 43 3e 00 00 00 3c 41 50 50 3e 00 00 00 3c 45 58 45 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

