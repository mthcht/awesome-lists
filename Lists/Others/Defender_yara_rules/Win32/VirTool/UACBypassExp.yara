rule VirTool_Win32_UACBypassExp_A_2147752130_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = " /i:../../../" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_UACBypassExp_A_2147752130_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = " -w hidden " wide //weight: 1
        $x_1_3 = {49 00 65 00 78 00 [0-96] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_UACBypassExp_A_2147752130_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "-MpPreference " wide //weight: 1
        $x_1_3 = " -DisableRealtimeMonitoring 1" wide //weight: 1
        $x_1_4 = " -ExclusionProcess" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_UACBypassExp_A_2147752130_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "WMIC" wide //weight: 1
        $x_1_3 = "/Namespace:\\\\root\\Microsoft\\Windows\\Defender class MSFT_MpPreference" wide //weight: 1
        $x_1_4 = "call Add ExclusionPath=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_UACBypassExp_A_2147752130_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-96] 72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 41 00 70 00 70 00 58 00 38 00 32 00 61 00 36 00 67 00 77 00 72 00 65 00 34 00 66 00 64 00 67 00 33 00 62 00 74 00 36 00 33 00 35 00 74 00 6e 00 35 00 63 00 74 00 71 00 6a 00 66 00 38 00 6d 00 73 00 64 00 64 00 32 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00}  //weight: 2, accuracy: Low
        $x_1_2 = " /d powershell.exe " wide //weight: 1
        $x_1_3 = " /t REG_SZ " wide //weight: 1
        $x_1_4 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_UACBypassExp_A_2147752130_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-96] 72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 41 00 70 00 70 00 58 00 38 00 32 00 61 00 36 00 67 00 77 00 72 00 65 00 34 00 66 00 64 00 67 00 33 00 62 00 74 00 36 00 33 00 35 00 74 00 6e 00 35 00 63 00 74 00 71 00 6a 00 66 00 38 00 6d 00 73 00 64 00 64 00 32 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00}  //weight: 2, accuracy: Low
        $x_1_2 = " /d C:\\Windows\\system32\\cmd.exe /c start " wide //weight: 1
        $x_1_3 = " /t REG_SZ " wide //weight: 1
        $x_1_4 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_UACBypassExp_A_2147761343_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!A"
        threat_id = "2147761343"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $n_100_2 = "\\Windows\\" wide //weight: -100
        $n_100_3 = "\\Program Files" wide //weight: -100
        $n_100_4 = "\\Windows Defender" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_UACBypassExp_B_2147837947_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!B"
        threat_id = "2147837947"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 00 72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {5c 00 70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {5c 00 70 00 77 00 73 00 68 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 20 00 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 20 00}  //weight: 1, accuracy: Low
        $n_10_16 = "ddbf9b05-fcb0-4fce-949e-a6ae899ab273" wide //weight: -10
        $n_10_17 = "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\" wide //weight: -10
        $n_10_18 = "C:\\Program Files" wide //weight: -10
        $n_10_19 = "C:\\WINDOWS\\ccmcache\\" wide //weight: -10
        $n_10_20 = "C:\\WINDOWS\\CCM\\" wide //weight: -10
        $n_10_21 = "\\SysVol\\" wide //weight: -10
        $n_10_22 = "\\netlogon\\" wide //weight: -10
        $n_10_23 = "\\WindowsDefenderATPOnboardingScript" wide //weight: -10
        $n_10_24 = " -Noninteractive " wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule VirTool_Win32_UACBypassExp_C_2147838063_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!C"
        threat_id = "2147838063"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 00 72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {5c 00 70 00 77 00 73 00 68 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 20 00 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 20 00}  //weight: 1, accuracy: Low
        $n_10_13 = "6ab33e61-41c3-4b70-b64d-9a1d1b48abbc" wide //weight: -10
        $n_10_14 = "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\" wide //weight: -10
        $n_10_15 = "C:\\Program Files" wide //weight: -10
        $n_10_16 = "C:\\WINDOWS\\ccmcache\\" wide //weight: -10
        $n_10_17 = "C:\\WINDOWS\\CCM\\" wide //weight: -10
        $n_10_18 = "\\SysVol\\" wide //weight: -10
        $n_10_19 = "\\netlogon\\" wide //weight: -10
        $n_10_20 = "\\WindowsDefenderATPOnboardingScript" wide //weight: -10
        $n_10_21 = " -Noninteractive " wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule VirTool_Win32_UACBypassExp_D_2147852914_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!D"
        threat_id = "2147852914"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "-MpPreference -Exclusion" wide //weight: 1
        $x_1_7 = " vbscript:Execute(" wide //weight: 1
        $x_1_8 = "C:\\Users\\public\\" wide //weight: 1
        $x_1_9 = "\\AppData\\Roaming\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_UACBypassExp_D_2147852914_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!D"
        threat_id = "2147852914"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "-MpPreference -Exclusion" wide //weight: 1
        $x_1_5 = " vbscript:Execute(" wide //weight: 1
        $x_1_6 = "];iex($" wide //weight: 1
        $x_1_7 = "ConsentPromptBehaviorAdmin -Value 0" wide //weight: 1
        $x_1_8 = {20 00 2f 00 76 00 20 00 2f 00 63 00 20 00 [0-8] 73 00 65 00 74 00 20 00 [0-8] 3d 00}  //weight: 1, accuracy: Low
        $x_1_9 = ").DownloadString(" wide //weight: 1
        $x_1_10 = {63 00 75 00 72 00 6c 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_11 = "C:\\Users\\public\\" wide //weight: 1
        $x_1_12 = "\\AppData\\Roaming\\" wide //weight: 1
        $x_1_13 = {20 00 2d 00 65 00 20 00 22 80 80 0b 30 2d 39 41 2d 5a 61 2d 7a 2f 2b}  //weight: 1, accuracy: Low
        $x_1_14 = {20 00 2d 00 65 00 6e 00 20 00 22 80 80 0b 30 2d 39 41 2d 5a 61 2d 7a 2f 2b}  //weight: 1, accuracy: Low
        $x_1_15 = {20 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 65 00 64 00 20 00 22 80 80 0b 30 2d 39 41 2d 5a 61 2d 7a 2f 2b}  //weight: 1, accuracy: Low
        $x_1_16 = "=[Ref].Assembly.GetType($((" wide //weight: 1
        $x_1_17 = " -ExclusionProcess powershell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_UACBypassExp_E_2147893801_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!E"
        threat_id = "2147893801"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = ".py" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

