rule Trojan_Win32_GhostRAT_AA_2147745411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.AA!MTB"
        threat_id = "2147745411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 e4 be c6 45 e5 16 c6 45 e6 cf c6 45 e7 52 c6 45 e8 cd 90}  //weight: 1, accuracy: High
        $x_1_2 = {30 11 ff 45 ?? c3 1a 00 be 7c 44 00 00 0f be 04 02 99 f7 fe b8 ?? ?? ?? ?? 80 ea 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_MA_2147817603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.MA!MTB"
        threat_id = "2147817603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 0f b6 45 10 99 b9 ?? ?? ?? ?? 53 f7 f9 56 57 89 65 f0 80 c2 17 83 65 ec 00 88 55 13 8b 45 ec 3b 45 0c 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_MA_2147817603_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.MA!MTB"
        threat_id = "2147817603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 e4 f8 81 ec 5c 0b 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 58 0b 00 00 53 56 57 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15}  //weight: 5, accuracy: Low
        $x_2_2 = "\\jisupdf.exe" wide //weight: 2
        $x_2_3 = "RunOnlyOneInstance" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_MC_2147817604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.MC!MTB"
        threat_id = "2147817604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 f8 8b 0d ?? ?? ?? ?? 8b 55 f8 3b 91 fc 05 00 00 73 ?? 8b 45 f4 33 c9 8a 08 8b 55 fc 81 e2 ff 00 00 00 33 ca 8b 45 f4 88 08 8b 4d f4 83 c1 01 89 4d f4 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "SuspendThread" ascii //weight: 1
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_MB_2147819114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.MB!MTB"
        threat_id = "2147819114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FuckBaby.dll" ascii //weight: 2
        $x_2_2 = "windows\\temp\\svchost.exe" ascii //weight: 2
        $x_1_3 = {8d 4c 24 48 8d 54 24 10 51 68 3f 00 0f 00 6a 00 52 68 02 00 00 80 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_BS_2147837840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.BS!MTB"
        threat_id = "2147837840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 40 89 45 08 c7 45 fc 01 00 00 00 b8 [0-4] c3 ff 45 e8 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "fuckyou" ascii //weight: 1
        $x_1_3 = "C:\\windowss64\\computer.exe" ascii //weight: 1
        $x_1_4 = "47.93.60.63:8000/exploror.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_A_2147891717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.A!MTB"
        threat_id = "2147891717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 8b 55 f4 31 d0 83 f0 ?? 89 c2 8b 45 ?? 05 20 ?? ?? ?? 88 10 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_B_2147896327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.B!MTB"
        threat_id = "2147896327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 4d 88 ff d6 80 65 0b 00 ff 15 ?? 21 40 00 99 b9 00 01 00 00 68 00 28 00 00 f7 f9 8d 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_C_2147896771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.C!MTB"
        threat_id = "2147896771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 5f 5e 8b e5 5d ?? 8a 04 39 2c ?? 34 ?? 88 04 39 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_D_2147899008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.D!MTB"
        threat_id = "2147899008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 08 81 e9 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 03 45 ?? 0f be 08 83 f1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_RHA_2147914342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.RHA!MTB"
        threat_id = "2147914342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BakOnlineAddr2:" ascii //weight: 1
        $x_1_2 = "BakOnlineAddr1:" ascii //weight: 1
        $x_1_3 = "OnlineAddr:" ascii //weight: 1
        $x_1_4 = "NoConnectDelayTime:" ascii //weight: 1
        $x_1_5 = {75 70 64 61 74 65 2e 64 6c 6c 00 58 00}  //weight: 1, accuracy: High
        $x_1_6 = "taskmgr.exe" ascii //weight: 1
        $x_1_7 = "api.microsoft-ns1.com" ascii //weight: 1
        $x_1_8 = "CreateMutexA" ascii //weight: 1
        $x_1_9 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_10 = "Abc159753@" wide //weight: 1
        $x_2_11 = {50 45 00 00 4c 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 06 00 00 c6 00 00 00 82 00 00 00 00 00 00 08 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_SPHF_2147935751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.SPHF!MTB"
        threat_id = "2147935751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "tasklist /FI \"IMAGENAME eq %ProcessName%\" | findstr /I \"%ProcessName%\" >nul" ascii //weight: 5
        $x_4_2 = "powershell -Command \"Set-ExecutionPolicy Unrestricted -Scope CurrentUser\"powershell -ExecutionPolicy Bypass -File" ascii //weight: 4
        $x_4_3 = "YXJ0T25EZW1hbmQ+dHJ1ZTwvQWxsb3dTdGFydE9uRGVtYW5kPgogICAgPEVuYWJsZWQ+dHJ1Z" ascii //weight: 4
        $x_2_4 = "C:\\Windows\\IiViS" ascii //weight: 2
        $x_1_5 = "backup.exe" ascii //weight: 1
        $x_1_6 = "copy /Y \"%BackupDLLPath%\" \"%DLLPath%\"" ascii //weight: 1
        $x_1_7 = "start \"\" \"%ProcessPath%\"" ascii //weight: 1
        $x_1_8 = "timeout /t 30 /nobreak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_ARAX_2147954631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.ARAX!MTB"
        threat_id = "2147954631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ":\\buildbot\\build1\\desktop_screen\\build\\bin\\active_desktop_launcher.pdb" ascii //weight: 3
        $x_3_2 = ":\\Program Files\\RandomFolder_" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRAT_SPVX_2147959671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRAT.SPVX!MTB"
        threat_id = "2147959671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SystemRoot%\\System32\\svchost.exe -k imgsvc" ascii //weight: 2
        $x_2_2 = "Msbfjs Gvturuxk Jkl" ascii //weight: 2
        $x_1_3 = "Vpkq\\Bixasnbwp.pic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

