rule Trojan_Win32_Hancitor_2147740851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor!MTB"
        threat_id = "2147740851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 0f 81 50 00 6a 40 eb [0-48] 8b 00 eb ff 00 b9 00 00 00 00 eb [0-80] b8 ?? ?? ?? ?? 71 [0-80] 30 07 e9 [0-160] 47 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_TW_2147741772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.TW!MTB"
        threat_id = "2147741772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 f4 81 c6 ?? ?? ?? ?? 8b 5d f4 81 c3 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? 00 00 89 c2 8b 45 f4 89 d1 ba 00 00 00 00 f7 f1 0f b6 92 ?? ?? ?? ?? 0f b6 03 28 d0 88 06 8d 45 f4 ff 00 eb ae b8 ?? ?? ?? ?? 83 c4 10 5b 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_PA_2147745870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.PA!MTB"
        threat_id = "2147745870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d 59 11 00 00 a3 ?? ?? ?? ?? [0-64] 8b 15 ?? ?? ?? ?? 81 c2 59 11 00 00 a1 ?? ?? ?? ?? 8b ca a0 01 31 0d ?? ?? ?? ?? [0-240] a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 5d c3}  //weight: 1, accuracy: Low
        $x_20_2 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 8a 10 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 8a 10 00 00 8b 45 08 89 10 8b e5 5d c3}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_CN_2147767536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.CN!MTB"
        threat_id = "2147767536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" ascii //weight: 5
        $x_5_2 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)" ascii //weight: 5
        $x_1_3 = "http://api.ipify.org" ascii //weight: 1
        $x_1_4 = "Rundll32.exe %s, start" ascii //weight: 1
        $x_1_5 = "WinHost32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GB_2147772814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GB!MTB"
        threat_id = "2147772814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 f0 0f b7 c3 83 c0 ?? 89 35 ?? ?? ?? ?? 03 45 ?? 8b fe 03 d0 8b 41 ?? 8b da 05 08 36 04 01 2b de 89 41 ?? 83 eb ?? a3 ?? ?? ?? ?? 83 6d ?? 01 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GB_2147772814_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GB!MTB"
        threat_id = "2147772814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 4d f8 ba ?? ?? ?? ?? c1 e2 ?? 3b 8a ?? ?? ?? ?? 75 ?? eb ?? 8b 45 f4 8b 0c 85 ?? ?? ?? ?? 03 4d 0c 8b 55 f4 89 0c 95 ?? ?? ?? ?? eb ?? 8b 75 ?? 81 c1 ?? ?? ?? ?? 83 c6 03 03 cb 83 ee 03 81 e9 ?? ?? ?? ?? ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GB_2147772814_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GB!MTB"
        threat_id = "2147772814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 c1 80 eb [0-1] 89 44 24 [0-1] 03 c6 8b 74 24 [0-1] 03 d0 0f b7 c2 02 da 89 44 24 [0-1] 8b 44 24 [0-1] 05 [0-4] 66 89 15 [0-4] 89 06 83 c6 04 83 6c 24 [0-1] 01 a3 [0-4] 8b 44 24 [0-1] 89 74 24 [0-1] 0f b7 f0 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GB_2147772814_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GB!MTB"
        threat_id = "2147772814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 00 88 87 ?? ?? ?? ?? 47 39 1d ?? ?? ?? ?? 77 ?? 0f b6 c1 8a cb 02 c9 a3 ?? ?? ?? ?? 8b 44 24 ?? 2a c8 80 c1 ?? 88 0d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_10_2 = {2a c2 2c 63 a2 ?? ?? ?? ?? 8b 07 05 ?? ?? ?? ?? 89 07 83 c7 04 a3 ?? ?? ?? ?? 8a c2 02 c0 04 ?? 02 05 ?? ?? ?? ?? 02 c1 83 6c 24 ?? 01 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GB_2147772814_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GB!MTB"
        threat_id = "2147772814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d ?? ?? ?? ?? 8b 4d 08 89 01 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {89 08 5b 5d c3 ff 00 33 [0-220] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hancitor_GC_2147772925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GC!MTB"
        threat_id = "2147772925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 08 0f b7 c1 ff 75 08 8d 94 00 ?? ?? ?? ?? a0 ?? ?? ?? ?? 66 0f b6 c8 66 2b d1 8b 0d ?? ?? ?? ?? 04 01 f6 e9 66 03 d1 0f b7 d2 a2 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GC_2147772925_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GC!MTB"
        threat_id = "2147772925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 45 fc eb ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 11 ?? a3 ?? ?? ?? ?? 0f b7 4d fc 0f af 0d ?? ?? ?? ?? 03 4d 0c 66 89 4d fc 8b 75 f4 41 83 c6 03 2b c8 83 ee 03 83 c1 71 ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GC_2147772925_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GC!MTB"
        threat_id = "2147772925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c6 8a f2 8a 54 24 ?? 2b c8 8b 06 2a d3 c0 e6 ?? 83 c1 ?? 2a f3 89 0d ?? ?? ?? ?? 80 c2 ?? 88 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? 0f b6 da 2b d9 89 06 33 c9 a3 ?? ?? ?? ?? 83 c3 ?? 89 0d ?? ?? ?? ?? 83 c6 04 ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GC_2147772925_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GC!MTB"
        threat_id = "2147772925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be ac 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d be ac 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {03 45 fc 88 1c 30 8b 4d f8 83 c1 01 89 4d f8 eb [0-15] 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-20] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_4 = {89 08 5f 5d c3 ff 00 04 01 01 01 01 31 32 30 33 [0-200] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hancitor_PC_2147772971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.PC!MTB"
        threat_id = "2147772971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "180"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "about_Remote_Jobs.</maml:para>" ascii //weight: 50
        $x_50_2 = "about_Jobs" ascii //weight: 50
        $x_50_3 = "Windows PowerShell" ascii //weight: 50
        $x_10_4 = "enable-computerrestore -drive" wide //weight: 10
        $x_10_5 = "Stop-Computer" wide //weight: 10
        $x_5_6 = "Receive-Job." wide //weight: 5
        $x_5_7 = "Connect" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GD_2147773021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GD!MTB"
        threat_id = "2147773021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 01 89 4d ?? 8b 15 ?? ?? ?? ?? 83 ea ?? 33 c0 2b 55 ?? 1b 45 ?? 89 55 ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GD_2147773021_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GD!MTB"
        threat_id = "2147773021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 81 c2 ?? ?? ?? ?? 57 8b 35 ?? ?? ?? ?? b0 ef 2a 05 ?? ?? ?? ?? 66 0f b6 c8 66 83 c1 ?? 66 89 0d ?? ?? ?? ?? 0f b7 c9 3b f1 72 ?? 28 1d ?? ?? ?? ?? 8d 4c 1e ?? 66 89 0d ?? ?? ?? ?? fe c0 b1 ?? f6 e9 a2 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GD_2147773021_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GD!MTB"
        threat_id = "2147773021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 00 88 86 ?? ?? ?? ?? 83 ef 01 83 c6 01 83 3d ?? ?? ?? ?? 04 75}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 37 02 c2 00 05 ?? ?? ?? ?? 81 fd ?? ?? ?? ?? a1 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 37 89 35 ?? ?? ?? ?? 8b f1 6b f6 ?? 8b d8 2b de 03 1d ?? ?? ?? ?? 83 c7 04 03 d3 83 6c 24 ?? 01 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GD_2147773021_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GD!MTB"
        threat_id = "2147773021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f8 03 55 f0 8b 45 fc 03 45 f8 8b 4d f4 8a 14 11 88 10 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 10, accuracy: High
        $x_10_2 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-18] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = {89 08 5f 5d c3 ff 00 04 01 01 01 01 31 32 30 33 [0-200] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
        $x_10_4 = {89 08 5b 5d c3 ff 00 04 01 01 01 01 31 32 30 33 [0-200] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hancitor_MX_2147773327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.MX!MTB"
        threat_id = "2147773327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 11 88 10 8b 45 f8 83 c0 01 89 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 33 d8 8b c3 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 06 00 8b 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_PH_2147773959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.PH!MTB"
        threat_id = "2147773959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 d8 8b 00 03 45 e8 03 d8 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 89 18 8b 45 c8 03 45 a8 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_MR_2147775131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.MR!MTB"
        threat_id = "2147775131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f2 8b 15 [0-4] 01 35 [0-4] 80 3d [0-5] 8d [0-6] 8b 37 ff 35 [0-4] 69 c0 [0-4] 51 6a 00 50 e8 [0-4] a3 [0-4] 81 [0-5] 89 [0-5] 89 [0-5] 89 37 8b [0-5] 8b [0-5] 8b c1 2b c3 48 48 83 c5 04 a3 [0-4] 81 [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GH_2147775536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GH!MTB"
        threat_id = "2147775536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c8 3b 0d ?? ?? ?? ?? 74 ?? 29 1e 8d 43 ?? 02 c2 66 8b d7 0f b6 c8 66 2b d1 a2 ?? ?? ?? ?? 66 83 ea ?? 0f b7 d2 83 ee ?? 81 fe ?? ?? ?? ?? 7f ?? 8b 44 24 ?? 8b 4c 24 ?? 85 ed 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GH_2147775536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GH!MTB"
        threat_id = "2147775536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 01 89 4d ?? 8b 15 ?? ?? ?? ?? 83 ea ?? 2b 15 ?? ?? ?? ?? 89 55 ?? c7 45 ?? 00 00 00 00 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b7 55 f4 a1 ?? ?? ?? ?? 8d 4c 02 ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 10 01 66 89 4d ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GE_2147776796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GE!MTB"
        threat_id = "2147776796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d1 66 89 55 ?? 8b 45 ?? 05 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b c1 03 45 ?? 03 45 ?? 89 45 ?? 8b 7d ?? ba ?? ?? ?? ?? 2b d0 ff d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GE_2147776796_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GE!MTB"
        threat_id = "2147776796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b3 7e f6 eb b3 3c 2a d8 3b fd 8a c3 75}  //weight: 10, accuracy: High
        $x_10_2 = {8b 3b 2b f1 83 ee ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ce 75 ?? 2b 2d ?? ?? ?? ?? 8d 51 ff 0f af ea 8d 54 01 ?? 0f b7 f2 0f b7 f6 81 c7 ?? ?? ?? ?? 8b d6 2b 15 ?? ?? ?? ?? 89 3b 83 c3 04 83 6c 24 ?? 01 89 3d ?? ?? ?? ?? 8d 4c 11 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GG_2147777946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GG!MTB"
        threat_id = "2147777946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MASSLoader.dll" ascii //weight: 10
        $x_1_2 = "\\System32\\svchost.exe" ascii //weight: 1
        $x_1_3 = "explorer.exe" ascii //weight: 1
        $x_1_4 = "Rundll32.exe %s, start" ascii //weight: 1
        $x_1_5 = "http://api.ipify.org" ascii //weight: 1
        $x_1_6 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hancitor_GT_2147777947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GT!MTB"
        threat_id = "2147777947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 ca 2b c8 83 c1 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 02 d2 2a d1 02 15 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? fe ca 89 3d ?? ?? ?? ?? 89 bc 2e ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 0f b6 ca 2b cb 83 c1 ?? 33 ff 83 c6 04 88 54 24 ?? 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GT_2147777947_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GT!MTB"
        threat_id = "2147777947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d0 66 89 55 ?? 0f b6 05 ?? ?? ?? ?? 8b 4d ?? 2b c8 03 4d ?? 88 0d ?? ?? ?? ?? 0f b7 55 ?? 03 15 ?? ?? ?? ?? 8b 45 ?? 8d 8c 10 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 8b 45 ?? 8d 8c 10 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? ff 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_AC_2147779431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.AC!MTB"
        threat_id = "2147779431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c7 3b c8 74 ?? 28 8e ?? ?? ?? ?? 8a da 8a 3d ?? ?? ?? ?? 02 d9 8d ?? ?? 0f b6 c3 8b ?? ?? ?? 2b c8 81 c2 ?? ?? ?? ?? 03 d1 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c7 3b c1 77 ?? 8a fb 8a c3 c0 e3 03 02 c3 88 3d ?? ?? ?? ?? 8a da 2a d8 0f b6 d3 2b d1 83 ea 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GN_2147779994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GN!MTB"
        threat_id = "2147779994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 52 03 c0 2b 45 ?? 2b 45 ?? 03 c2 0f b7 f0 6b c6 ?? 89 45 ?? 03 c1 0f b7 f8 0f b6 05 ?? ?? ?? ?? 83 c0 ?? a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GN_2147779994_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GN!MTB"
        threat_id = "2147779994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 45 fc 99 2b 05 ?? ?? ?? ?? 1b 15 ?? ?? ?? ?? 33 c9 03 45 ?? 13 d1 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 03 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? ff 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GM_2147779995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GM!MTB"
        threat_id = "2147779995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 44 11 ff 33 c9 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? 8a 08 88 0a 8b 55 ?? 83 c2 ?? 89 55 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 81 e9 ?? ?? ?? ?? 8b 55 ?? 83 da ?? 2b 0d ?? ?? ?? ?? 1b 15 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GO_2147780321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GO!MTB"
        threat_id = "2147780321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cb 2b ce 83 c2 ?? 0f af f3 03 d1 69 de ?? ?? ?? ?? 8b 4c 24 ?? 8d 72 ?? 8b 54 24 ?? 81 c1 ?? ?? ?? ?? 03 f0 89 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 89 0a 8b d7 8b 4c 24 ?? 2b d6 83 c1 04 83 ea ?? 83 6c 24 ?? 01 89 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GP_2147780450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GP!MTB"
        threat_id = "2147780450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b ca 89 0d ?? ?? ?? ?? ba ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 0f b6 0d ?? ?? ?? ?? 03 cf 02 c2 04 08 66 81 fb ?? ?? 8d ac 69 ?? ?? ?? ?? 8b 0e a2 ?? ?? ?? ?? 75 ?? 0f b7 05 ?? ?? ?? ?? 2b e8 81 c1 ?? ?? ?? ?? 8b c7 2b c2 89 0e 83 e8 ?? 83 c6 04 83 6c 24 ?? 01 89 0d ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GA_2147782468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GA!MTB"
        threat_id = "2147782468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 cb 80 e9 ?? 66 0f b6 c1 66 03 c6 66 05 ?? ?? 0f b7 d8 8b 07 05 ?? ?? ?? ?? 89 07 a3 ?? ?? ?? ?? b2 ?? 8a c3 f6 ea 8a 15 ?? ?? ?? ?? f6 da 2a d0 02 ca 83 c7 04 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GA_2147782468_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GA!MTB"
        threat_id = "2147782468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 2b d3 8b da 1b c7 8b f8 [0-25] 05 a8 31 04 01 a3 [0-4] 83 c6 ?? 89 02 8a 44 24 ?? 2a 44 24 ?? 2a c3 2c ?? 02 c8 8b c2 83 c0 04 83 6c 24 ?? 01 89 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_BMH_2147782965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.BMH!MTB"
        threat_id = "2147782965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 2a d3 c0 e6 02 83 c1 63 2a f3 89 0d ?? ?? ?? ?? 80 c2 48 88 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? 0f b6 da 2b d9 89 06 33 c9 a3 ?? ?? ?? ?? 83 c3 63 89 0d ?? ?? ?? ?? 83 c6 04 ff 4c 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GPU_2147782970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GPU!MTB"
        threat_id = "2147782970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3b 2b f1 83 ee 4a 81 3d ?? ?? ?? ?? f6 1a 00 00 8b ce 75 ?? 2b 2d ?? ?? ?? ?? 8d 51 ?? 0f af ea 8d 54 01 ?? 0f b7 f2 0f b7 f6 81 c7 dc af 0d 01 8b d6 2b 15 ?? ?? ?? ?? 89 3b 83 c3 04 83 6c 24 10 01 89 3d ?? ?? ?? ?? 8d 4c 11 50 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GPV_2147782971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GPV!MTB"
        threat_id = "2147782971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 38 01 15 ?? ?? ?? ?? 0f b6 c3 b2 06 f6 ea 02 c1 a2 ?? ?? ?? ?? b8 45 22 00 00 66 [0-6] 75 ?? 0f b6 c3 a3 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c8 8b 44 24 ?? 83 d5 00 83 44 24 ?? ?? 81 c7 34 48 0a 01 ff 4c 24 ?? 89 3d ?? ?? ?? ?? 89 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_FGQ_2147783085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.FGQ!MTB"
        threat_id = "2147783085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 39 8a c8 80 e9 3b 00 0d ?? ?? ?? ?? 81 7c 24 ?? ?? ?? ?? ?? 83 c5 33 33 c9 2b e8 1b ce 01 2d ?? ?? ?? ?? 0f b6 6c 24 12 11 0d ?? ?? ?? ?? 4d 0f af 2d ?? ?? ?? ?? 8b 4c 24 14 83 44 24 [0-2] 81 c7 20 77 00 01 89 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_FGS_2147783086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.FGS!MTB"
        threat_id = "2147783086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 69 c0 f2 b0 00 00 02 d9 80 eb 06 83 c5 04 81 fd a2 0d 00 00 8a d3 0f b7 c8 0f 82 1d 00 a1 ?? ?? ?? ?? 81 c7 1c d3 0d 01 89 3d ?? ?? ?? ?? 89 bc 28 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_FGR_2147783087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.FGR!MTB"
        threat_id = "2147783087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ea 83 ed 06 89 2d ?? ?? ?? ?? 8b 54 24 10 69 d2 f7 1e 00 00 2b ca 0f b7 c1 8b 0d ?? ?? ?? ?? 81 c7 20 1c 00 01 0f b7 d0 89 3d ?? ?? ?? ?? 89 bc 31 14 00 8b bc 37 ?? ?? ?? ?? a3 ?? ?? ?? ?? 72 ?? 29 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GRA_2147783164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GRA!MTB"
        threat_id = "2147783164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8b 45 [0-2] 8b 4d [0-2] 8b 55 [0-2] 31 db 89 ce 83 e6 03 75 [0-2] 8b 5d [0-1] 66 01 da 66 f7 da 6b d2 03 c1 ca 08 89 55 [0-1] 30 10 40 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_LLQ_2147783296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.LLQ!MTB"
        threat_id = "2147783296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 39 0f b7 ca 89 4c 24 [0-2] 8b 4c 24 [0-2] 8d 04 41 8b 4c 24 [0-2] 81 c1 ?? ?? ?? ?? 03 c8 83 3d ?? ?? ?? ?? ?? 74 ?? 0f af 0d ?? ?? ?? ?? 2b 4c 24 ?? 83 c1 1e 0f b7 c2 2b c6 81 c7 cc 4a 06 01 03 c1 89 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_VJ_2147783369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.VJ!MTB"
        threat_id = "2147783369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 db 2a 5c 24 1c 8b 4c 24 10 80 eb 2e 83 44 24 0c 04 81 c1 64 40 02 01 89 0f 02 da 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f b6 fb 83 c1 f8 03 cf 89 7c 24 10 33 ff 89 4c 24 1c 83 6c 24 18 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_VK_2147783370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.VK!MTB"
        threat_id = "2147783370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 03 75 [0-2] 8b 5d 10 66 01 da 66 f7 da 6b d2 03 c1 ca 07 89 55 10 30 10 40 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_WP_2147783371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.WP!MTB"
        threat_id = "2147783371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 c8 c8 03 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f8 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 33 66 ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_FWZ_2147783500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.FWZ!MTB"
        threat_id = "2147783500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 83 c3 04 [0-2] e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 29 00 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 [0-2] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GF_2147784087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GF!MTB"
        threat_id = "2147784087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 02 a1 [0-4] 83 d8 00 33 c9 2b 55 ?? 1b c1 89 15 [0-4] 8b 55 ?? 8b 45 ?? 8a 08 88 0a 8b 55 ?? 83 c2 ?? 89 55 ?? 8b 45 ?? 83 c0 ?? 89 45}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b7 55 fc 03 15 [0-4] 03 15 [0-4] 66 89 55 ?? a1 [0-4] 05 [0-4] a3 [0-4] 8b 0d [0-4] 03 4d ?? 8b 15 [0-4] 89 91 [0-4] a1 [0-4] 8b 0d [0-4] 8d 54 01 ?? 66 89 55 ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GI_2147786537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GI!MTB"
        threat_id = "2147786537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c8 03 0d [0-4] 89 35 [0-4] 01 0d [0-4] 8a cb 2a c8 a1 [0-4] 80 e9 ?? 3b 05 [0-4] 88 0d [0-4] 8b 4c 24 ?? 8d 14 1b 2b 15 [0-4] 81 c5 [0-4] 2b d7 89 29 83 c1 04 83 6c 24 ?? 01 8d 84 10 [0-4] 89 2d [0-4] a3 [0-4] 89 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GJ_2147786693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GJ!MTB"
        threat_id = "2147786693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce 2b cf 83 c1 ?? 01 3d [0-4] 11 2d [0-4] 8b ef 0f af ee 69 ed [0-4] 8b f5 89 35 [0-4] 81 c2 [0-4] 8b ef 2b eb 89 10 8d 4c 29 ?? 83 c0 04 83 6c 24 ?? 01 89 0d [0-4] 89 15 [0-4] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_GY_2147794131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.GY!MTB"
        threat_id = "2147794131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 e9 8b d3 2b d7 03 15 [0-4] 8b c5 2b c3 83 e8 ?? 8b fa 8b 16 3b 05 [0-4] 2b c1 03 05 [0-4] 81 c2 [0-4] 0f b7 c8 0f b7 c1 2b c7 89 16 83 c0 ?? 83 c6 ?? 83 6c 24 ?? 01 89 15 [0-4] a3 [0-4] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_DA_2147819978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.DA!MTB"
        threat_id = "2147819978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 e4 03 45 e8 8b 55 ec 31 02 83 45 e8 04 e8 ?? ?? ?? ?? 8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 5d ec 8b 45 e8 3b 45 e0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_EVK_2147821826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.EVK!MTB"
        threat_id = "2147821826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rASDFygsvTAFSrtwysgfwtyu" ascii //weight: 1
        $x_1_2 = {3f 1b c3 44 45 79 67 73 72 54 41 46 ac 8d 74 77 c1 73 67 66 77 74 79 75 40 72 41 53 44 46 79 67 73 76 54 41 46 53 72 74 77 79 73 67 66 77 74 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_ARA_2147847795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.ARA!MTB"
        threat_id = "2147847795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 ?? ?? ?? ?? 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hancitor_ARAX_2147929142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hancitor.ARAX!MTB"
        threat_id = "2147929142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 0f be 0c 10 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

