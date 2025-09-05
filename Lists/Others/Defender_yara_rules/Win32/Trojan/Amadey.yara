rule Trojan_Win32_Amadey_VC_2147759787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.VC!MTB"
        threat_id = "2147759787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 45 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GM_2147760184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GM!MTB"
        threat_id = "2147760184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 c7 05 [0-32] 01 05 [0-16] 8b ff 8b 15 [0-16] a1 [0-16] 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 55 ?? 03 32 8b 45 ?? 89 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MK_2147773014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MK!MTB"
        threat_id = "2147773014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d dc 0d 00 00 73 07 cc fa 40 fb cc eb f2}  //weight: 1, accuracy: High
        $x_1_2 = {73 07 cc fa 40 fb cc eb f2 05 00 3d ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Amadey_MK_2147773014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MK!MTB"
        threat_id = "2147773014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c6 c1 ?? 04 03 45 ?? 33 45 ?? 33 45 ?? 50 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_DA_2147775307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.DA!MTB"
        threat_id = "2147775307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 55 e1 8a c1 c0 ea 06 c0 e8 02 80 e1 03 88 45 e8 33 db 8a c5 c0 e1 04 c0 e8 04 80 e5 0f 02 c8 c0 e5 02 8d 47 01 88 4d e9 02 ea 89 45 e4 88 6d ea 85 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RT_2147777558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RT!MTB"
        threat_id = "2147777558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "anonymous namespace" ascii //weight: 1
        $x_1_2 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_3 = "GetNativeSystemInfo" ascii //weight: 1
        $x_10_4 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" ascii //weight: 10
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "GetComputerNameW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Amadey_A_2147787338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.A!MTB"
        threat_id = "2147787338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 4d f4 51 50 56 ff 75 f0 ff d3 8d 45 f8 50 ff 75 f8 56 57 ff 15 ?? ?? ?? ?? 85 c0 75 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_A_2147787338_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.A!MTB"
        threat_id = "2147787338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" ascii //weight: 1
        $x_1_2 = "Microsoft Internet Explorer" ascii //weight: 1
        $x_1_3 = "rundll32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ER_2147824157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ER!MTB"
        threat_id = "2147824157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 06 8d 4e 01 8b 7d e8 83 c6 02 8a}  //weight: 3, accuracy: High
        $x_2_2 = {0f b6 01 8b 4d e4 c0 e2 04 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AM_2147825958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AM!MTB"
        threat_id = "2147825958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 0f 43 4d 08 6a 00 6a 03 6a 00 6a 00 6a 50 51 50 89 45 9c ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AM_2147825958_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AM!MTB"
        threat_id = "2147825958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 85 c8 81 43 00 32 04 19 8b 4d f8 88 83 10 61 43 00 43 3b 5d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NEAA_2147835727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NEAA!MTB"
        threat_id = "2147835727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 d8 89 45 fc 33 45 e8 31 45 f8 8b 45 f0 89 45 e0 8b 45 f8 29 45 e0 8b 45 e0 89 45 f0 8b 45 c4 29 45 f4 ff 4d d4 0f 85 ?? ?? ?? ?? 8b 45 f0 5e 89 07 89 57 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MA_2147836228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MA!MTB"
        threat_id = "2147836228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CLIPPERDLL.dll" ascii //weight: 5
        $x_2_2 = "4CClipperDLL@@QAEAAV0@ABV0@@Z" ascii //weight: 2
        $x_2_3 = "??4CClipperDLL@@QAEAAV0@$$QAV0@@Z" ascii //weight: 2
        $x_1_4 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MA_2147836228_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MA!MTB"
        threat_id = "2147836228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" ascii //weight: 5
        $x_1_2 = {6a 40 68 00 30 00 00 ff 77 50 50 ff b5 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 0c 33 03 4e 3c 6a 00 ff b1 ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 03 c6 50 8b 81 ?? ?? ?? ?? 03 85 ?? fe ff ff 50 ff b5 ?? fe ff ff ff 15 ?? ?? ?? ?? 8b 8d ?? fe ff ff 8d 5b 28 0f b7 47 06 41 89 8d ?? fe ff ff 3b c8 7e b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAB_2147836542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAB!MTB"
        threat_id = "2147836542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 04 8b 00 eb 03 8b 45 cc 0f be 04 10 8b 04 81 83 f8 ff 74 5c c1 e7 06 03 f8 83 c3 06 78 46 8b cb 8b d7 d3 fa 8b 4e ?? 88 55 e0 3b 4e 14 73 1a 83 7e 14 10 8d 41 01 89 46 10 8b c6 72 02 8b 06 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NEAB_2147836725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NEAB!MTB"
        threat_id = "2147836725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 ea 03 45 d4 89 45 fc 8b 45 e8 03 55 d0 03 ?? 89 45 f0 8b 45 f0 31 45 fc 31 55 fc}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 fc 29 45 f8 81 45 e8 47 86 c8 61 ff 4d e0 0f 85 ?? fe ff ff 8b 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_WW_2147836737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.WW!MTB"
        threat_id = "2147836737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c3 c1 e0 04 03 45 ?? 33 45 ?? 33 45 ?? 50 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MZZ_2147836807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MZZ!MTB"
        threat_id = "2147836807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c7 c1 e0 ?? 03 45 ?? 33 45 ?? 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MYY_2147836899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MYY!MTB"
        threat_id = "2147836899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c6 c1 e0 ?? 03 45 ?? 8d 0c 32 33 c1 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MRR_2147836900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MRR!MTB"
        threat_id = "2147836900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAA_2147836969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAA!MTB"
        threat_id = "2147836969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6d 58 6a 73 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 33 c0 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AA_2147837045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AA!MTB"
        threat_id = "2147837045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {83 f8 10 b9 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f 43 ca 03 c1 3b f0 74 ?? 8b 45 ?? 8b 57 10 8a 0c 30 32 0e 88 4d f0 3b 57 14 73 ?? 83 7f 14 10 8d 42 01 89 47 10 8b c7 72 ?? 8b 07 88 0c 10 46 c6 44 10 01 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? eb}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BA_2147838099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BA!MTB"
        threat_id = "2147838099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 77 50 50 ff b5 a0 fe ff ff ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8d 0c 33 03 4e 3c 6a 00 ff b1 08 01 00 00 8b 81 0c 01 00 00 03 c6 50 8b 81 04 01 00 00 03 85 98 fe ff ff 50 ff b5 a0 fe ff ff ff 15 [0-4] 8b 8d 9c fe ff ff 8d 5b 28 0f b7 47 06 41 89 8d 9c fe ff ff 3b c8 7c}  //weight: 1, accuracy: Low
        $x_2_3 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AD_2147840101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AD!MTB"
        threat_id = "2147840101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 03 4d 94 88 4d ff 0f b6 55 ff f7 da 88 55 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AD_2147840101_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AD!MTB"
        threat_id = "2147840101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 33 d2 8b c1 f7 f6 83 c2 ?? 66 31 54 4d b8 41 83 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cb 5e 33 d2 8b c1 f7 f6 80 c2 ?? 30 54 0d 98 41 83 f9}  //weight: 1, accuracy: Low
        $x_1_3 = "%windir%\\system32\\rundll32.exe %programdata%\\updateTask.dll, Entry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GEE_2147840276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GEE!MTB"
        threat_id = "2147840276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 43 ca 03 c1 3b f0 0f 84 ?? ?? ?? ?? 8b 45 e8 8d 4d c4 6a ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8a 04 30 32 06 88 45 ef 8d 45 ef 50}  //weight: 10, accuracy: Low
        $x_1_2 = "Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MB_2147840326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MB!MTB"
        threat_id = "2147840326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c8 6a 01 6a 00 6a 03 6a 00 6a 00 8d 45 08 89 8d 94 fb ff ff 0f 43 45 08 6a 50 50 51 ff 15}  //weight: 5, accuracy: High
        $x_2_2 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MB_2147840326_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MB!MTB"
        threat_id = "2147840326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 60 cc 42 00 e8 c5 85 01 00 59 c3 cc cc cc cc 68 00 cc 42 00 e8 b5 85 01 00 59 c3 cc cc cc cc 6a 20 68 dc 53 43 00 b9 8c ab 43 00 e8}  //weight: 2, accuracy: High
        $x_2_2 = "Amadey.pdb" ascii //weight: 2
        $x_2_3 = "CreateMutexW" ascii //weight: 2
        $x_2_4 = "nbveek.exe" ascii //weight: 2
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAC_2147840360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAC!MTB"
        threat_id = "2147840360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 45 e4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 33 c3 31 45 08 8b 45 08 29 45 f8 8b 45 e0 29 45 fc ff 4d f4 8b 45 f8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BAI_2147841123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BAI!MTB"
        threat_id = "2147841123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 d1 09 c8 88 c1 8b 45 e4 88 08 8b 0d [0-4] a1 [0-4] 89 ca 81 ea [0-4] 83 ea 01 81 c2 [0-4] 0f af ca 83 e1 01 83 f9 00 0f 94 c3 83 f8 0a 0f 9c c6 88 d8 34 ff 88 f4 80 f4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MC_2147842503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MC!MTB"
        threat_id = "2147842503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {43 66 81 e3 a9 02 c1 c8 6e 66 c1 e9 73 66 03 f8 c1 c2 30 c1 c1 0b 23 c8 66 81 cf 36 02 43 66 be a8 01 66 c1 ca 46 f7 e6 81 ef c8 02 00 00 66 81 e2 5e 02 66 47 0f b6 c0 0f b7 ca 4f c1 e6 30 74}  //weight: 5, accuracy: High
        $x_5_2 = "_jbxjgbguyw3@4" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MC_2147842503_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MC!MTB"
        threat_id = "2147842503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 d0 c3 42 00 e8 35 7e 01 00 59 c3 cc cc cc cc 68 70 c3 42 00 e8 25 7e 01 00 59 c3 cc cc cc cc 6a 20 68 cc 53 43 00 b9 74 bb 43 00 e8}  //weight: 2, accuracy: High
        $x_2_2 = "Amadey.pdb" ascii //weight: 2
        $x_2_3 = "CreateMutexW" ascii //weight: 2
        $x_2_4 = {3a 5c 54 45 4d 50 5c [0-37] 5c 67 68 61 61 65 72 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RMV_2147842649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RMV!MTB"
        threat_id = "2147842649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 8b c2 c1 e8 ?? 03 c3 03 ca 89 44 24 ?? 33 c8 8b 44 24 ?? 33 c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 2b f0 8b 44 24 ?? 29 44 24 ?? 4f 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MOK_2147842733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MOK!MTB"
        threat_id = "2147842733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca c1 e1 ?? 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b c2 c1 e8 ?? 03 c3 8d 0c 17 33 c8 8b 44 24 ?? 33 c1 2b f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CAJ_2147842736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CAJ!MTB"
        threat_id = "2147842736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 85 e8 a2 43 00 32 04 31 8b 4d ec 88 86 ?? ?? ?? ?? 46 3b 75 e4 7c ?? 81 fe ?? ?? ?? ?? 0f}  //weight: 5, accuracy: Low
        $x_1_2 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_KHA_2147842952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.KHA!MTB"
        threat_id = "2147842952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 33 44 24 ?? 33 c8 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MYC_2147843848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MYC!MTB"
        threat_id = "2147843848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 50 8b c7 e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 8b f8 89 7c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RB_2147844060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RB!MTB"
        threat_id = "2147844060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 01 d0 88 08 8d 95 ec ?? fc ff 8b 45 f4 01 d0 0f b6 00 83 f0 49 89 c1 8d 95 ec ?? fc ff 8b 45 f4 01 d0 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RB_2147844060_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RB!MTB"
        threat_id = "2147844060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 ff b1 e0 00 00 00 8b 81 e4 00 00 00 03 c6 50 8b 81 dc 00 00 00 03 85 98 fe ff ff 50 ff b5 a0 fe ff ff ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {50 8d 85 b4 fe ff ff 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 8d 85 f8 fe ff ff 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_HRX_2147844096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.HRX!MTB"
        threat_id = "2147844096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 1c 37 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 6a ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 8d 4c 24 ?? 51 8d 54 24 ?? 52 8d 44 24 ?? 50 6a ?? ff 15 ?? ?? ?? ?? 31 5c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_HRY_2147844190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.HRY!MTB"
        threat_id = "2147844190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 ee ?? 03 f5 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 52 ff 15 ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 33 d2 8b 4c 24 ?? 33 ce 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PCS_2147844271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PCS!MTB"
        threat_id = "2147844271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 89 4c 24 ?? ff 15 ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 6a ?? 8d 4c 24 ?? 51 6a ?? 68 ?? ?? ?? ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 31 7c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CAQQ_2147844989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CAQQ!MTB"
        threat_id = "2147844989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 7c 24 10 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 28 29 44 24 18 ff 4c 24 20 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CAQT_2147845010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CAQT!MTB"
        threat_id = "2147845010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 7c 24 0c 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 1c 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GHP_2147845228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GHP!MTB"
        threat_id = "2147845228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 81 44 24 ?? 47 86 c8 61 33 c6 2b d8 83 6c 24 ?? ?? 89 44 24 ?? 89 5c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BAK_2147845267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BAK!MTB"
        threat_id = "2147845267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 4d f8 8d 4d d8 0f 43 cf 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 04 85 [0-4] 32 04 31 8b 4d f8 88 86 [0-4] 46 3b 75 f4 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NMJ_2147845280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NMJ!MTB"
        threat_id = "2147845280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 6c 24 10 89 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 8b f3 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 52 56 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 2b 7c 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 89 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BAH_2147845421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BAH!MTB"
        threat_id = "2147845421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e0 02 01 d0 c1 e0 03 89 c6 8b 45 08 8b 40 3c 89 c2 8b 45 08 01 c2 8b 45 08 8b 40 3c 89 c7 8b 45 08 01 f8 0f b7 40 14}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 08 8b 40 3c 89 c2 8b 45 08 01 d0 8b 40 50 c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 89 44 24 04 c7 04 24 00 00 00 00 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAD_2147845621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAD!MTB"
        threat_id = "2147845621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 8b 44 24 ?? 89 04 24 8b ?? 24 44 31 04 24 8b 04 24 8b 4c 24 ?? 89 01 83 c4 3c}  //weight: 1, accuracy: Low
        $x_1_2 = {01 44 24 18 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b c7 c1 e8 05 03 c5 51 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GHV_2147845818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GHV!MTB"
        threat_id = "2147845818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cf 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 8b 44 24 ?? 52 50 8d 4c 24 ?? 51 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_APR_2147845834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.APR!MTB"
        threat_id = "2147845834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cd 89 4c 24 ?? 8d 0c 07 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b ce c1 e9 ?? 03 cb 8d 14 37 31 54 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 14 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_TRE_2147845939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.TRE!MTB"
        threat_id = "2147845939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 0c 37 31 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GID_2147846291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GID!MTB"
        threat_id = "2147846291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 df ca 7c b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 44 24 ?? 11 d9 f7 09 81 44 24 ?? ae 7f 68 1a 81 44 24 ?? b6 a2 b2 20 81 44 24 ?? e5 a1 5a 02 81 44 24 ?? e8 c2 1a 07 b8 ?? ?? ?? ?? f7 a4 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 81 fe bd 08 bf 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_SPH_2147846382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.SPH!MTB"
        threat_id = "2147846382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OPmoQaBwMN72QeyQRu==" ascii //weight: 1
        $x_1_2 = "LRXIWMCQUfbDXPnvOK==" ascii //weight: 1
        $x_1_3 = "0YKS3NN3MyIfRr==" ascii //weight: 1
        $x_1_4 = "dY7a4OK4LhY14L==" ascii //weight: 1
        $x_1_5 = "KeCbO u0aR4igYLQNxy9BfNeOxTsBw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GIF_2147846465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GIF!MTB"
        threat_id = "2147846465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 d9 f7 09 81 44 24 ?? ae 7f 68 1a 81 44 24 ?? b6 a2 b2 20 81 44 24 ?? e5 a1 5a 02 81 84 24 ?? ?? ?? ?? e8 c2 1a 07 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 fe bd 08 bf 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CAP_2147846517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CAP!MTB"
        threat_id = "2147846517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 28 01 44 24 0c 8b c6 c1 e8 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 44 24 10 8b 44 24 20 01 44 24 10 8d 0c 33 31 4c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d [0-4] 93 00 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GIG_2147846532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GIG!MTB"
        threat_id = "2147846532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 d7 e8 59 81 44 24 ?? 8d 8e b1 2f b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 59 dd a3 59 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 74 b0 32 20 81 6c 24 ?? ec 47 b6 15 81 44 24 ?? 76 74 dd 1e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GHG_2147846577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GHG!MTB"
        threat_id = "2147846577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0c 33 32 0e 8b 57 10 8b 5f 14 88 4d fc 3b d3 73 ?? 8d 42 01 89 47 10 8b c7 83 fb 10 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AY_2147846638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AY!MTB"
        threat_id = "2147846638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 50 8b 84 31 ?? ?? ?? ?? 03 45 f4 50 ff 75 e4 ff 15 ?? ?? ?? ?? 8b 4d f8 83 c3 28 0f b7 47 06 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AY_2147846638_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AY!MTB"
        threat_id = "2147846638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 43 ca 03 c1 3b f0 74 ?? 8a 0c 33 32 0e 8b 57 10 8b 5f 14 88 4d fc 3b d3 73 ?? 8d 42 01 89 47 10 8b c7 83 fb 10 72 ?? 8b 07 8b 5d ec 46 88 0c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPX_2147846834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPX!MTB"
        threat_id = "2147846834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 da cc 00 00 00 81 da aa 00 00 00 c1 c2 b2 83 c3 6e c1 c7 ee f7 d3 c1 df 2d 8b 7d 08 f6 17 80 07 9f fe 07 47 e2 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPX_2147846834_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPX!MTB"
        threat_id = "2147846834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 30 33 c0 5e c2 04 00 56 8b 35 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 8b 35 ?? ?? ?? ?? 90 68 30 75 00 00 ff d6 eb f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPX_2147846834_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPX!MTB"
        threat_id = "2147846834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fc 06 8d 95 d0 fc ff ff 83 bd e4 fc ff ff 08 8d bd d0 fc ff ff 8b 85 e0 fc ff ff 8d 8d b0 fc ff ff 0f 43 95 d0 fc ff ff 0f 43 bd d0 fc ff ff c7 85 c0 fc ff ff 00 00 00 00 c7 85 c4 fc ff ff 0f 00 00 00 8d 1c 42 c6 85 b0 fc ff ff 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAF_2147847955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAF!MTB"
        threat_id = "2147847955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b d0 88 95 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? f7 d9 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 83 ea 6f 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 03 8d fc f7 ff ff 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 da 88 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAG_2147848146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAG!MTB"
        threat_id = "2147848146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d8 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 83 c1 15 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 d2 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 2b 85 74 ff ff ff 88 85 ?? ?? ?? ?? 0f b6 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ITI_2147848976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ITI!MTB"
        threat_id = "2147848976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 10 8b 44 24 20 01 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 0d 8d 54 24 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 c7 31 44 24 0c 8b 44 24 0c 29 44 24 14 8b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ADY_2147849130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ADY!MTB"
        threat_id = "2147849130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 4d ed 0f b6 55 ed f7 da 88 55 ed 0f b6 45 ed f7 d0 88 45 ed 0f b6 4d ed 81 c1 ?? ?? ?? ?? 88 4d ed 0f b6 55 ed f7 da 88 55 ed 0f b6 45 ed 83 e8 0d 88 45 ed 8b 4d c8 8a 55 ed 88 54 0d 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ADY_2147849130_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ADY!MTB"
        threat_id = "2147849130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 74 b2 72 68 ?? ?? ?? ?? 50 a3 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 69 88 15 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 50 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6c 88 15 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6f 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GGO_2147849270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GGO!MTB"
        threat_id = "2147849270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 14 8b 44 24 ?? 01 44 24 14 8b 44 24 24 31 44 24 ?? 8b 4c 24 10 33 4c 24 14 8d 44 24 2c 89 4c 24 10 e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 eb 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GJU_2147849274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GJU!MTB"
        threat_id = "2147849274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 43 ca 03 c1 3b f0 0f 84 ?? ?? ?? ?? 8a 04 33 8d 4d dc 32 06 88 45 fb 8d 45 fb}  //weight: 10, accuracy: Low
        $x_1_2 = "Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ADM_2147849350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ADM!MTB"
        threat_id = "2147849350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 03 0f b6 45 ?? c1 e0 05 0b d0 88 55 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? f7 d2 88 55 ?? 0f b6 45 ?? c1 f8 06 0f b6 4d ?? c1 e1 02 0b c1 88 45 ?? 0f b6 55 ?? 2b 55 ?? 88 55 ?? 8b ?? bc 8a 4d ee 88 4c 05 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GKC_2147849480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GKC!MTB"
        threat_id = "2147849480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 d3 ee 89 44 24 ?? 8b cd 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AME_2147849482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AME!MTB"
        threat_id = "2147849482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c3 23 c3 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 47 c6 85 ?? ?? ?? ?? 03 c6 85 ?? ?? ?? ?? 96 c6 85 ?? ?? ?? ?? 0e c6 85 ?? ?? ?? ?? 81 c6 85 ?? ?? ?? ?? a0 c6 85 ?? ?? ?? ?? 3c c6 85 ?? ?? ?? ?? 3b c6 85 ?? ?? ?? ?? 33 c6 85 ?? ?? ?? ?? 96 c6 85 ?? ?? ?? ?? 1a c6 85 ?? ?? ?? ?? 4d c6 85 ?? ?? ?? ?? b4 c6 85 ?? ?? ?? ?? e8 c6 85 ?? ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AME_2147849482_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AME!MTB"
        threat_id = "2147849482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dFKUeEPZMpb=" ascii //weight: 1
        $x_1_2 = "TYyxVCP J8==" ascii //weight: 1
        $x_1_3 = "P0RZOATUOaN8Cs==" ascii //weight: 1
        $x_1_4 = "20YUfUYdMdZUPI==" ascii //weight: 1
        $x_1_5 = "d945c8d4b2e11313c738a9a3ee074483" ascii //weight: 1
        $x_1_6 = "56a1c3d463f38174c2fd686077b9fd81" ascii //weight: 1
        $x_1_7 = "a2b77533b3b6d5aaf9786e5ad5d2f18c" ascii //weight: 1
        $x_3_8 = "OVOocTQo0xYj" ascii //weight: 3
        $x_4_9 = "PxxoPAHnNaUQBbuV" ascii //weight: 4
        $x_5_10 = "O0agcwQVTqol1OVc1T9rcEho" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPY_2147849818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPY!MTB"
        threat_id = "2147849818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 33 db 33 d2 8b 45 08 8a 10 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0 ee 33 c0 8b 4d 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPY_2147849818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPY!MTB"
        threat_id = "2147849818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d b0 00 00 00 f7 ee 81 ce b8 00 00 00 33 c9 33 ff 48 83 de 09 25 e0 00 00 00 f7 d0 c1 ca e9 81 df e0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPZ_2147850141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPZ!MTB"
        threat_id = "2147850141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 14 8b 44 24 28 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 2b f8 8d 44 24 18}  //weight: 1, accuracy: High
        $x_1_2 = {8b c7 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPQ_2147850142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPQ!MTB"
        threat_id = "2147850142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 39 c1 ef 02 c1 e2 06 8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01 83 c0 02 83 c7 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMY_2147850644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMY!MTB"
        threat_id = "2147850644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 69 f6 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 33 f1 3b d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMY_2147850644_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMY!MTB"
        threat_id = "2147850644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 2b c6 57 3b f8 77 ?? 8d 04 3e 83 fb 10 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 0f 43 85 ?? ?? ?? ?? 03 f0 8d 85 ?? ?? ?? ?? 50 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMY_2147850644_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMY!MTB"
        threat_id = "2147850644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 56 57 8b f9 ff 77 04 ff 15 70 b5 69 00 8b f0 56 ff 15 38 b5 69 00 89 45 d8 0f 57 c0 8d 45 ec}  //weight: 2, accuracy: High
        $x_1_2 = "TEMP\\pixelsee-installer-tmp" ascii //weight: 1
        $x_1_3 = "MediaGet\\mediaget.exe" ascii //weight: 1
        $x_1_4 = "PixelSee LLC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMY_2147850644_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMY!MTB"
        threat_id = "2147850644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 84 24 1c 02 00 00 56 b5 8b 2c c7 84 24 64 01 00 00 e1 c3 9c 0c c7 84 24 5c 01 00 00 94 27 73 51 c7 84 24 58 01 00 00 65 48 6d 5a c7 84 24 f0 01 00 00 9f 3a 12 51 c7 84 24 18 02 00 00 84 82 10 45 c7 84 24 08 01 00 00 80 d9 0f 28 c7 84 24 20 01 00 00 5a 91 84 3c c7 84 24 ac 01 00 00 c2 99 3e 72 c7 84 24 e0 00 00 00 f4 09 87 1b c7 84 24 00 02 00 00 d9 b0 ba 48 c7 84 24 50 01 00 00 02 a6 fb 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GNI_2147851092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GNI!MTB"
        threat_id = "2147851092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 d9 f7 09 81 44 24 ?? ae 7f 68 1a 81 44 24 ?? b6 a2 b2 20 81 44 24 ?? e5 a1 5a 02 81 44 24 ?? e8 c2 1a 07 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CAQ_2147851723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CAQ!MTB"
        threat_id = "2147851723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 8a 04 85 ?? ?? ?? ?? 32 04 31 8b 4d ec 88 86 ?? ?? ?? ?? 46 3b 75 e4 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "P41JNwgsMiN IWehdhdw4SQX2J ffmGl97FfIUYp5kNr3FSjdiSm4SW W1dmfGYoU1BfNOQc5gtQ0GOqcxGD4Soh41Fp" ascii //weight: 1
        $x_1_3 = "L61x6xYl6ATR4XujPdGq6MoXf1x8gnFlUq1B4J4bQVJeDyugcY0rRwwvjXWjPSPj" ascii //weight: 1
        $x_1_4 = "yUhG4T8RRUXXAUKndYGs5ScXf05kSiqc77BwDNU96Ew4xGYfcRZ6AcIeiKA9Syqc60po4dIkRRSf" ascii //weight: 1
        $x_1_5 = "DkSNITbl6ENr3CUSfSGiG9sehLxieWC89Kdy4 bmQ1Ji3CUxeCOiQMRKHkWA" ascii //weight: 1
        $x_1_6 = "L61x6xYl6ATR4XujPdGe5xspf0J8hGal7m17DOgU6wTj13CrMS0v4wMr365a3WF" ascii //weight: 1
        $x_1_7 = "P5dWNvYEPCFs1nKwcXCQRNHtRHB3Y2Ko9qdmROQ4Ikxw0WGCbSSt4ww22JVf3GKl" ascii //weight: 1
        $x_1_8 = "MKNpQOYj6DFi3HKnchiwDbcP41JlfHKQ601x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Amadey_GNS_2147852130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GNS!MTB"
        threat_id = "2147852130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Amadey\\Release\\Amadey.pdb" ascii //weight: 1
        $x_1_2 = "xmscoree.dll" ascii //weight: 1
        $x_1_3 = "eCR35KM0Go0" ascii //weight: 1
        $x_1_4 = "Mx9XMlAc" ascii //weight: 1
        $x_1_5 = "ZhlnRZ9DMq==" ascii //weight: 1
        $x_1_6 = "YVNLNHFNNRE=" ascii //weight: 1
        $x_1_7 = "YCJyR6Jb7NE=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GNV_2147852171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GNV!MTB"
        threat_id = "2147852171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 6b 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GNV_2147852171_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GNV!MTB"
        threat_id = "2147852171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Amadey\\Release\\Amadey.pdb" ascii //weight: 1
        $x_1_2 = "xmscoree.dll" ascii //weight: 1
        $x_1_3 = "BgwcNlED2O16" ascii //weight: 1
        $x_1_4 = "6lRk3JAxPrF6" ascii //weight: 1
        $x_1_5 = "wOkjPV3yOKX=" ascii //weight: 1
        $x_1_6 = "24584906758" ascii //weight: 1
        $x_1_7 = "EVRkeZQA2yRi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AHC_2147852398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AHC!MTB"
        threat_id = "2147852398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 89 4d f0 8b 55 fc 83 ea 01 89 55 fc 83 7d f0 00 76 ?? 8b 45 f8 c6 00 00 8b 4d f8 83 c1 01 89 4d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AHUG_2147852414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AHUG!MTB"
        threat_id = "2147852414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d7 4b}  //weight: 2, accuracy: High
        $x_1_2 = "OpenMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AER_2147852642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AER!MTB"
        threat_id = "2147852642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 e9 97 22 ff 34 df 38 68 ?? 17 fd ed e4 ?? 8b 11 47 88 20 38 0b 11 e9 b2 61 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ADZ_2147852827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ADZ!MTB"
        threat_id = "2147852827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 c6 44 24 ?? 83 8a 44 34 ?? 34 a9 0f b6 c0 66 89 44 74 ?? 46 83 fe 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RAJ_2147852900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RAJ!MTB"
        threat_id = "2147852900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 45 ec 8b 45 ec 83 45 f4 ?? 29 45 f4 83 6d f4 ?? 8b 45 f4 8d 4d fc e8 ?? ?? ?? ?? 8b 45 d8 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 03 c3 33 c2 31 45 fc 2b 75 fc 8b 45 d4 29 45 f8 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_FCB_2147889001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.FCB!MTB"
        threat_id = "2147889001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 20 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AP_2147889132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AP!MTB"
        threat_id = "2147889132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 5d e8 8b 5d b4 c7 06 00 00 00 00 8b 75 b0 89 31 8b 75 b8 8b 4d bc 89 1f 89 32 89 08 83 ec 04 c7 04 24 20 4e 00 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MBIX_2147890486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MBIX!MTB"
        threat_id = "2147890486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lovipuxed lufetanu xarezohivivapuw bugenu rajobege" wide //weight: 1
        $x_1_2 = "Gijiy cawuvij&Far susaliyeronoma gar suravavebucocewUWewicuma" wide //weight: 1
        $x_1_3 = "2Lovipuxed lufetanu xarezohivivapuw bugenu rajobege" wide //weight: 1
        $x_1_4 = "Dahukowemab wud nunimojiwif zagowocena nezu dofesevifax nokeb nowakapi fudasevusibeyiv nigulimos" wide //weight: 1
        $x_1_5 = "Wewicuma havadim jiwohatum" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MD_2147891464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MD!MTB"
        threat_id = "2147891464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 5c cd cc f6 02 c2 02 db 7c 01 57 21 1c 8e 05 35 30 11 28 bb 3a 23 03 92 58 7b 6b a7 2b 7a 41}  //weight: 5, accuracy: High
        $x_5_2 = {9e 76 e9 3c 64 10 14 76 2a 3b 0f 5c f9 43 b4 61 6a 7c 2f 77 33 61 55 49 58 06 65 20 86 7d 17 02 a2 50 e8 18 9f 39 04 33 08 4a 3c 7d ec 07 e8 02}  //weight: 5, accuracy: High
        $x_5_3 = {e0 00 02 01 0b 01 0e 18 00 bc 02 00 00 d6 00 00 00 00 00 00 3d 52 89 00 00 10}  //weight: 5, accuracy: High
        $x_2_4 = ".vmp0" ascii //weight: 2
        $x_2_5 = ".vmp1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ME_2147891799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ME!MTB"
        threat_id = "2147891799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 f7 c5 df 1a 33 cb e9 ec b7 53 00 ff e6 66 85 e7 66 3b f5 81 c7 08 00 00 00 89 08 81 ee 04 00 00 00 66 c1 f1 6b 0f ab f9 66 c1 e1 37 8b 0e f8}  //weight: 5, accuracy: High
        $x_5_2 = {81 ff 01 44 f9 f8 81 e9 51 1c f4 0f 84 f2 66 f7 c4 cc 0e 0f c9 33 d9 e9 a6 f2 0b 00 f7 d9 f9 33 d9 03 f1 56 c3 0f 31 f8 8d bf f8 ff ff ff 66 f7}  //weight: 5, accuracy: High
        $x_2_3 = {e0 00 02 01 0b 01 0e 18 00 8c 02 00 00 0c 0c}  //weight: 2, accuracy: High
        $x_2_4 = ".vmp0" ascii //weight: 2
        $x_2_5 = ".vmp2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_EC_2147892779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.EC!MTB"
        threat_id = "2147892779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0f be 02 33 c1 69 c0 91 e9 d1 5b 33 f0 8b c6 c1 e8 0d 33 c6 69 c8 91 e9 d1 5b 8b c1 c1 e8 0f 33 c1}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GPA_2147892788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GPA!MTB"
        threat_id = "2147892788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 04 30 32 06 88 45 ff 8d 45 ff 50 c6 45 c0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GPA_2147892788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GPA!MTB"
        threat_id = "2147892788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JMfIVZLCyF3FJtsBKF1VKdq" ascii //weight: 1
        $x_1_2 = "eqNvQBnqOxx6" ascii //weight: 1
        $x_1_3 = "KF1FQRnjfEJ6J3KHyuC" ascii //weight: 1
        $x_1_4 = "W31HMA4zWiK2RYec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMD_2147893178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMD!MTB"
        threat_id = "2147893178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 8d 4d e8 51 50 56 ff 75 b4 ff d3 8d 45 ec 50 ff 75 ec 56 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMD_2147893178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMD!MTB"
        threat_id = "2147893178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d0 8b 75 d4 8b 55 b0 8b 14 95 c8 e3 41 00 03 d1 8a 0c 03 03 d3 43 88 4c 32 2e 8b 4d bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMD_2147893178_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMD!MTB"
        threat_id = "2147893178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 b8 0b 00 00 ff d7 ff 35 ?? bc 46 00 ff d6 6a 00 6a 01 6a 02 ff 15 ?? ?? ?? ?? 6a 10 8d 4c 24 14 a3 ?? bc 46 00 51 50 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = {6a 00 6a 00 6a 00 6a 01 6a 00 ff 15 b8 12 45 00 89 45 d0 83 7d 1c 10 8d 4d 08 6a 00 0f 43 4d 08 6a 00 6a 03 6a 00 6a 00 6a 50 51 50 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMD_2147893178_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMD!MTB"
        threat_id = "2147893178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ff 10 88 9b e0 80 46 00 8b c3 b9 2c 63 46 00 0f 43 0d 2c 63 46 00 99 f7 fe 8a 04 0a 88 83 f0 81 46 00 43 81 fb}  //weight: 2, accuracy: High
        $x_1_2 = {83 7d 4c 10 8d 45 38 ff 75 48 0f 43 45 38 b9 c0 ?? 46 00 50 e8 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? 46 00 68 80 88 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 68 f4 01 00 00 ff d6 8b 55 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMD_2147893178_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMD!MTB"
        threat_id = "2147893178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 8d 47 34 50 8b 44 24 24 8b 80 a4 00 00 00 83 c0 08 50 ff 74 24 30 ff 15 ?? ?? ?? ?? 8b 4c 24 18 8b 47 28 03 44 24 14 51}  //weight: 1, accuracy: Low
        $x_2_2 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d e0 5c 46 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 e0 5c 46 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMD_2147893178_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMD!MTB"
        threat_id = "2147893178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 d2 2a d0 80 f2 44 2a ca 8a d0 80 f1 af 2a d1 0f b6 c8 d0 ca 2a d0 69 c9 fe 00 00 00 32 d0 f6 d2 80 c2 1a c0 ca 02 80 ea 57 32 d0 2a f2 b2 7d d0 c6 02 f0 f6 de 32 f0 02 f0 80 f6 09 2a ce f6 d1 02 c8 c0 c1 02 f6 d1 32 c8 80 e9 06 c0 c1 02 32 c8 80 c1 25 c0 c9 03 2a c8 d0 c9 80 e9 41 32 c8 80 c1 07 c0 c9 03 80 e9 56 32 c8 02 c8 f6 d9 32 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NAY_2147893288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NAY!MTB"
        threat_id = "2147893288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ed 04 00 00 00 80 ca ?? 8b 54 25 00 33 d3 e9 b7 a4 f8 ff 0f 84 7c 61 6d 00 0f b6 11 c1 e6 ?? 66 85 ea c1 e0 08 f7 c7 ?? ?? ?? ?? 0b f2 66 ff c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MF_2147893294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MF!MTB"
        threat_id = "2147893294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f bf c8 c1 cf 86 66 c1 d1 17 66 33 d0 c1 c8 9d 66 c1 c0 33 66 83 ee 02 47 66 81 eb c7 00 66 c1 ea 57 66 41 66 c1 c2 95 c1 e6 50 66 c1 c2 db f7 ee 66 f7 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_IP_2147894642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.IP!MTB"
        threat_id = "2147894642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 33 8d 4d c8 32 06 88 45 ff 8d 45 ff 6a 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_HH_2147895718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.HH!MTB"
        threat_id = "2147895718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e1 04 03 cf 03 d0 33 ca 89 4c 24 14}  //weight: 1, accuracy: High
        $x_1_2 = {31 74 24 14 8b 44 24 28 31 44 24 14 8b 44 24 14 29 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MG_2147895916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MG!MTB"
        threat_id = "2147895916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {e0 00 02 01 0b 01 0e 18 00 94 04 00 00 56 07 00 00 00 00 00 ac a3 7a 00 00 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GAA_2147898250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GAA!MTB"
        threat_id = "2147898250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 51 04 1c 81 84 24 ?? ?? ?? ?? d4 5f bb 25 b8 ?? ?? ?? ?? f7 a4 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 81 84 24 ?? ?? ?? ?? 07 82 f9 48 81 ac 24 ?? ?? ?? ?? 18 2b 67 55 81 84 24 ?? ?? ?? ?? 40 86 92 69 81 ac 24 ?? ?? ?? ?? ac b7 aa 67}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CCEZ_2147898569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CCEZ!MTB"
        threat_id = "2147898569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 81 c3 ?? ?? ?? ?? 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_EM_2147900695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.EM!MTB"
        threat_id = "2147900695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 0f 32 cb 66 81 ea 59 53 0f bc d3 d2 d6 80 c1 ef d0 c9 66 81 ca 46 52 66 85 c8 80 c1 16 d2 da 66 0f ca 80 f1 b8 32 d9 89 04 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_EM_2147900695_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.EM!MTB"
        threat_id = "2147900695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ISNmfV==" ascii //weight: 1
        $x_1_2 = "V3Bf1HWobyt=" ascii //weight: 1
        $x_1_3 = "JjsrPl==" ascii //weight: 1
        $x_1_4 = "R3JbesI5cs==" ascii //weight: 1
        $x_1_5 = "%userappdata%\\RestartApp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RDP_2147901218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RDP!MTB"
        threat_id = "2147901218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 01 00 00 00 c1 e0 00 c6 80 ?? ?? ?? ?? 65 b9 01 00 00 00 6b d1 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AAY_2147901221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AAY!MTB"
        threat_id = "2147901221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 38 c7 85 ?? ?? ?? ?? a3 95 05 16 c7 85 ?? ?? ?? ?? 6c 46 ba 09 c7 85 ?? ?? ?? ?? c7 a4 ad 16 c7 85 ?? ?? ?? ?? 55 96 03 5f c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RDS_2147901845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RDS!MTB"
        threat_id = "2147901845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 00 6a 04 8d 47 34 50 8b 83 a4 00 00 00 83 c0 08 50 ff b5 a0 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMA_2147902432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMA!MTB"
        threat_id = "2147902432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c5 81 c0 4c 00 00 00 b9 c2 05 00 00 ba 83 be 29 a5 30 10 40 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMA_2147902432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMA!MTB"
        threat_id = "2147902432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d9 c1 e1 05 c1 e1 05 c1 e9 03 c1 e9 07 81 e9 4a 0e 4c 89 89 cb 59 81 f3 0d 10 fb 79 81 f3 81 81 42 0f 89 d8 5b 01 f0 01 18 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RDU_2147902624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RDU!MTB"
        threat_id = "2147902624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 08 a1 ?? ?? ?? ?? 88 14 08 41 3b 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMBC_2147902696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMBC!MTB"
        threat_id = "2147902696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 ec 31 45 f0 8b 45 f0 33 c2 2b f8 8b c7 c1 e0 04 89 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GPB_2147902719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GPB!MTB"
        threat_id = "2147902719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {33 18 88 5d f3 8d 55 f3 52 8d 4d b0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_B_2147902822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.B!MTB"
        threat_id = "2147902822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CWRAV1IV4MpAPSNdTZaQLYJIMGdPVvFBzycWPnD=" ascii //weight: 2
        $x_2_2 = "LXpVRJYI2yC68fKibsGF25X3gqduWZ04OARx8sUtgWmhQO6mdLKmLpdn30deSXdSMBNRPKARXOGKOTx=" ascii //weight: 2
        $x_2_3 = "PSNlVLYh4W7u6eupb1Ux3KxBg7W3fki86TsyIYLuSxJ7Irh2L0X=" ascii //weight: 2
        $x_2_4 = "CSZ6V1QWiAaA7fCsbLal5VtB306xfD0D2ShwV1TbQOOu7yVdIl==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NA_2147903515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NA!MTB"
        threat_id = "2147903515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 c1 f8 10 88 04 3a 8b c1 c1 f8 08 88 44 3a 01 8b c2 88 4c 38 02 83 c7 03 83 6c 24 28 01 75 a3}  //weight: 10, accuracy: High
        $x_5_2 = {8d 42 ff c1 e8 02 83 c6 02 40}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NA_2147903515_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NA!MTB"
        threat_id = "2147903515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 1d e5 36 5e 00 b9 ?? ?? ?? ?? c1 cb 04 89 05 f2 63 5e 00 81 2d ?? ?? ?? ?? ea dd f6 08 c1 cf 15 81 c7 07 8d ae 68 81 05 ?? ?? ?? ?? 81 31 e3 67 33 d3}  //weight: 3, accuracy: Low
        $x_3_2 = {c1 c2 13 21 15 ?? ?? ?? ?? 2b 0d d4 6d 5e 00 89 1d ?? ?? ?? ?? e8 53 96 fe ff e8 4b 01 0d 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NB_2147903516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NB!MTB"
        threat_id = "2147903516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&= CHR ( RANDOM ( 97 , 122 , 1 ) )" ascii //weight: 2
        $x_1_2 = "&= STRINGMID ( $CHARS , RANDOM ( 1 , STRINGLEN ( $CHARS ) , 1 ) , 1 )" ascii //weight: 1
        $x_1_3 = "RUN ( @COMSPEC & \" /c schtasks /create /tn \" &" ascii //weight: 1
        $x_1_4 = "script = decodeURIComponent" ascii //weight: 1
        $x_1_5 = "STRINGREPLACE ( $EXENAME , \"\\\" , \"%5C\" ) ) &" ascii //weight: 1
        $x_1_6 = "%50%6f%77%65%72%53%68%65%6c%6c%20%2d%57%69%6e%64%6f%77%53%74%79%6c%65%20%48%" ascii //weight: 1
        $x_1_7 = "%27%3b%28%4e%65%77%2d%4f%62%6a%65%63%74%20%53%79%73%74%65%6d%2e%4e%65%74%2e%57%65%62%43%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_KL_2147904617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.KL!MTB"
        threat_id = "2147904617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 31 45 e4 8b 45 f8 33 45 e4 2b f8 89 45 f8 8b c7 c1 e0 04 89 7d dc 89 45 fc 8b 45 c8 01 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_HNS_2147907109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.HNS!MTB"
        threat_id = "2147907109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {e9 00 20 00 00 0a 00 eb 08 0f ?? ?? 00 00 00 00 00}  //weight: 20, accuracy: Low
        $x_1_2 = {31 cb 31 e1 83 ea 01 52 ff 0c 24 5a}  //weight: 1, accuracy: High
        $x_1_3 = {89 1c 24 e8 01 00 00 00 cc 8b 04 24 ?? 89 ?? 81 ?? 04 00 00 00 83 ?? 04}  //weight: 1, accuracy: Low
        $x_5_4 = {e1 6b 67 1a 45 12 3a 87 ac 17 5a 6b}  //weight: 5, accuracy: High
        $x_5_5 = {1c 6b 67 1a 45 12 3a 87 ac 17 5a 6b 72 bb 7d 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Amadey_LDP_2147909241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.LDP!MTB"
        threat_id = "2147909241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 89 45 f8 8b 45 e0 01 45 f8 8b 45 f8 8b 4d ?? 33 45 f4 33 c8 2b f9 89 4d ?? 8d 4d ?? 89 7d e8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NM_2147909277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NM!MTB"
        threat_id = "2147909277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 b9 00 00 00 00 01 d9 31 01 59 5b 68 c4 da fe 6d 89 04 24 b8 00 00 00 00 05 01 d2 fd 7e 01 f0 2d 01 d2 fd 7e 01 18 58 68 00 8e 80 7b 89 0c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_KGZ_2147912422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.KGZ!MTB"
        threat_id = "2147912422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 c1 e8 05 89 44 24 14 8b 44 24 30 01 44 24 14 8d 04 2b 33 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c ba ?? ?? ?? ?? 8d 4c 24 18 e8 ?? ?? ?? ?? 4e 74 09 8b 5c 24 18 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_IIZ_2147912755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.IIZ!MTB"
        threat_id = "2147912755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_THY_2147912756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.THY!MTB"
        threat_id = "2147912756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 46 89 45 fc 83 6d fc 28 83 6d fc ?? 8b 45 08 8a 4d fc 03 c6 30 08 46 3b 75 0c 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMAD_2147913028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMAD!MTB"
        threat_id = "2147913028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 04 1e 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ASGJ_2147913062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ASGJ!MTB"
        threat_id = "2147913062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zadaferofuxesiwituxexulata vuvopa jigamuwom logawufadavujoke lavehepedatewavufapomuxame" ascii //weight: 1
        $x_1_2 = "cupikofaxicusavezetiz" ascii //weight: 1
        $x_1_3 = "Sicereme binaleve cekarihezoyog" wide //weight: 1
        $x_1_4 = "Suhohufo xihus jolewolo nicoriducubilo yetef wagano" wide //weight: 1
        $x_1_5 = "lakomeforebigu dowegayi hor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GNK_2147913075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GNK!MTB"
        threat_id = "2147913075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 fc 50 e8 ?? ?? ?? ?? 8b 45 08 03 c6 59 8a 4d fc 30 08 46 3b 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAEP_2147913141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAEP!MTB"
        threat_id = "2147913141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d fc 30 08 46 3b 75 0c 7c e2}  //weight: 1, accuracy: High
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_PAEQ_2147913164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PAEQ!MTB"
        threat_id = "2147913164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 03 8b 1c 24 83 c4 04 51 b9 00 00 00 00 01 f1 52 51 b9 00 00 00 00 89 ca 59 01 ca 01 1a 5a 59 53 bb 04 00 00 00 57 bf ee 84 bf 5e 01 fe 5f 01 de 81 ee ee 84 bf 5e 5b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ASGK_2147913359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ASGK!MTB"
        threat_id = "2147913359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 45 c4 50 89 7d c4 e8 ?? ?? ?? ff 8a 45 c4 30 04 33 83 7d 08 0f 59 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_TSA_2147913507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.TSA!MTB"
        threat_id = "2147913507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 8b c3 c1 ea 04 8b ca c1 e1 04 03 ca 2b c1 03 c6 0f b6 44 04 ?? 32 85 04 10 40 00 83 c5 06 88 47 fd 8d 45 ff 3d 00 a2 06 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GXZ_2147913591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GXZ!MTB"
        threat_id = "2147913591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e8 ?? 03 ce 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 31 4d ?? 81 3d ?? ?? ?? ?? 03 0b 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_TIV_2147913759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.TIV!MTB"
        threat_id = "2147913759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 7d fc e8 ?? ?? ?? ?? 8b 45 08 59 8a 4d fc 03 c6 30 08 83 fb 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MET_2147913831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MET!MTB"
        threat_id = "2147913831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 33 85 8c fd ff ff 8b 55 70 2b f8 8b c7 c1 e8 05 03 d7 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c 8b f7 c1 e6 04 03 b5 80 fd ff ff 33 f2 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_YAH_2147914054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.YAH!MTB"
        threat_id = "2147914054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 6c 33 c3 2b f0 89 b5 94 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {03 cf 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c 8b df c1 e3 04 03 9d ?? ?? ff ff 33 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NC_2147915289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NC!MTB"
        threat_id = "2147915289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 1a 1c 00 00 00 00 00 e9 00 20 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ROA_2147916070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ROA!MTB"
        threat_id = "2147916070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 3b f0 0f 84 ?? ?? ?? ?? 8b 45 e4 8d 4d c0 6a 01 c7 45 d0 00 00 00 00 c7 45 d4 0f 00 00 00 8a 04 30 32 06 88 45 eb 8d 45 eb 50 c6 45 c0 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_KAA_2147918471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.KAA!MTB"
        threat_id = "2147918471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a ca 2a c8 80 c1 ?? 30 ?? 15 [0-4] 42 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RDAC_2147920257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RDAC!MTB"
        threat_id = "2147920257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 d9 31 01 8b 0c 24 81 c4 04 00 00 00 5b 50 89 14 24 53 bb 00 00 00 00 89 da 5b 01 f2 01 1a 5a 56}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_KAB_2147920782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.KAB!MTB"
        threat_id = "2147920782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c8 0f b6 46 ?? c1 e1 06 0f b6 80 ?? ?? ?? ?? 0b c8 0f b6 46 ?? c1 e1 06 83 c6 04 0f b6 80 ?? ?? ?? ?? 0b c8 8b c2 42 89 54 24 ?? 8b d1 c1 ea ?? 88 10 8b 54 24 ?? 8b c2 42 89 54 24 ?? 8b d1 c1 ea 08 88 10 8b 54 24 ?? 8b c2 42 88 08 83 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RZ_2147921609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RZ!MTB"
        threat_id = "2147921609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8d 04 0a 33 d2 f7 35 ?? ?? ?? ?? 03 d6 8b 75 ?? 8b ce 83 7e ?? 10 72 ?? 8b 0e 8a 02 88 04 19 43 89 5d ?? 3b 5d ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BKC_2147923106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BKC!MTB"
        threat_id = "2147923106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 37 8d 4d c4 32 06 88 45 ?? 8d 45 ef 6a 01 50 c7 45 d4 ?? ?? ?? ?? c7 45 d8 0f 00 00 00 c6 45 c4 00 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_EZ_2147923539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.EZ!MTB"
        threat_id = "2147923539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 04 00 00 00 90 06 00 00 06 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_EZ_2147923539_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.EZ!MTB"
        threat_id = "2147923539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bgplyofn" ascii //weight: 2
        $x_2_2 = "pdwvfcxw" ascii //weight: 2
        $x_2_3 = "NzAzMTAyMzU5NTlaMDIxEjAQBgNVBAMMCU9SX0syRDlLTzEcMBoGA1UECgwTT3Jl" ascii //weight: 2
        $x_1_4 = "Y2FsIGFuZCBFbGVjdHJvbmljcyBFbmdpbmVlcnMsIEluYy4xDTALBgNVBAsTBElF" ascii //weight: 1
        $x_1_5 = "bGVjdHJpY2FsYW5kRWxlY3Ryb25pY3NFbmdpbmVlcnNJbmNJRUVFUm9vdENBLmNy" ascii //weight: 1
        $x_1_6 = "Oi8vcGtpLWNybC5zeW1hdXRoLmNvbS9vZmZsaW5lY2EvVGhlSW5zdGl0dXRlb2ZF" ascii //weight: 1
        $x_1_7 = "KgI8WCsKbA0ZGeThc1GC7WN3kYdWRXtU2S+auJHMpA17DJMyNmsn7DAC2QKBgDb3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CCJC_2147924800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CCJC!MTB"
        threat_id = "2147924800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "program files\\mozilla firefox" ascii //weight: 1
        $x_1_2 = "program files\\mozilla thunderbird" ascii //weight: 1
        $x_1_3 = "purple\\accounts.xml" ascii //weight: 1
        $x_1_4 = "CentBrowser\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "Sputnik\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_6 = "powershell -Command Compress-Archive -Path" ascii //weight: 1
        $x_2_7 = "encryptedUsername" ascii //weight: 2
        $x_2_8 = "encryptedPassword" ascii //weight: 2
        $x_1_9 = "FileZilla\\sitemanager.xml" ascii //weight: 1
        $x_2_10 = "Monero\\wallets\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_HZ_2147926766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.HZ!MTB"
        threat_id = "2147926766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 48 04 00 00 00 90 06 00 00 06 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMCS_2147928168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMCS!MTB"
        threat_id = "2147928168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 73 72 63 00 00 00 88 03 00 00 00 90 06 00 00 04 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 94 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BKL_2147928287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BKL!MTB"
        threat_id = "2147928287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 56 31 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BAN_2147928680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BAN!MTB"
        threat_id = "2147928680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30}  //weight: 2, accuracy: High
        $x_3_2 = {40 00 00 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 b0 06 00 00 ?? ?? 00 00 f6 02}  //weight: 3, accuracy: Low
        $x_2_3 = {a7 bb 2d 49 e3 da 43 1a e3 da 43 1a e3 da 43 1a b8 b2 40 1b ed da 43 1a b8 b2 46 1b 42 da 43 1a 36 b7 47 1b f1 da 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_GOP_2147928825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.GOP!MTB"
        threat_id = "2147928825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 7a 2d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BSA_2147928965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BSA!MTB"
        threat_id = "2147928965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {be 58 9a d7 7f 4e 81 f6 76 ab 9f 6d 81 ee 74 7c ab 58 81 c6 77 86 3f 67 81 ce da 03 be 6b 81 ee fa 3b fe 6b 01 f7 5e 83 ef 04 87 3c 24}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BSA_2147928965_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BSA!MTB"
        threat_id = "2147928965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f dc 2d 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_2 = {eb 08 0f 24 2e 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_3 = {eb 08 0f 22 2e 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_4 = {eb 08 0f 48 2d 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_5 = {eb 08 0f 28 2d 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_6 = {eb 08 0f fc 2c 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_7 = {eb 08 0f ee 2c 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_8 = {eb 08 0f 4a 2b 00 00 00 00 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Amadey_FZZ_2147929048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.FZZ!MTB"
        threat_id = "2147929048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 0f 84 20 00 00 00 8b 85 05 17 2d 12 bb 00 00 00 00 0b db 0f 85 ?? ?? ?? ?? 28 24 39 30 04 39 49 0f 85 ?? ?? ?? ?? 61 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_AMCW_2147929313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.AMCW!MTB"
        threat_id = "2147929313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 04 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPA_2147929973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPA!MTB"
        threat_id = "2147929973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 04 00 00 00 90 06 00 00 06 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 96 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d4 05 00 00 00 90 06 00 00 04 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 94 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Amadey_RPA_2147929973_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPA!MTB"
        threat_id = "2147929973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 20 00 78 00 20 00 2d 00 61 00 6f 00 61 00 20 00 2d 00 62 00 73 00 6f 00 30 00 20 00 2d 00 62 00 73 00 70 00 31 00 20 00 63 00 3a 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 7a 00 69 00 70 00 20 00 2d 00 70 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 2d 00 6f 00 63 00 3a 00 5c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NIT_2147931114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NIT!MTB"
        threat_id = "2147931114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 79 04 39 ba a0 00 00 00 72 14 8b 01 03 c7 39 82 a0 00 00 00 0f 82 0b 01 00 00 0f b7 42 06 46 83 c1 28 3b f0 72 d9}  //weight: 2, accuracy: High
        $x_1_2 = {0f 8c 0a ff ff ff ff 75 d0 ff 15 5c f0 43 00 83 f8 ff 74 0e b8 01 00 00 00 5f 5e 8b e5 5d 8b e3 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_Y_2147932740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.Y!MTB"
        threat_id = "2147932740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[system.reflection.assembly]::(" wide //weight: 1
        $x_1_2 = ".substring(" wide //weight: 1
        $x_1_3 = "[system.iO.file]::(" wide //weight: 1
        $x_1_4 = "system.iO.memorystream" wide //weight: 1
        $x_1_5 = "-join" wide //weight: 1
        $x_1_6 = "[convert]::(" wide //weight: 1
        $x_1_7 = ".invoke($" wide //weight: 1
        $x_1_8 = ".createdecryptor(" wide //weight: 1
        $x_1_9 = ".split([environment]::" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_YLH_2147932922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.YLH!MTB"
        threat_id = "2147932922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 6c 20 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ADZY_2147938130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ADZY!MTB"
        threat_id = "2147938130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 a3 54 74 46 00 ff 15 ?? ?? ?? ?? 68 f8 23 45 00 56 a3 58 74 46 00 ff 15 ?? ?? ?? ?? 68 0c 24 45 00 56 a3 5c 74 46 00 ff 15 ?? ?? ?? ?? 68 1c 24 45 00 56 a3 60 74 46 00 ff 15 ?? ?? ?? ?? 68 30 24 45 00 56 a3 64 74 46 00 ff 15 ?? ?? ?? ?? 68 44 24 45 00 56 a3 68 74 46 00 ff 15 ?? ?? ?? ?? 68 5c 24 45 00 56 a3 6c 74 46 00 ff 15 ?? ?? ?? ?? 68 70 24 45 00 56 a3 70 74 46 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_CHV_2147938675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.CHV!MTB"
        threat_id = "2147938675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 06 21 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BAA_2147939310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BAA!MTB"
        threat_id = "2147939310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 02 32 94 8d ?? ?? ?? ?? 8b 45 18 8b 08 8b 85 ?? ?? ?? ?? 88 14 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_BW_2147939329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.BW!MTB"
        threat_id = "2147939329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 c7 50 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 13 83 45}  //weight: 4, accuracy: Low
        $x_1_2 = {04 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_Z_2147941857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.Z!MTB"
        threat_id = "2147941857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".EntryPoint.Invoke($" wide //weight: 1
        $x_1_2 = "[Char](" wide //weight: 1
        $x_1_3 = ".GetValue(" wide //weight: 1
        $x_1_4 = "[Reflection.Assembly]::Load" wide //weight: 1
        $x_1_5 = "Runtime.InteropServices.Marshal]" wide //weight: 1
        $x_1_6 = "split" wide //weight: 1
        $x_1_7 = ".GetMethod(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NMQ_2147942039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NMQ!MTB"
        threat_id = "2147942039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 1
        $x_1_2 = "USNpVx9lbxq TZtl tZg6DoY" ascii //weight: 1
        $x_1_3 = "QwNzVYNibLKj9DB9" ascii //weight: 1
        $x_1_4 = "Io2ARBc1YNqVUTJX dfW9N==" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "7919770680e9bb04829c00e5bc047c3b" ascii //weight: 1
        $x_2_7 = "e0d27f0433178d157a8a1848a75bca2c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_HB_2147942270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.HB!MTB"
        threat_id = "2147942270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 6d 00 64 00 20 00 22 02 02 03 30 2d 39}  //weight: 1, accuracy: Low
        $x_1_2 = {65 00 78 00 74 00 72 00 61 00 63 00 33 00 32 00 20 00 2f 00 59 00 20 00 2f 00 45 00 20 00 [0-48] 2e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "choice /d y /t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Amadey_ZA_2147942698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZA!MTB"
        threat_id = "2147942698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-60] 2e 00 74 00 6d 00 70 00 [0-16] 26 00 28 00 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "System.IO.Compression.DeflateStream([IO.MemoryStream]" wide //weight: 1
        $x_1_3 = "Convert]::FromBase64String(" wide //weight: 1
        $x_1_4 = "System.IO.Compression.CompressionMode]::Decompress" wide //weight: 1
        $x_1_5 = "New-Object IO.StreamReader($" wide //weight: 1
        $x_1_6 = "$_.ReadToEnd(" wide //weight: 1
        $x_1_7 = "System.Text.Encoding]::Ascii" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ZB_2147942699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZB!MTB"
        threat_id = "2147942699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String(" wide //weight: 1
        $x_1_2 = "Invoke-Expression $" wide //weight: 1
        $x_1_3 = "-replace" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ZC_2147942700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZC!MTB"
        threat_id = "2147942700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MpPreference -ExclusionPath @($env:UserProfile, $env:SystemDrive" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "DownloadString" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ZE_2147942701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZE!MTB"
        threat_id = "2147942701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[System.IO.DriveInfo]::GetDrives(" wide //weight: 1
        $x_1_2 = "ForEach-Objec" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPB_2147943510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPB!MTB"
        threat_id = "2147943510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {d6 b6 42 53 92 d7 2c 00 92 d7 2c 00 92 d7 2c 00 86 bc 2f 01 9f d7 2c 00 86 bc 29 01 28 d7 2c 00 c0 a2 28 01 80 d7 2c 00 c0 a2 2f 01 84 d7 2c 00 c0 a2 29 01 cb d7 2c 00 a3 8b d1 00 90 d7 2c 00 86 bc 28 01 85 d7 2c 00 86 bc 2d 01 81 d7 2c 00 92 d7 2d 00 62 d7 2c 00 5e a2 25 01 93 d7 2c 00 5e a2 d3 00 93 d7 2c 00 5e a2 2e 01 93 d7 2c 00 52 69 63 68 92 d7 2c}  //weight: 100, accuracy: High
        $x_1_2 = "\\\\.\\Global\\oreansx64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPB_2147943510_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPB!MTB"
        threat_id = "2147943510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 2f 00 74 00 72 00 20 00 63 00 3a 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 30 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MR_2147943630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MR!MTB"
        threat_id = "2147943630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {8b ec 56 68 e4 5e 4a 00 68 dc 5e 4a 00 68 24 36 4a 00 6a 21}  //weight: 15, accuracy: High
        $x_10_2 = {89 4d fc 8b 45 fc 89 45 f8 8b 45 fc 0f b6 00 85 c0 74 ?? 83 3d 44 51 4b 00 00 ?? ?? ff 15 4c 90 49 00 39 05 44 51 4b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ZAC_2147945136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZAC!MTB"
        threat_id = "2147945136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::GetTotalMemory($" wide //weight: 1
        $x_1_2 = ".ReaDTOeNd(" wide //weight: 1
        $x_1_3 = "froMBASE64strinG(" wide //weight: 1
        $x_1_4 = "-join" wide //weight: 1
        $x_1_5 = "char[]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_NJL_2147945776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.NJL!MTB"
        threat_id = "2147945776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LUNWH0Urhm2tL6hyXzW4Qeyq9q==" ascii //weight: 2
        $x_1_2 = "whEgFTfWUlb7R4GwFgO ViVwOiIw==" ascii //weight: 1
        $x_1_3 = "netsh advfirewall firewall set rule group=\"Remote Desktop\" new enable=Yes" ascii //weight: 1
        $x_1_4 = "SET Passwordchangeable=FALSE" ascii //weight: 1
        $x_1_5 = "WMIC USERACCOUNT WHERE \"Name =" ascii //weight: 1
        $x_1_6 = "MqUrQEcT3WqTZ0J5afm0jH==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_SUPC_2147948947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.SUPC!MTB"
        threat_id = "2147948947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 16 40 32 c5 88 02 48 ff c2 49 ff c8 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_RPC_2147949248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.RPC!MTB"
        threat_id = "2147949248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Get-ScheduledTask -TaskName" wide //weight: 1
        $x_1_2 = "$task.Settings.DisallowStartIfOnBatteries = $false;$task.Settings.StopIfGoingOnBatteries = $false;" wide //weight: 1
        $x_100_3 = "$task.Settings.WakeToRun = $false;$task.Settings.RunOnlyIfIdle = $false;$task.Settings.ExecutionTimeLimit = 'PT0S';" wide //weight: 100
        $x_1_4 = "$task.Settings.MultipleInstances = 'IgnoreNew';Set-ScheduledTask -InputObject $task;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_ARA_2147949561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ARA!MTB"
        threat_id = "2147949561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 b4 8b 0c 85 38 a8 41 00 8a 04 3b 03 ce 88 44 19 2e 43 3b da 7c e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_MJO_2147950812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MJO!MTB"
        threat_id = "2147950812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 4a ff 83 e1 1e 0f b6 89 ?? ?? ?? ?? 32 8a ?? ?? ?? ?? 88 4c 10 ff 81 fa a9 39 06 00 74 1a 89 d1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 32 8a ?? ?? ?? ?? 88 0c 10 83 c2 02 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amadey_2147951561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.MTH!MTB"
        threat_id = "2147951561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2z1690.exe" ascii //weight: 1
        $x_1_2 = "1d55e9.exe" ascii //weight: 1
        $x_1_3 = "hater/nircmd.exe" ascii //weight: 1
        $x_1_4 = "InstallHinfSection %s 128" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

