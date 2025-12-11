rule Trojan_Win64_ShellcodeLoader_MKV_2147942741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.MKV!MTB"
        threat_id = "2147942741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 1e 32 18 48 8b 95 58 02 00 00 48 83 ec 20 48 89 f9 e8 12 a3 00 00 48 83 c4 20 88 18 48 8b 9d ?? ?? ?? ?? 48 83 c3 01 b8 56 e9 d3 fd 3d e3 8d 0c 15 0f 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_AJZ_2147944327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.AJZ!MTB"
        threat_id = "2147944327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 c8 49 f7 e0 48 c1 ea 03 48 8d 04 92 48 89 ca 48 01 c0 48 29 c2 41 0f b6 04 11 30 04 0e 48 83 c1 01 48 81 f9 00 02 00 00 75 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_NOV_2147950131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.NOV!MTB"
        threat_id = "2147950131"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 48 8b 4c 24 70 48 8b c1 48 8b 4c 24 78 48 f7 f1 48 8b c2 48 8d 0d 88 ed 00 00 0f be 04 01 48 8b 4c 24 30 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 11 33 c8 8b c1 48 63 4c 24 28 48 8b 54 24 30 88 04 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_AN_2147952413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.AN!MTB"
        threat_id = "2147952413"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellcodeLoader" ascii //weight: 1
        $x_1_2 = "latestumang.netlify.app/shellcode.bin" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_TRX_2147953142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.TRX!MTB"
        threat_id = "2147953142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 39 44 24 ?? 73 ?? 0f b6 05 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 8b d0 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 ?? 48 8b 44 24 ?? 0f b6 00 88 44 24 ?? 0f b6 44 24 ?? 33 44 24 ?? 48 8b 4c 24 ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_SYJ_2147953784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.SYJ!MTB"
        threat_id = "2147953784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 3c 48 89 fb 89 c1 01 f0 99 41 f7 f9 48 63 c2 8a 14 04 48 89 c6 88 14 3c 88 0c 04 02 0c 3c 0f b6 c9 8a 04 0c 43 30 04 02 49 ff c0 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_TRK_2147956235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.TRK!MTB"
        threat_id = "2147956235"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 0f b6 4c 1a ?? 4c 8b 83 ?? ?? ?? ?? b8 ?? ?? ?? ?? 49 ff c2 f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 b8 ?? ?? ?? ?? 69 d2 ?? ?? ?? ?? 2b ca f7 ef 80 c1 ?? 43 30 0c 08 c1 fa ?? 8b cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_AHB_2147958343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.AHB!MTB"
        threat_id = "2147958343"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {06 00 48 8b 85 ?? ?? ?? 00 0f b7 08 81 f1 ?? ?? 00 00 0f b6 40 02 35 ?? 00 00 00 66 09 c8}  //weight: 30, accuracy: Low
        $x_20_2 = "[-] Failed to find 'mov rcx, r8' pattern" ascii //weight: 20
        $x_10_3 = "[+] Searching for syscall" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_IUY_2147958473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.IUY!MTB"
        threat_id = "2147958473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "62.60.226.248:5553/may.bin" ascii //weight: 1
        $x_1_2 = "vivolt\\x64\\Release\\vivolt.pdb" ascii //weight: 1
        $x_1_3 = "\\OneDrive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_AHC_2147959272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.AHC!MTB"
        threat_id = "2147959272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 89 eb 83 e3 ?? c1 eb ?? 44 89 ed 83 e5 ?? c1 ed ?? 45 89 ee 41 83 e6 ?? 41 c1 ee ?? 45 89 ec 41}  //weight: 30, accuracy: Low
        $x_20_2 = {f3 43 0f 6f 04 02 f3 42 ?? ?? ?? ?? ?? ?? ?? ?? 66 0f ef c8 48 83 c0 ?? f3 43 0f 7f 0c 01 49 83 c0 ?? 48 39 c1 75}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

