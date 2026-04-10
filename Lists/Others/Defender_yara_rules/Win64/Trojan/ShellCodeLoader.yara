rule Trojan_Win64_ShellCodeLoader_NWU_2147954064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoader.NWU!MTB"
        threat_id = "2147954064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 e8 ?? ?? ?? ?? 48 83 7d ?? ?? 78 ?? 48 8b 85 ?? ?? ?? ?? 48 39 45 ?? 7c ?? 48 8b 85 ?? ?? ?? ?? 48 8d 50 ?? 48 8b 45 ?? 48 89 c1 e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 48 8b 45 ?? 48 01 d0 48 83 c0 ?? 0f b6 00 32 45 ?? 48 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "Evasive Shellcode Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeLoader_KJ_2147956959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoader.KJ!MTB"
        threat_id = "2147956959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 89 c1 49 0f af d0 48 c1 ea ?? 8d 14 52 c1 e2 ?? 29 d1 8d 50 ?? 32 14 03 48 63 c9 32 94 0c ?? ?? ?? ?? 88 14 03 48 83 c0 ?? 48 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeLoader_NQA_2147957581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoader.NQA!MTB"
        threat_id = "2147957581"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "S7jwIIhtHcubgx1yrXpUFfH9jBHaa" ascii //weight: 2
        $x_2_2 = "z4h1ygL9pxEoJmGd46Kta2T624nLnIM" ascii //weight: 2
        $x_2_3 = "03Xr0gFAOAldC9hoJz7V0yx9B" ascii //weight: 2
        $x_2_4 = "FkaFFLS3SRTD6g0ZYyXOFMHbKwhPdGOL.dll" ascii //weight: 2
        $x_2_5 = "RepositoryUrlBpnEFTpGDxsfKKrPFYPCqvZGsxSkwyskIg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_ShellCodeLoader_GDB_2147966592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoader.GDB!MTB"
        threat_id = "2147966592"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4d 10 e8 42 67 02 00 48 39 45 f8 0f 92 c0 84 c0 74 22 48 8b 45 f8 48 89 c2 48 8b 4d 10 e8 97 bc 08 00 48 89 c2 0f b6 02 32 45 18 88 02 48 83 45 f8 01 eb ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeLoader_KTL_2147966640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoader.KTL!MTB"
        threat_id = "2147966640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c3 48 69 d0 ?? ?? ?? ?? 48 c1 fa ?? 89 d9 c1 f9 ?? 29 ca 44 8d 0c d2 46 8d 0c 4a 89 da 44 29 ca 48 63 d2 0f b6 14 16 41 30 10 48 69 c0 ?? ?? ?? ?? 48 c1 f8 ?? 29 c8 69 c0 ?? ?? ?? ?? 39 d8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

