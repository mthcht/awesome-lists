rule Trojan_Win32_MixLoader_RJ_2147842438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MixLoader.RJ!MTB"
        threat_id = "2147842438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MixLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 14 50 ff 15 60 e2 46 00 ff 15 64 e2 46 00 e9}  //weight: 1, accuracy: High
        $x_1_2 = {83 6a 0c 01 8b 42 00 74 2c 85 c0 89 4a 08 8a 40 01 89 41 fc 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MixLoader_RB_2147844302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MixLoader.RB!MTB"
        threat_id = "2147844302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MixLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 6a 00 e8 1a 45 04 00 85 c0 74 0f e8 dd 00 00 00 e8 38 75 fd ff e8 23 4e fe ff e9}  //weight: 5, accuracy: High
        $x_1_2 = "ASmartCore.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MixLoader_RPX_2147846029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MixLoader.RPX!MTB"
        threat_id = "2147846029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MixLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 66 69 63 61 74 69 6f 6e 00 00 00 00 44 62 67 51 75 65 72 79 44 65 62 75 67 46 69 6c 74 65 72 53 74 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 72 65 42 75 66 66 65 72 00 00 00 00 4c 64 72 52 65 67 69 73 74 65 72 44 6c 6c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 74 65 72 53 74 61 74 65 00 00 00 00 44 62 67 55 69 43 6f 6e 76 65 72 74 53 74 61 74 65 43 68 61 6e 67 65 53 74 72 75 63 74 75 72 65 45 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 49 6e 66 6f 72 6d 61 74 69 6f 6e 00 41 6c 70 63 52 75 6e 64 6f 77 6e 43 6f 6d 70 6c 65 74 69 6f 6e 4c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 72 6f 63 41 64 64 72 65 73 73 00 00 41 70 69 53 65 74 51 75 65 72 79 41 70 69 53 65 74 50 72 65 73 65 6e 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

