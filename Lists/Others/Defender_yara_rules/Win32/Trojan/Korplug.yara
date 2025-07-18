rule Trojan_Win32_Korplug_GMN_2147918622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korplug.GMN!MTB"
        threat_id = "2147918622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b e8 8b 4d ?? 8d 41 ?? 89 45 ?? 8a 44 9c ?? 8b 9c 24 ?? ?? ?? ?? 32 04 1a 88 44 29 ?? 8d 44 24 ?? 50 6a 01 52 e8 ?? ?? ?? ?? 83 c4 ?? 84 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Korplug_WFB_2147919021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korplug.WFB!MTB"
        threat_id = "2147919021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8a 4d e0 d3 f8 30 44 37 08 83 fb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Korplug_VV_2147920035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korplug.VV!MTB"
        threat_id = "2147920035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 94 95 e8 fb ff ff 8d 8d e0 fb ff ff 32 14 30 46 0f b6 d2 e8 af c7 ff ff e9 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Korplug_AHT_2147946724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korplug.AHT!MTB"
        threat_id = "2147946724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 e4 47 c6 45 e5 65 c6 45 e6 74 c6 45 e7 4d c6 45 e8 6f c6 45 e9 64 c6 45 ea 75 c6 45 eb 6c c6 45 ec 65 c6 45 ed 46 c6 45 ee 69 c6 45 ef 6c c6 45 f0 65 c6 45 f1 4e c6 45 f2 61 c6 45 f3 6d c6 45 f4 65 c6 45 f5 41 c6 45 f6 00}  //weight: 2, accuracy: High
        $x_3_2 = {83 f2 4c 88 95 5f fe ?? ?? 0f be 85 5f fe ?? ?? 83 f0 76 88 85 5f fe ?? ?? 8b 8d a4 fe ?? ?? 03 8d 54 fe ?? ?? 0f b6 09 8b 85 54 fe ?? ?? 33 d2 f7 75 b4 8b 45 d8 0f be 14 10 33 ca}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

