rule Trojan_Win32_DarkVNC_RPY_2147850294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkVNC.RPY!MTB"
        threat_id = "2147850294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkVNC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 e0 04 2c 10 0a c3 32 c1 32 44 24 10 88 06 32 f8 83 c6 02 83 c5 02 eb 0d 8d 48 ff bf 01 00 00 00 c0 e1 04 0a cb 8a 02 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkVNC_SX_2147955085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkVNC.SX!MTB"
        threat_id = "2147955085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkVNC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 46 f0 66 89 35 ?? ?? ?? ?? 8b f2 0f b7 4f ?? 66 3b d1 8b c1 0f 46 f0 fe c7}  //weight: 10, accuracy: Low
        $x_5_2 = {c7 44 24 14 57 54 53 51 c7 44 24 18 75 65 72 79 c7 44 24 1c 53 65 73 73 c7 44 24 20 69 6f 6e 49 c7 44 24 24 6e 66 6f 72 c7 44 24 28 6d 61 74 69 c7 44 24 2c 6f 6e 57 00}  //weight: 5, accuracy: High
        $x_3_3 = {0f b7 c9 0f b7 c2 c1 e1 ?? 0b c8 89 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 d2 81 f9 ?? ?? ?? ?? 0f 4c c2 a3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

