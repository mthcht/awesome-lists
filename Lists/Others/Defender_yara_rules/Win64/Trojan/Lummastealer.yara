rule Trojan_Win64_Lummastealer_ZTS_2147941171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lummastealer.ZTS!MTB"
        threat_id = "2147941171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lummastealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 70 48 8b 54 24 28 30 04 0a 8b 44 24 70 8b 44 24 70 8b 44 24 70 8b 44 24 70 b8 1d 32 cf 80 3d a7 a0 44 e5 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lummastealer_NE_2147956237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lummastealer.NE!MTB"
        threat_id = "2147956237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lummastealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 54 24 68 48 89 14 24 48 89 c3 31 c9 48 89 cf 31 f6 41 b8 04 00 00 00 45 31 c9 4d 89 ca 4c 8d 9c 24 a0 00 00 00 4c 89 c8}  //weight: 2, accuracy: High
        $x_1_2 = {48 85 c0 74 1e 0f b6 54 24 49 84 d2 74 0b 48 8b 5c 24 60 48 89 58 30 eb 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

