rule Trojan_Win64_MysticStealer_YAA_2147900612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MysticStealer.YAA!MTB"
        threat_id = "2147900612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c9 ff c1 41 0f af c9 f6 c1 01 41 0f 94 c1 44 30 ca 84 d2 41 b9 a8 08 00 00 ba ?? ?? ?? ?? 49 0f 45 d1 f6 c1 01 48 89 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MysticStealer_AMYS_2147924974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MysticStealer.AMYS!MTB"
        threat_id = "2147924974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 c7 85 10 04 00 00 53 00 66 c7 85 12 04 00 00 5c 00 66 c7 85 14 04 00 00 48 00 66 c7 85 16 04 00 00 55 00 66 c7 85 18 04 00 00 59 00 66 c7 85 1a 04 00 00 51 00 66 c7 85 1c 04 00 00 0d 00 66 c7 85 1e 04 00 00 0d 00 66 c7 85 20 04 00 00 6e 00 66 c7 85 22 04 00 00 25 00 66 c7 85 24 04 00 00 2e 00 66 c7 85 26 04 00 00 2f 00 66 c7 85 28 04 00 00 44 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

