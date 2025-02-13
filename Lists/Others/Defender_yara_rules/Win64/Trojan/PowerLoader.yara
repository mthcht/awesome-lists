rule Trojan_Win64_PowerLoader_GA_2147932969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PowerLoader.GA!MTB"
        threat_id = "2147932969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PowerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d2 41 0f b6 0b 41 8b c0 49 ff c3 48 33 c8 0f b6 c1 41 8b c8 44 8b 04 83 c1 e9 08 44 33 c1 48 ff ca 75 de}  //weight: 2, accuracy: High
        $x_1_2 = {4c 8b f9 48 8d 4c 24 38 45 8d 45 30 33 d2 41 8b f9 41 8b f5 4c 89 6c 24 30}  //weight: 1, accuracy: High
        $x_2_3 = {41 ff c1 33 d2 41 8b c0 41 f7 f1 30 11 48 ff c1 45 3b ca 72 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

