rule Trojan_Win64_Helcobtik_A_2147946168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Helcobtik.A"
        threat_id = "2147946168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Helcobtik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 a9 74 64 cf [0-16] c1 ea 06 6b c2 4f}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 a9 74 64 cf [0-16] 66 83 e1 7f 66 89 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Helcobtik_B_2147946363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Helcobtik.B"
        threat_id = "2147946363"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Helcobtik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_1_2 = {da b8 dc 91 [0-5] 18 93 1a 32}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c1 e8 0a 66 83 e1 1c 66 83 e0 0f 66 c1 e1 02 66 0b c8 66 41 89 49 02 0f b7 42 04}  //weight: 1, accuracy: High
        $x_1_4 = {52 00 76 00 c7 ?? ?? ?? 31 00 31 00 c7 ?? ?? ?? 35 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c3 34 5a 48 83 3d ?? ?? ?? 00 00 0f 84 cb 00 00 00 4c 8b d7 4c 8b de 48 83 c4 08 5e 48 8b 7c 24 20}  //weight: 1, accuracy: Low
        $x_1_6 = {eb 24 c7 43 10 05 00 00 00 48 8d 4b 10 e8}  //weight: 1, accuracy: High
        $x_1_7 = {00 20 20 20 20 61 20 20 20 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

