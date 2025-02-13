rule Trojan_Win64_Ransodoppo_STA_2147779006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ransodoppo.STA"
        threat_id = "2147779006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ransodoppo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 40 05 66 [0-10] 00 c6 40 06 61 [0-10] 00 c6 40 07 63 [0-10] 00 c6 40 08 65}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 69 48 8b 05 ?? ?? ?? ?? c6 40 01 6e [0-10] c6 40 02 74 [0-10] c6 40 03 65 [0-10] c6 40 04 72}  //weight: 1, accuracy: Low
        $x_2_3 = {b9 66 00 00 00 [0-16] b9 61 00 00 00 [0-16] b9 63 00 00 00 [0-16] b9 65 00 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = {48 83 c0 04 48 89 05 2a 00 e8 ?? ff ff ff 48 8d 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8b 05}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 0c 08 48 8b 05 ?? ?? ?? ?? 0f b6 14 18 03 d1 8b 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08 48 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 00 6b 65 72 6e 65 6c 33 32 00 00 00 00 21 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Ransodoppo_LK_2147843796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ransodoppo.LK!MTB"
        threat_id = "2147843796"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ransodoppo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 08 48 8b 05 ?? ?? ?? 00 0f b6 14 38 03 d1 8b 0d ?? ?? ?? 00 48 8b 05 ?? ?? ?? 00 88 14 08 8b 05 ?? ?? ?? 00 83 c0 01 89 05}  //weight: 1, accuracy: Low
        $x_1_2 = {03 14 24 8b 0c 24 48 8b 44 24 20 89 14 08 8b 14 24 8b 0c 24 81 c1 e9 03 00 00 48 8b 44 24 20 8b 14 10 33 d1 8b 0c 24 48 8b 44 24 20 89 14 08 eb b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

