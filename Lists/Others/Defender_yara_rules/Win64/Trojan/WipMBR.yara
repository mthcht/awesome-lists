rule Trojan_Win64_WipMBR_A_2147660573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WipMBR.A"
        threat_id = "2147660573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WipMBR"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 69 00 6e 00 66 00 5c 00 6e 00 65 00 74 00 66 00 74 00 ?? ?? ?? ?? ?? ?? 2e 00 70 00 6e 00 66 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {45 00 24 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {48 8b cf ff d0 85 c0 75 ?? 8d 50 30 33 c9 44 8d 48 04 41 b8 00 30 00 00 ff 15 ?? ?? ?? ?? 4c 8b d8 b3 01 48 85 c0 74 ?? 8b 4d ?? 89 48 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {57 ff d0 3b c3 74 05 88 5d ?? eb ?? 6a 04 68 00 30 00 00 6a 30 53 ff 15 ?? ?? ?? ?? 8b f0 3b f3 74 ?? 8b 45 ?? 89 46 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_WipMBR_A_2147660605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WipMBR.gen!A"
        threat_id = "2147660605"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WipMBR"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 06 3c 45 0f 84 ?? ?? ?? ?? 3c 54 0f 85 ?? ?? ?? ?? 4c 8d 0d}  //weight: 2, accuracy: Low
        $x_1_2 = "/ajax_modal/modal/data.asp" wide //weight: 1
        $x_2_3 = {83 e0 03 41 b8 01 00 00 00 48 8b cd 42 0f b6 04 28 4c 89 74 24 20 32 06 88 84 24 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff c3 48 ff c6}  //weight: 2, accuracy: Low
        $x_1_4 = {15 af 52 f0 a0 ff ca 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

