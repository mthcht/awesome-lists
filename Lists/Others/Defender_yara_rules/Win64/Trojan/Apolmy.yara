rule Trojan_Win64_Apolmy_A_2147688978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Apolmy.A"
        threat_id = "2147688978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Apolmy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 a3 0b 00 00 00 01 00 00 00 b0 04 a2 25 00 00 00 01 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {48 b8 fb ff ff ff 00 00 00 00 48 83 c4 38}  //weight: 1, accuracy: High
        $x_1_3 = {b8 fb ff ff ff 48 83 c4 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Apolmy_C_2147694857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Apolmy.C"
        threat_id = "2147694857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Apolmy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 b9 0b 00 00 00 01 00 00 00 48 8b 44 24 ?? 48 89 01 48 b8 25 00 00 00 01 00 00 00 c6 00 04}  //weight: 2, accuracy: Low
        $x_2_2 = {48 b8 0b 00 00 00 01 00 00 00 48 8b 4c 24 ?? 48 89 08 48 b8 25 00 00 00 01 00 00 00 c6 00 04}  //weight: 2, accuracy: Low
        $x_1_3 = {48 b8 fb ff ff ff 00 00 00 00 48 83 c4 38}  //weight: 1, accuracy: High
        $x_1_4 = {b8 fb ff ff ff 48 83 c4 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

