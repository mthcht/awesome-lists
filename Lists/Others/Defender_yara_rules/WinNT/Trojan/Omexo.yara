rule Trojan_WinNT_Omexo_A_2147626896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Omexo.A"
        threat_id = "2147626896"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3e b8 75 05 8b 46 01 eb 03 83 c8 ff}  //weight: 1, accuracy: High
        $x_1_2 = {b9 90 90 90 00 03 ce 0f c9 8b 74 24 10 f0 0f c7 0e}  //weight: 1, accuracy: High
        $x_2_3 = {c7 03 50 55 54 41}  //weight: 2, accuracy: High
        $x_3_4 = {74 0a 8d 72 34 b9 02 00 00 00 f3 a5 89 d7 68 90 7d 33 50 e8 6a 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Omexo_D_2147631677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Omexo.D"
        threat_id = "2147631677"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 03 8b 70 01 6a 00 89 35 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {74 1a 0f b7 57 06 83 c6 01 83 c3 28 3b f2 72 e0 5f 5e 5d b8 25 02 00 c0}  //weight: 1, accuracy: High
        $x_1_3 = {bf 03 00 00 f0 eb 05 bf 01 00 00 f0}  //weight: 1, accuracy: High
        $x_1_4 = {17 00 ca 5a 59 5a 5a 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Omexo_F_2147645482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Omexo.F"
        threat_id = "2147645482"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 19 0f b7 47 06 83 45 fc 28 46 3b f0 72 e2 b8 25 02 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {53 b8 30 00 df ff 6a 02 8d 50 02 5b 66 8b 08 03 c3}  //weight: 1, accuracy: High
        $x_1_3 = {bf 03 00 00 f0 eb 05 bf 01 00 00 f0}  //weight: 1, accuracy: High
        $x_1_4 = {17 00 ca 5a 59 5a 5a 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

