rule Trojan_MSIL_Pobfeaua_A_2147941233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pobfeaua.A"
        threat_id = "2147941233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pobfeaua"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c}  //weight: 10, accuracy: High
        $x_1_2 = {4c 8b d1 49 bb b8 41 ff e3}  //weight: 1, accuracy: High
        $x_1_3 = {4c 89 e1 00 00 00 00 00 55 89 e5 00}  //weight: 1, accuracy: High
        $x_1_4 = {e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb 66 8c d8 8e d0}  //weight: 1, accuracy: High
        $x_1_5 = {48 b9 49 b8 49 b9 83 f9 00 74 10 41 8a 01 41 88 00 49 ff c0 49 ff c1 ff c9 eb eb}  //weight: 1, accuracy: High
        $x_1_6 = {55 8b ec bb b9 49 ff 74 8d 08 75 f9 e8 00 00 00 00 58 83 c0 15 50 b8 64 8b 15 ff e3 8d 64 24 04 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_7 = {67 48 8b 4d 10 67 48 8b 55 18 67 4c 8b 45 20 67 4c 8b 4d 28 67 48 8b 45 30 67 48 8b 7d 38 48 85 c0 74 16 48 8d 7c c7 f8 48 85 c0 74 0c ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

