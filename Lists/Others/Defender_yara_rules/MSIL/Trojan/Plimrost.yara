rule Trojan_MSIL_Plimrost_A_2147705536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Plimrost.A"
        threat_id = "2147705536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Plimrost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 00 70 a2 25 17 72 ?? 02 00 70 a2 25 18 72 ?? 02 00 70 a2 25 19 72 ?? ?? 00 70 a2 25 1a 72 ?? ?? 00 70 a2 25 1b 72 ?? ?? 00 70 a2 03 00 16 72}  //weight: 6, accuracy: Low
        $x_1_2 = {05 73 00 73 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {07 6d 00 6f 00 6e 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {07 6d 00 67 00 72 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {05 73 00 76 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {07 73 00 76 00 63 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {09 68 00 6f 00 73 00 74 00 00}  //weight: 1, accuracy: High
        $x_3_8 = {2f 00 63 00 20 00 72 00 65 00 67 00 20 00 61 00 64 00 64 00 [0-2] 20 00 22 00 7b 00 30 00 7d 00 22 00 20 00 2f 00 76 00 20 00 22 00 7b 00 31 00 7d 00 22 00 20 00 2f 00 64 00 20 00 22 00 7b 00 32 00 7d 00 22 00 20 00 2f 00 66 00 00}  //weight: 3, accuracy: Low
        $x_6_9 = {0c 08 07 61 0c 08 66 0c 08 17 58 0c 08 07 58 0c 08 20 ?? ?? ?? ?? 58 0c 08 20 ?? ?? ?? ?? 61 0c 06 16 07 6f}  //weight: 6, accuracy: Low
        $x_6_10 = {0c 08 07 61 0c 08 20 ?? ?? ?? ?? 59 0c 08 07 61 0c 08 66 0c 06 16 07 6f}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_6_*) and 6 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Plimrost_B_2147705537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Plimrost.B"
        threat_id = "2147705537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Plimrost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 7e 15 00 00 04 a2 25 17 7e 17 00 00 04 a2 25 18 7e 19 00 00 04 a2 25 19 7e 1b 00 00 04 a2 25 1a 7e 1d 00 00 04 a2 25 1b 7e 1f 00 00 04 a2}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 17 2b 0d 00 2c 03 00 2b 0d 17 2c 07 2b f0 2b 02 2b f1 00 16 2d ea 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {0c 08 17 58 0c 08 07 61 0c 08 17 59 0c 08 07 59 0c 08 07 58 0c 08 20 ?? ?? ?? ?? 61 0c 08 20 ?? ?? ?? ?? 58 0c 06 16 07 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {15 7b 00 30 00 7d 00 7b 00 31 00 7d 00 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

