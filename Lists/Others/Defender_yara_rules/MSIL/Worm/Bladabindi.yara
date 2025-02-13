rule Worm_MSIL_Bladabindi_D_2147681342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Bladabindi.gen!D"
        threat_id = "2147681342"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 07 72 c4 01 00 70 2b 05}  //weight: 1, accuracy: High
        $x_1_2 = {72 e4 01 00 70}  //weight: 1, accuracy: High
        $x_1_3 = {72 be 01 00 70}  //weight: 1, accuracy: High
        $x_1_4 = {72 b6 01 00 70}  //weight: 1, accuracy: High
        $x_1_5 = {72 7c 02 00 70}  //weight: 1, accuracy: High
        $x_10_6 = {20 e9 01 00 00 20 8b 01 00 00 28 10 00 00 06 25 14 fe 06 03 00 00 06 73 07 00 00 0a 20 ea 03 00 00 20 f1 03 00 00 16 2c 2a 26 26}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Bladabindi_F_2147683820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Bladabindi.F"
        threat_id = "2147683820"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 23 00 00 04 2d 24 02 02 25 fe 07 4d 00 00 06 73 34 00 00 0a 17 73 35 00 00 0a 7d 23 00 00 04 02 7b 23 00 00 04 6f c0 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {1f 14 3c 25 01 00 00 02 07 08 02 08 28 cf 00 00 0a 6f 4f 00 00 06 6f 4e 00 00 06 26 06 7b 27 00 00 04 08}  //weight: 1, accuracy: High
        $x_1_3 = {03 6f c4 00 00 0a 04 73 20 00 00 0a 6f a8 00 00 0a 72 7d 08 00 70 28 3b 00 00 0a 28 a7 00 00 0a de 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

