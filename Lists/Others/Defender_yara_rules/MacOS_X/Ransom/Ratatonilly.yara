rule Ransom_MacOS_X_Ratatonilly_A_2147722467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS_X/Ratatonilly.A"
        threat_id = "2147722467"
        type = "Ransom"
        platform = "MacOS_X: "
        family = "Ratatonilly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 44 1d 00 b9 59 b6 99 f7 31 c8 41 89 07 41 89 04 1e}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 7c c5 b6 d9 06 e4 dc b6}  //weight: 1, accuracy: High
        $x_2_3 = {80 3c 0b 5f 0f 85 c1 01 00 00 48 b9 00 00 00 00 fe ff ff ff 48 01 c1 48 c1 f9 20 80 3c 0b 45 0f 85 a6 01 00 00 48 b9 00 00 00 00 fd ff ff ff 48 01 c1 48 c1 f9 20 80 3c 0b 4d 0f 85 8b 01 00 00 48 b9 00 00 00 00 fc ff ff ff 48 01 c1 48 c1 f9 20 80 3c 0b 44}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

