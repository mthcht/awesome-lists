rule Trojan_Win64_Cipduk_STA_2147942962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cipduk.STA"
        threat_id = "2147942962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cipduk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_2_2 = {52 00 45 00 c7 [0-3] 4e 00 54 00 c7 [0-3] 5f 00 4e 00 c7 [0-3] 41 00 4d 00 c7 [0-3] 45 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {41 00 4e 00 c7 [0-3] 44 00 5f 00 c7 [0-3] 4c 00 49 00 c7 [0-3] 4e 00 45 00}  //weight: 2, accuracy: Low
        $x_2_4 = {6e 74 64 6c 66 c7 [0-3] 6c 00}  //weight: 2, accuracy: Low
        $x_1_5 = {54 b8 b9 1a}  //weight: 1, accuracy: High
        $x_1_6 = {78 1f 20 7f}  //weight: 1, accuracy: High
        $x_1_7 = {62 34 89 5e}  //weight: 1, accuracy: High
        $x_1_8 = {73 80 48 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

