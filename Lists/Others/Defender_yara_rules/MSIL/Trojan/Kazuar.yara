rule Trojan_MSIL_Kazuar_B_2147959330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kazuar.B!dha"
        threat_id = "2147959330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 63 72 65 73 65 ?? 76 65 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 61 75 6c 74 48 61 6e 64 6c 65 00 66 69 6c ?? 68 61 6e 64 6c 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 75 6e 6e 61 6d 65 00 61 70 70 ?? 61 6d 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {63 6f 6d 6d 69 74 73 69 7a 65 00 76 69 ?? 77 73 69 7a 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {77 69 6e 6e 61 6d 00 63 6c 73 6e ?? 6d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {63 6c 73 6e 61 6d 00 6c 70 ?? 72 61 6d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 6c 67 69 74 65 6d 00 4f 70 65 72 61 74 ?? 6e 67 53 79 73 74 65 6d 00}  //weight: 1, accuracy: Low
        $x_1_8 = {69 6e 66 6c 65 6e 00 62 75 66 6c ?? 6e 00}  //weight: 1, accuracy: Low
        $x_1_9 = {6d 61 78 63 6c 73 6c ?? 6e 00}  //weight: 1, accuracy: Low
        $x_1_10 = {67 50 61 64 64 69 6e 67 49 ?? 66 6f 00}  //weight: 1, accuracy: Low
        $x_1_11 = {74 6f 6b 69 6e ?? 6f 00}  //weight: 1, accuracy: Low
        $x_1_12 = {63 68 69 6c 64 61 66 74 65 72 00 58 6d 6c 57 72 ?? 74 65 72 00}  //weight: 1, accuracy: Low
        $x_1_13 = {70 61 73 73 77 6f 72 64 56 61 ?? 6c 74 50 74 72 00}  //weight: 1, accuracy: Low
        $x_1_14 = {73 65 63 61 74 74 72 00 61 6c 6c 6f ?? 61 74 74 72 00}  //weight: 1, accuracy: Low
        $x_1_15 = {61 6c 6c 6f 63 61 74 74 72 00 70 72 6f ?? 61 74 74 72 00}  //weight: 1, accuracy: Low
        $x_1_16 = {70 72 6f 63 61 74 74 72 00 74 68 72 61 ?? 74 72 00}  //weight: 1, accuracy: Low
        $x_1_17 = {74 68 72 61 74 74 72 00 67 65 74 5f 48 6f ?? 72 00}  //weight: 1, accuracy: Low
        $x_1_18 = {63 68 68 63 6c 73 00 63 ?? 6c 73 00}  //weight: 1, accuracy: Low
        $x_1_19 = {7a 65 72 6f 62 69 74 73 00 73 65 74 5f 41 72 67 75 ?? 65 6e 74 73 00}  //weight: 1, accuracy: Low
        $x_1_20 = {61 70 63 73 74 61 74 75 73 00 6e 74 73 ?? 61 74 75 73 00}  //weight: 1, accuracy: Low
        $x_1_21 = {73 65 63 6f ?? 66 73 65 74 00}  //weight: 1, accuracy: Low
        $x_1_22 = {73 65 63 74 69 6e 68 65 ?? 69 74 00}  //weight: 1, accuracy: Low
        $x_1_23 = {6d 61 78 69 6e 73 74 00 67 65 74 5f 48 ?? 73 74 00}  //weight: 1, accuracy: Low
        $x_1_24 = {43 72 65 61 74 65 4e 6f 57 69 ?? 64 6f 77 00 63 6d 64 73 68 6f 77 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

