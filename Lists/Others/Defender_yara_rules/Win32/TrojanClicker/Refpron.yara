rule TrojanClicker_Win32_Refpron_A_2147611831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Refpron.A"
        threat_id = "2147611831"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "R:MyFireClick" wide //weight: 2
        $x_2_2 = {61 00 64 00 6c 00 69 00 6e 00 6b 00 00 00 00 00 0a 00 00 00 63 00 6c 00 69 00 63 00 6b 00 00 00 0c 00 00 00 69 00 73 00 68 00 69 00 74 00 73 00}  //weight: 2, accuracy: High
        $x_2_3 = {73 00 75 00 62 00 74 00 79 00 70 00 65 00 00 00 0c 00 00 00 69 00 6d 00 67 00 73 00 72 00 63 00 00 00 00 00 0a 00 00 00 61 00 68 00 72 00 65 00 66 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 00 6e 00 72 00 6e 00 64 00 66 00 6f 00 72 00 63 00 74 00 72 00 32 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = {00 00 6f 00 62 00 6a 00 4c 00 69 00 6e 00 6b 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 68 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Refpron_2147626994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Refpron"
        threat_id = "2147626994"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 00 00 00 02 00 00 00 68 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 77}  //weight: 5, accuracy: High
        $x_5_2 = {6e 00 72 00 00 00 00 00 02 00 00 00 31 00 00 00 02 00 00 00 32 00 00 00 02 00 00 00 34 00 00 00 02 00 00 00 33}  //weight: 5, accuracy: High
        $x_10_3 = {68 00 00 00 02 00 00 00 74 00 00 00 02 00 00 00 70 00 00 00 02 00 00 00 61 00 00 00 02 00 00 00 62 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 75 00 00 00 02 00 00 00 3a 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 6e 00 00 00 02 00 00 00 6b 00 00 00 02 00 00 00 49 00 00 00 02 00 00 00 73 00 00 00 02 00 00 00 2e}  //weight: 10, accuracy: High
        $x_1_4 = {6c 00 69 00 6e 00 6b 00 73 00 00 00 68 00 72 00 65 00 66 00 00 00 00 00 6f 00 75 00 74 00 65 00 72 00 48 00 54 00 4d 00 4c 00 00 00 54 00 61 00 72 00 67 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 00 61 00 76 00 69 00 67 00 61 00 74 00 65 00 00 00 00 00 46 00 69 00 72 00 65 00 45 00 76 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {6f 00 6e 00 6d 00 6f 00 75 00 73 00 65 00 6f 00 75 00 74 00 [0-8] 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6f 00 6e 00 6d 00 6f 00 75 00 73 00 65 00 6f 00 75 00 74 00 [0-8] 66 00 6f 00 63 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_8 = {67 00 65 00 74 00 45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 73 00 42 00 79 00 54 00 61 00 67 00 4e 00 61 00 6d 00 65 00 00 00 00 00 6c 00 65 00 6e 00 67 00 74 00 68 00 00 00 00 00 73 00 72 00 63 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Refpron_H_2147631419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Refpron.H"
        threat_id = "2147631419"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 6e 00 72 00 6e 00 64 00 66 00 6f 00 72 00 63 00 74 00 72 00 32 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 69 00 72 00 63 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 00 69 00 73 00 68 00 69 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 61 00 64 00 6c 00 69 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_2_5 = {00 00 73 00 74 00 79 00 6c 00 65 00 2e 00 62 00 65 00 68 00 61 00 76 00 69 00 6f 00 72 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

