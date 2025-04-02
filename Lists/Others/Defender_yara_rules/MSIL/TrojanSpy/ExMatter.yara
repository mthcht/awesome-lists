rule TrojanSpy_MSIL_ExMatter_SA_2147838601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/ExMatter.SA"
        threat_id = "2147838601"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ExMatter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 00 63 00 20 00 22 00 73 00 74 00 6f 00 70 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 2d 00 69 00 64 00 20 00 7b 00 30 00 7d 00 3b 00 20 00 73 00 74 00 61 00 72 00 74 00 2d 00 73 00 6c 00 65 00 65 00 70 00 [0-16] 3b 00 20 00 73 00 65 00 74 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 20 00 2d 00 70 00 61 00 74 00 68 00 20 00 27 00 7b 00 31 00 7d 00 27 00 20 00 2d 00 76 00 61 00 6c 00 75 00 65 00 20 00 30 00}  //weight: 2, accuracy: Low
        $x_2_2 = {2d 63 20 22 73 74 6f 70 2d 70 72 6f 63 65 73 73 20 2d 69 64 20 7b 30 7d 3b 20 73 74 61 72 74 2d 73 6c 65 65 70 [0-16] 3b 20 73 65 74 2d 63 6f 6e 74 65 6e 74 20 2d 70 61 74 68 20 27 7b 31 7d 27 20 2d 76 61 6c 75 65 20 30}  //weight: 2, accuracy: Low
        $x_1_3 = {6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 [0-32] 72 00 65 00 6d 00 6f 00 74 00 65 00 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 65 74 77 6f 72 6b [0-32] 72 65 6d 6f 74 65 70 61 74 68}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 70 00 64 00 66 00 [0-32] 2e 00 64 00 6f 00 63 00 [0-32] 2e 00 64 00 6f 00 63 00 78 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 70 64 66 [0-32] 2e 64 6f 63 [0-32] 2e 64 6f 63 78}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 00 73 00 71 00 6c 00 [0-32] 2e 00 6d 00 73 00 67 00 [0-32] 2e 00 70 00 73 00 74 00 [0-32] 2e 00 64 00 77 00 67 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 73 71 6c [0-32] 2e 6d 73 67 [0-32] 2e 70 73 74 [0-32] 2e 64 77 67}  //weight: 1, accuracy: Low
        $x_1_9 = "We have {0} to upload and {1} completed" ascii //weight: 1
        $x_1_10 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-5] 2f 00 64 00 61 00 74 00 61 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_11 = {68 74 74 70 3a 2f 2f [0-5] 2f 64 61 74 61 2f}  //weight: 1, accuracy: Low
        $x_1_12 = {73 00 79 00 6e 00 63 00 [0-16] 2e 00 70 00 64 00 70 00}  //weight: 1, accuracy: Low
        $x_1_13 = {73 79 6e 63 [0-16] 2e 70 64 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_ExMatter_G_2147937592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/ExMatter.G"
        threat_id = "2147937592"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ExMatter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {54 69 6e 79 49 70 63 2e 49 4f 00 61 64 64 5f 46 69 6c 65 55 70 64 61 74 65 64 00 72 65 6d 6f 76 65 5f 46 69 6c 65 55 70 64 61 74 65 64 00}  //weight: 2, accuracy: High
        $x_1_2 = {5c 62 69 6e 5c 44 65 62 75 67 5c 53 69 6e 67 6c 65 46 69 6c 65 ?? 70 64 62}  //weight: 1, accuracy: Low
        $x_2_3 = {2d 00 69 00 70 00 63 00 00 11 2d 00 69 00 70 00 63 00 70 00 72 00 65 00 66 00 00 0b 2d 00 70 00 61 00 74 00 68 ?? 00 15 2d 00 6e 00 6f 00 72 00 65 00 77 00 72 00 69 00 74 00 65 00 00 05 2d 00 77 00}  //weight: 2, accuracy: Low
        $x_1_4 = {43 6c 69 65 6e 74 00 57 65 62 44 41 56 43 6c 69 65 6e 74 00 4f 62 6a 65 63 74 00 49 44 69 73 70 6f 73 61 62 6c 65 ?? 6d 5f 70 72 6f 70 46 69 6e 64 4d 65 74 68 6f 64 00 48 74 74 70 4d 65 74 68 6f 64 00 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

