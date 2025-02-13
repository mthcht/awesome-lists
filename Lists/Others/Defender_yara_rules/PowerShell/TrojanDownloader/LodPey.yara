rule TrojanDownloader_PowerShell_LodPey_A_2147777715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/LodPey.A"
        threat_id = "2147777715"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "LodPey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 65 00 76 00 32 00 30 00 31 00 2e 00 63 00 64 00 6e 00 69 00 6d 00 61 00 67 00 65 00 73 00 2e 00 78 00 79 00 7a 00 3a 00 38 00 30 00 2f 00 15 00 2f 00 15 00 27 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_LodPey_B_2147777716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/LodPey.B"
        threat_id = "2147777716"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "LodPey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 6e 00 65 00 74 00 63 00 61 00 74 00 6b 00 69 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 73 00 71 00 6c 00 6e 00 65 00 74 00 63 00 61 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 61 00 6d 00 79 00 6e 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 7a 00 65 00 72 00 32 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 7a 00 7a 00 33 00 72 00 30 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 7a 00 65 00 72 00 39 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 61 00 77 00 63 00 6e 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_8 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 61 00 63 00 6b 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_9 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 62 00 36 00 39 00 6b 00 71 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_10 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 62 00 64 00 64 00 70 00 2e 00 6e 00 65 00 74 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_11 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 74 00 72 00 32 00 71 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_12 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 37 00 37 00 36 00 36 00 2e 00 6f 00 72 00 67 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_13 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 65 00 61 00 74 00 75 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

