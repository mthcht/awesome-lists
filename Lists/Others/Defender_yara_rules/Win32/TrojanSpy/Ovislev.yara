rule TrojanSpy_Win32_Ovislev_A_2147679146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ovislev.A"
        threat_id = "2147679146"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ovislev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "fakerror" ascii //weight: 50
        $x_20_2 = {43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 41 00 75 00 74 00 6f 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 45 00 64 00 69 00 74 00 56 00 69 00 65 00 77 00 00 00 24 00 00 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 4f 00 6d 00 6e 00 69 00 62 00 6f 00 78 00 56 00 69 00 65 00 77 00}  //weight: 20, accuracy: High
        $x_20_3 = {73 00 65 00 6e 00 64 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00 1c 00 00 00 73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 20, accuracy: High
        $x_10_4 = {73 61 6c 76 61 64 6f 73 70 72 6f 61 72 72 61 79 00}  //weight: 10, accuracy: High
        $x_10_5 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 3d 00 6f 00 72 00 6b 00 75 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {6f 00 67 00 69 00 6e 00 2e 00 6c 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 6f 00 00 00}  //weight: 10, accuracy: High
        $x_10_7 = {6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 63 00 68 00 65 00 63 00 6b 00 6f 00 75 00 74 00 2f 00 66 00 6f 00 72 00 6d 00 61 00 00 00}  //weight: 10, accuracy: High
        $x_10_8 = {61 00 6e 00 6b 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 62 00 72 00 67 00 63 00 62 00 2f 00 6a 00 00 00}  //weight: 10, accuracy: High
        $x_10_9 = {62 00 61 00 6e 00 72 00 69 00 73 00 75 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 62 00 72 00 62 00 00 00}  //weight: 10, accuracy: High
        $x_10_10 = {73 00 62 00 63 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 69 00 74 00 65 00 2f 00 63 00 6f 00 00 00}  //weight: 10, accuracy: High
        $x_30_11 = {73 61 6c 76 61 72 6e 6f 76 6f 73 62 61 69 78 61 64 6f 73 00 68 6f 72 61 73 61 69 72 64 6f 73 61 6e 64}  //weight: 30, accuracy: High
        $x_30_12 = "\\triploader.vbp" wide //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 7 of ($x_10_*))) or
            ((1 of ($x_30_*) and 2 of ($x_20_*) and 5 of ($x_10_*))) or
            ((2 of ($x_30_*) and 6 of ($x_10_*))) or
            ((2 of ($x_30_*) and 1 of ($x_20_*) and 4 of ($x_10_*))) or
            ((2 of ($x_30_*) and 2 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_50_*) and 7 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 5 of ($x_10_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 4 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

