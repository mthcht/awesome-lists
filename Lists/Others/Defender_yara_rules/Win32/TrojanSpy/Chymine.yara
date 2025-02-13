rule TrojanSpy_Win32_Chymine_A_2147636565_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Chymine.A"
        threat_id = "2147636565"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chymine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-8] 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {5b 00 4e 00 75 00 6d 00 20 00 4c 00 6f 00 63 00 6b 00 5d 00 [0-8] 5b 00 44 00 6f 00 77 00 6e 00 5d 00 [0-8] 5b 00 52 00 69 00 67 00 68 00 74 00 5d 00 [0-8] 5b 00 55 00 50 00 5d 00 [0-8] 5b 00 4c 00 65 00 66 00 74 00 5d 00 [0-8] 5b 00 50 00 61 00 67 00 65 00 44 00 6f 00 77 00 6e 00 5d 00}  //weight: 2, accuracy: Low
        $x_2_3 = {2e 00 6c 00 6f 00 67 00 [0-8] 25 00 64 00 2e 00 62 00 61 00 6b 00}  //weight: 2, accuracy: Low
        $x_1_4 = {5c 00 54 00 65 00 73 00 74 00 4c 00 70 00 63 00 53 00 63 00 72 00 65 00 65 00 6e 00 57 00 72 00 69 00 74 00 65 00 [0-8] 5c 00 54 00 65 00 73 00 74 00 4c 00 70 00 63 00 53 00 63 00 72 00 65 00 65 00 6e 00 52 00 65 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 [0-8] 5c 00 54 00 65 00 73 00 74 00 4c 00 70 00 63 00 53 00 79 00 73 00 74 00 65 00 6d 00 [0-8] 43 00 56 00 69 00 64 00 65 00 6f 00 43 00 61 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = "%d.%d.%d.%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

