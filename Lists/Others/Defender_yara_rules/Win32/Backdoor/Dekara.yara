rule Backdoor_Win32_Dekara_A_2147649509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dekara.A"
        threat_id = "2147649509"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dekara"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {54 10 40 00 09 75 54 43 50 46 6c 6f 6f 64 8b c0}  //weight: 3, accuracy: High
        $x_1_2 = {72 65 76 72 65 53 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {3d 64 69 77 68 3f 70 68 70 2e 74 63 65 6e 6e 6f 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {5d 70 6f 74 73 5f 70 74 74 68 5b 00}  //weight: 1, accuracy: High
        $x_1_5 = {5d 74 72 61 74 73 65 72 5b 00}  //weight: 1, accuracy: High
        $x_1_6 = {5d 65 74 61 64 70 75 5b 00}  //weight: 1, accuracy: High
        $x_1_7 = {5d 6c 6c 61 74 73 6e 69 6e 75 5b 00}  //weight: 1, accuracy: High
        $x_1_8 = {5d 78 65 6c 64 5b 00}  //weight: 1, accuracy: High
        $x_1_9 = {5d 74 69 73 69 76 5b 00}  //weight: 1, accuracy: High
        $x_1_10 = {46 32 46 32 41 33 30 37 34 37 34 37 38 36 00}  //weight: 1, accuracy: High
        $x_1_11 = {67 72 61 62 62 65 72 2d 63 6f 6e 6e 65 63 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_12 = {2e 68 61 72 64 63 6f 72 65 70 6f 72 6e 2e 63 6f 6d 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

