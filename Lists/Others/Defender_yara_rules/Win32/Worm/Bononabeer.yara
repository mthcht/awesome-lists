rule Worm_Win32_Bononabeer_A_2147651444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bononabeer.A"
        threat_id = "2147651444"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bononabeer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 6f 72 65 20 69 37 20 4e 61 62 69 72 65 20 43 6f 6d 6d 75 6e 69 74 69 65 7a 20 3a 3a 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 74 74 69 6e 67 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 69 6c 65 73 3a 20 66 69 6c 6d 20 62 6f 6b 65 70 2e 33 67 70 2c 70 65 72 61 77 61 6e 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 79 6f 2e 6d 61 6b 61 6e 61 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

