rule PWS_Win32_Jaftipee_A_2147682546_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jaftipee.A"
        threat_id = "2147682546"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaftipee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 01 72 07 3d ff ff 00 00 76 03 6a 15 58 50}  //weight: 2, accuracy: High
        $x_2_2 = {5f 4a 61 76 61 5f ?? 5f 70 61 79 6c 6f 5f 67 65 74 66 74 70 40 38 00}  //weight: 2, accuracy: Low
        $x_1_3 = {5f 4a 61 76 61 5f ?? 5f 70 61 79 6c 6f 5f 65 78 65 63 75 74 65 40 31 32 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2a 00 74 00 6f 00 74 00 61 00 6c 00 2a 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 65 00 72 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2a 00 66 00 69 00 6c 00 65 00 7a 00 69 00 6c 00 6c 00 61 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00 00 00 75 00 73 00 65 00 72 00 00 00 00 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

