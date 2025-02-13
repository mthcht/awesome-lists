rule Backdoor_Win32_Boomie_A_2147653435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Boomie.A"
        threat_id = "2147653435"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Boomie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 70 02 00 00 c6 45 d0 01 89 75 dc c7 45 e0 f8 24 01 00 c7 45 e4 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {88 4c 24 27 88 4c 24 37 b3 5c b2 72 b0 6e 8d 4c 24 54 c6 44 24 10 53}  //weight: 1, accuracy: High
        $x_1_3 = {2f 73 68 6f 77 61 72 74 69 63 6c 65 2e 61 73 70 3f 69 64 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 3a 5c 58 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {5a 7a 68 00 25 75 4d 42 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 25 58 25 69 25 58 25 69 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

