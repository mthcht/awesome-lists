rule PWS_Win32_QQkogdiv_A_2147626103_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQkogdiv.A"
        threat_id = "2147626103"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQkogdiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6a 2e ff d7 8b d0 8d 4d 9c ff d6 50 ff d3 8b d0 8d 4d 98 ff d6 50 6a 63 ff d7 8b d0 8d 4d 94 ff d6 50 ff d3 8b d0 8d 4d 90 ff d6 50 6a 6e}  //weight: 1, accuracy: High
        $x_1_2 = {00 11 62 84 76 0b 7a 8f 5e 5c 00 51 00 51 00 56 00 69 00 64 00 65 00 6f 00 5c 00 51 00 51 00 56 00 69 00 64 00 65 00 6f 00 2e 00 76 00 62 00 70 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {51 51 56 69 64 65 6f 2e 6a 63 62 75 74 74 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {6c 00 6f 00 67 00 69 00 6e 00 2e 00 61 00 73 00 70 00 3f 00 75 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {7b 00 72 00 65 00 67 00 6f 00 6b 00 7d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

