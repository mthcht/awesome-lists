rule PWS_Win32_Pesky_A_2147690418_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pesky.A"
        threat_id = "2147690418"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pesky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 21 4e 65 74 57 69 72 65 32 30 31 34 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 4f 46 54 57 41 52 45 5c 4d 6f 7a 69 6c 6c 61 5c 25 73 5c 25 73 5c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 50 4f 50 33 20 50 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 49 4d 41 50 20 50 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 48 54 54 50 20 50 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 53 4d 54 50 20 50 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 25 64 3a 25 49 36 34 75 3a 25 73 25 73 3b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

