rule PWS_Win32_Pastodib_A_2147696546_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pastodib.A"
        threat_id = "2147696546"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pastodib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3c 16 2b 75 04 c6 04 16 7c 8b ?? 46 8d ?? 01}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 00 00 00 5c 50 72 6f 66 69 6c 65 73 5c 00 00 5c 00 00 00 30 78 30 30 30 30}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 5c 74 6d 70 00 00 53 79 73 74 65 6d 44 72 69 76 65 00 5c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {50 4f 53 54 20 2f 70 67 61 74 65 2e 70 68 70 3f 69 64 3d 00 3b}  //weight: 1, accuracy: High
        $x_1_5 = ", encryptedPassword from moz_logins" ascii //weight: 1
        $x_1_6 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 60 6c 6f 67 69 6e 73 60 00 00 [0-32] 25 73 21 65 6e 64 21}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 4c 6f 67 69 6e 20 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {70 3d 00 00 62 6c 61 63 6b 2d 74 65 61 6d 2e 75 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 50 61 73 73 77 6f 72 64 73 54 6f 44 42 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_10 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e 00 68 6f 73 74 6e 61 6d 65 00 00 00 00 22 00 00 00 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

