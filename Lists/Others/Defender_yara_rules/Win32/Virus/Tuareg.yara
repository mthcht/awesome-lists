rule Virus_Win32_Tuareg_2147573931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tuareg"
        threat_id = "2147573931"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tuareg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fa 6b 65 72 6e 75 10 8b 56 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 fa 65 6c 33 32 74 0a 83 c3 14 83 e9 14 75}  //weight: 1, accuracy: High
        $x_1_3 = {81 38 2e 72 65 6c 75 15 81 78 04 6f 63 00 00 75 41}  //weight: 1, accuracy: High
        $x_1_4 = {81 38 2e 69 64 61 75 0f 81 78 04 74 61 00 00 75 06}  //weight: 1, accuracy: High
        $x_1_5 = {81 3c 3b 2e 72 73 72}  //weight: 1, accuracy: High
        $x_1_6 = {8b 58 0c 89 5e 28 03 5e 34 89 9d}  //weight: 1, accuracy: High
        $x_1_7 = {2c 19 04 61 8a e0 b0 2e 66 50 b8 2e 3f 74 65}  //weight: 1, accuracy: High
        $x_1_8 = {66 ad 0f b7 d0 e8 72 00 00 00 81 fa 74 62 00 00 74 66 81 fa 73 63 00 00 74 5e}  //weight: 1, accuracy: High
        $x_1_9 = {81 fa 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_10 = {81 fa 2e 73 63 72}  //weight: 1, accuracy: High
        $x_1_11 = "=.cpl" ascii //weight: 1
        $x_1_12 = {66 25 07 07 3a e0 74 f3 c0 e0 03 0a e0 80 cc c0 b0 39 66 ab eb 4d}  //weight: 1, accuracy: High
        $x_1_13 = {b0 55 aa 66 b8 8b ec 66 ab eb}  //weight: 1, accuracy: High
        $x_1_14 = {8a c2 04 58 aa e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

