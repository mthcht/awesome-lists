rule TrojanSpy_Win32_Nabuct_A_2147636729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nabuct.A"
        threat_id = "2147636729"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabuct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 6c 75 67 69 6e 5f 73 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 2f 5f 72 65 71 2f 3f 74 79 70 65 3d 25 63 26 73 69 64 3d 25 64 26 73 77 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 2e 73 75 70 70 6f 72 74 2f 77 69 6e 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 76 67 75 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 5f 72 65 71 2f 3f 74 79 70 65 3d 65 26 73 69 64 3d 32 26 73 77 3d 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 26 6f 73 74 79 70 65 3d 32 26 6f 73 73 70 3d 32 26 6f 73 62 69 74 73 3d 30 26 6f 73 66 77 74 79 70 65 3d 32 26 6f 73 72 69 67 68 74 73 3d 32 35 35 00}  //weight: 1, accuracy: High
        $x_1_6 = {47 6c 6f 62 61 6c 5c 70 72 65 63 73 61 67 70 63 77 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

