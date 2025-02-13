rule TrojanDropper_Win32_Proxit_A_2147629555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Proxit.A"
        threat_id = "2147629555"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Proxit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 74 00 79 00 70 00 65 00 20 00 25 00 73 00 79 00 73 00 74 00 65 00 6d 00 64 00 72 00 69 00 76 00 65 00 25 00 5c 00 5c 00 62 00 6f 00 6f 00 74 00 2e 00 69 00 6e 00 69 00 3e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 70 79 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 73 5c 64 65 6c 70 68 69 2e 65 78 65 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 6c 6c 63 61 63 68 65 5c 64 65 6c 70 68 69 2e 65 78 65 20 2f 79 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {20 00 73 00 74 00 6f 00 70 00 20 00 52 00 61 00 73 00 41 00 75 00 74 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 52 00 61 00 73 00 41 00 75 00 74 00 6f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

