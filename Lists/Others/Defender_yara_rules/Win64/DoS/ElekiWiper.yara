rule DoS_Win64_ElekiWiper_B_2147944723_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/ElekiWiper.B!dha"
        threat_id = "2147944723"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "ElekiWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 00 49 00 4e 00 46 00 4f 00 5d 00 20 00 53 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 6e 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 00 44 00 4f 00 4e 00 45 00 5d 00 20 00 41 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 64 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 66 00 6f 00 72 00 20 00 77 00 72 00 69 00 74 00 69 00 6e 00 67 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 00 53 00 4b 00 49 00 50 00 5d 00 20 00 4f 00 70 00 74 00 69 00 63 00 61 00 6c 00 20 00 64 00 72 00 69 00 76 00 65 00 20 00 73 00 6b 00 69 00 70 00 70 00 65 00 64 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

