rule Ransom_Win32_WinPlock_A_2147692190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WinPlock.A"
        threat_id = "2147692190"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WinPlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pay OK! ChangeWallpaper and decode!" wide //weight: 1
        $x_1_2 = {57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 20 00 63 00 68 00 61 00 6e 00 67 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 00 6f 00 72 00 6b 00 5c 00 63 00 6c 00 6f 00 63 00 6b 00 5c 00 50 00 43 00 6c 00 6f 00 63 00 6b 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 74 00 61 00 72 00 74 00 20 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {55 00 41 00 43 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 22 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 22 00 2c 00 20 00 22 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 33 00 66 00 72 00 7c 00 2e 00 61 00 63 00 63 00 64 00 62 00 7c 00 2e 00 61 00 69 00 7c 00 2e 00 61 00 72 00 77 00 7c 00 2e 00 62 00 61 00 79 00 7c 00 2e 00 63 00 64 00 72 00 7c 00 2e 00 63 00 65 00 72 00 7c 00 2e 00 63 00 72 00 32 00 7c 00 2e 00 63 00 72 00 74 00 7c 00 2e 00 63 00 72 00 77 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 00 69 00 6e 00 63 00 6c 00 77 00 70 00 2e 00 6a 00 70 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "onion_cab_iKnowShit=" wide //weight: 1
        $x_1_9 = {5c 00 65 00 6e 00 63 00 5f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 00 63 00 6c 00 6f 00 63 00 6b 00 5f 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {45 00 72 00 72 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 6c 00 69 00 73 00 74 00 21 00 20 00 53 00 6f 00 72 00 72 00 79 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

