rule Ransom_Win32_AnglerLocker_B_2147951790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AnglerLocker.B"
        threat_id = "2147951790"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AnglerLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 65 74 20 73 74 6f 70 20 76 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 4c 4f 4e 47 4c 4f 4e 47 20 67 65 74 5f 74 6f 74 61 6c 5f 61 64 64 65 64 5f 66 69 6c 65 73 28 29 3a 20 25 6c 6c 64 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 6f 74 61 6c 5f 66 69 6c 65 5f 68 61 6e 64 6c 65 64 3a 20 64 27 25 6c 6c 64 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {0a 0a 25 6c 73 3a 20 0a 09 68 61 6e 64 6c 65 64 3a 20 25 6c 6c 64 0a 09 61 64 64 65 64 3a 20 20 20 25 6c 6c 64 0a 0a 00}  //weight: 1, accuracy: High
        $x_1_6 = {21 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2d 00 6e 00 6f 00 5f 00 70 00 32 00 68 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

