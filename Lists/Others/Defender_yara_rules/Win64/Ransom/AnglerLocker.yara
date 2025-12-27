rule Ransom_Win64_AnglerLocker_A_2147951789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AnglerLocker.A"
        threat_id = "2147951789"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AnglerLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 4c 4f 4e 47 4c 4f 4e 47 20 67 65 74 5f 74 6f 74 61 6c 5f 61 64 64 65 64 5f 66 69 6c 65 73 28 29 3a 20 25 6c 6c 64 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 6f 74 61 6c 5f 66 69 6c 65 5f 68 61 6e 64 6c 65 64 3a 20 64 27 25 6c 6c 64 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 65 00 6c 00 66 00 5f 00 64 00 65 00 6c 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 00 65 00 70 00 6f 00 72 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 00 71 00 6c 00 73 00 65 00 72 00 76 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 00 73 00 44 00 74 00 73 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {56 00 73 00 73 00 57 00 72 00 69 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

