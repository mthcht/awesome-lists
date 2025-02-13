rule TrojanSpy_Win32_Heeshnik_A_2147711657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Heeshnik.A"
        threat_id = "2147711657"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Heeshnik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 65 74 50 63 49 6e 66 6f 7c 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 6e 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 7c 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 74 61 74 75 73 7c 4b 65 79 20 4c 6f 67 67 65 72 20 45 6e 61 62 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 74 61 74 75 73 7c 4b 65 79 20 4c 6f 67 67 65 72 20 44 69 73 61 62 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {3c 73 70 65 63 69 61 6c 6b 65 79 3e 5b 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 6c 69 70 62 6f 61 72 64 7c 5b 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 69 6e 67 6c 65 4b 65 79 7c 00}  //weight: 1, accuracy: High
        $x_1_8 = {4f 66 66 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 7c 53 74 61 72 74 7c 00}  //weight: 1, accuracy: High
        $x_1_9 = {55 6e 69 74 4b 65 79 4c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_10 = {75 53 79 73 74 65 6d 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_11 = {6d 55 6e 69 74 4f 66 66 6c 69 6e 65 4b 65 79 4c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

