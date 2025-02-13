rule TrojanSpy_Win32_Ingok_A_2147716295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ingok.A"
        threat_id = "2147716295"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ingok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 63 68 65 63 6b 65 72 5f 63 61 6c 6c 2f 67 65 74 5f 70 6f 73 74 2e 70 68 70 3f 67 61 74 65 3d 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 6f 66 69 6c 65 73 2f 2f 00 00 66 69 72 65 66 6f 78 5f 6c 69 6e 6b 73 28 29 3a 20 66 69 72 65 66 6f 78 20 63 6f 6f 6b 69 65 73 20 66 6f 75 6e 64 3a 20 00 00 00 00 63 6f 6f 6b 69 65 5f 63 68 65 63 6b 2e 70 61 79 70 61 6c 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 68 72 6f 6d 65 5f 6c 69 6e 6b 73 28 29 3a 20 63 68 72 6f 6d 65 20 65 78 65 20 65 78 69 73 74 00 00 00 00 79 65 73 00 2f 2f 47 6f 6f 67 6c 65 2f 2f 43 68 72 6f 6d 65 2f 2f 55 73 65 72 20 44 61 74 61 2f 2f 44 65 66 61 75 6c 74 2f 2f 43 6f 6f 6b 69 65 73 00 00 00 63 68 72 6f 6d 65 5f 6c 69 6e 6b 73 28 29 3a 20 63 68 72 6f 6d 65 20 63 6f 6f 6b 69 65 73 20 66 6f 75 6e 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 61 69 6e 28 29 3a 20 50 4f 53 54 5f 69 64 20 63 72 65 61 74 65 64 00 6d 61 69 6e 28 29 3a 20 50 4f 53 54 5f 70 72 6f 63 65 73 73 6f 72 20 63 72 65 61 74 65 64 00 00 6d 61 69 6e 28 29 3a 20 50 4f 53 54 5f 63 6f 72 65 73 20 63 72 65 61 74 65 64 00 00 6d 61 69 6e 28 29 3a 20 50 4f 53 54 5f 72 61 6d 20 63 72 65 61 74 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

