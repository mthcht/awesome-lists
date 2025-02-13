rule TrojanSpy_Win32_Regpass_A_2147627464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Regpass.A"
        threat_id = "2147627464"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Regpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 65 65 70 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 67 63 6c 65 61 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 69 63 65 20 66 69 6c 65 20 4f 4b 2e 00 00 00 49 6e 20 43 72 65 61 74 65 46 69 6c 65 00 00 00 5c 5c 25 73 5c 61 64 6d 69 6e 24 5c 73 79 73 74 65 6d 33 32 5c 25 73 00 53 75 63 63 65 65 64 21 00 00 00 00 44 65 6c 65 74 65 20 74 65 6d 70 6f 72 61 72 79 20 73 65 72 76 69 63 65 20 66 69 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

