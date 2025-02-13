rule TrojanSpy_Win32_GreenCollector_A_2147904755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/GreenCollector.A"
        threat_id = "2147904755"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "GreenCollector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 70 00 64 00 66 00 00 00 00 00 6a 00 70 00 67 00 00 00 2e 00 78 00 6c 00 73 00 00 00 00 00 2e 00 78 00 6c 00 73 00 78 00 00 00 2e 00 64 00 6f 00 63 00 00 00 00 00 64 00 6f 00 63 00 78 00 00 00 00 00 2e 00 74 00 69 00 66 00 00 00 00 00 2e 00 6d 00 73 00 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 72 72 6f 72 00 00 00 63 68 6f 6f 73 65 20 64 69 73 6b 20 69 6e 20 63 6d 64 20 61 72 67 75 6d 65 6e 74 73 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

