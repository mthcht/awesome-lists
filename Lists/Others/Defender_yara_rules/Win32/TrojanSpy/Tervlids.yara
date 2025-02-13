rule TrojanSpy_Win32_Tervlids_A_2147696576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tervlids.A"
        threat_id = "2147696576"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tervlids"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 10 ff d7 6a 14 8b f0 ff d7 81 e6 00 80 00 00 68 90 00 00 00 81 fe 00 80 00 00 0f 94 c3 24 01 3c 01 0f 94 44 24 13 ff d7 24 01 3c 01 8b 44 24 14 0f 94 c1 83 f8 30 7c 57}  //weight: 2, accuracy: High
        $x_1_2 = {5f 6e 74 73 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 3c 25 73 3e 3e 5b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

