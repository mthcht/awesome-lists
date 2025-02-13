rule TrojanProxy_Win32_Extats_A_2147686399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Extats.A"
        threat_id = "2147686399"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Extats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {52 65 63 76 28 29 20 66 61 69 6c 65 64 2e 00 00 52 65 63 76 28 29 2e 20 4e 6f 74 20 63 6f 6e 65 63 74 65 64 2e 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 65 6e 64 28 29 20 66 61 69 6c 65 64 2e 20 54 6f 74 61 6c 20 73 65 6e 74 20 6c 65 73 73 20 74 68 65 6e 20 6e 65 65 64 65 64 2e 00}  //weight: 10, accuracy: High
        $x_1_3 = {74 63 70 3a 2f 2f 73 65 72 76 65 72 39 2e 73 73 32 2e 6e 61 6d 65 3a 34 34 33 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 63 70 3a 2f 2f 39 31 2e 32 30 37 2e 37 2e 31 33 34 3a 34 34 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

