rule TrojanSpy_Win32_Sparsay_A_2147624840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sparsay.gen!A"
        threat_id = "2147624840"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sparsay"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "descblok" ascii //weight: 2
        $x_2_2 = "_2sys.php?PAR0=" ascii //weight: 2
        $x_1_3 = {77 65 62 63 72 79 70 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 6d 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 73 68 65 6c 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 71 6c 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

