rule TrojanSpy_Win32_Sticamint_A_2147634576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sticamint.A"
        threat_id = "2147634576"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sticamint"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 2e 00 77 00 64 00 77 00 [0-22] 67 00 2e 00 6e 00 65 00 74 00 2f 00 6e 00 65 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 2e 00 31 00 37 00 35 00 75 00 [0-22] 75 00 2e 00 63 00 6e 00 2f 00 6e 00 65 00 74 00}  //weight: 1, accuracy: Low
        $x_2_3 = "/dll.aspx?time=" wide //weight: 2
        $x_2_4 = "&INT=" wide //weight: 2
        $x_2_5 = "/stat.aspx" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

