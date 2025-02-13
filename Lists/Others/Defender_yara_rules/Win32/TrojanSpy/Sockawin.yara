rule TrojanSpy_Win32_Sockawin_A_2147601764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sockawin.A"
        threat_id = "2147601764"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sockawin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WinsockMUTEX102" ascii //weight: 2
        $x_2_2 = {50 61 63 6b 65 64 43 61 74 61 6c 6f 67 49 74 65 6d 00 00 00 25 75 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 69 6e 53 6f 63 6b 32 5c 57 69 6e 73 6f 63 6b 5f 53 70 69 00 00 ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "home.asp?act=a11111111&fs=%d&fp=%s&fn=%s" ascii //weight: 1
        $x_1_4 = "%s/home.asp?type=web&act=c33333333&fp=%s&fn=%s" ascii //weight: 1
        $x_1_5 = {6d 73 77 73 6f 63 6b 2e 64 6c 6c 90 5c 44 6f 77 6e 6c 6f 61 64 65 64 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 8b c0 8c 9b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

