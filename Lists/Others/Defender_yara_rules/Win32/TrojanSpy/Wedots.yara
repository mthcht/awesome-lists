rule TrojanSpy_Win32_Wedots_A_2147697026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wedots.A"
        threat_id = "2147697026"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wedots"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s%d_%sHD_%s.plk" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 70 6f 73 74 62 61 6e 6b 2e 63 6f 2e 6b 72 2f 00 68 74 74 70 3a 2f 2f 6b 66 63 63 2e 63 6f 6d 2f 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\profiles.pbk" ascii //weight: 1
        $x_1_4 = {66 72 6f 6d 33 5f 64 6f 77 6e 2d 2d 2d 2d 2d 2d 2d 2d 00}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 14 73 c6 44 24 15 74 c6 44 24 16 65 88 44 24 17 c6 44 24 18 5f c6 44 24 19 64 c6 44 24 1a 6f c6 44 24 1b 77 c6 44 24 1c 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

