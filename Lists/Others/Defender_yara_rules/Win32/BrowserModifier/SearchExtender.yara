rule BrowserModifier_Win32_SearchExtender_15296_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SearchExtender"
        threat_id = "15296"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SearchExtender"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 db 83 c4 10 39 1d 30 41 00 10 0f 85 93 01 00 00 39 1d 34 41 00 10 0f 85 87 01 00 00 57 53 8d 8d a0 f6 ff ff e8 13 ff ff ff 68 19 00 02 00 8d 45 b4 50 bf 01 00 00 80 57 8d 8d a0 f6 ff ff e8 a0 fe ff ff 84 c0 74 3b 8d 45 f4 50 8d 8d a0 f6 ff ff e8 0e ff ff ff 84 c0 74 28 83 bd ac fe ff ff 03 75 1f 83 bd a8 fe ff ff 08 75 16 8b 85 a4 fa ff ff a3 30 41 00 10 8b 85 a8 fa ff}  //weight: 2, accuracy: High
        $x_1_2 = {59 68 06 00 02 00 8d 45 d0 50 68 02 00 00 80 8d 8d c0 f6 ff ff e8 f3 fc ff ff 84 c0 74 5f 8d 85 d0 fe ff ff 68}  //weight: 1, accuracy: High
        $x_3_3 = {67 2d fa 54 25 d1 aa ad ae cd ae e2 f6 f8 dd c6 6e 5c 24 6d 67 70 23 ee cd 17 f0 ab 25 3b f6 8f 9b 26 b0 cf 7b 80 c5 b3 f9 63 3f d0 ee 5d 00 00 3d 5f 4c 3d 00 00 00 00}  //weight: 3, accuracy: High
        $x_5_4 = {5b c9 c3 55 8b ec 81 ec 40 09 00 00 6a 00 8d 8d c0 f6 ff ff e8 75 fd ff ff 8d 45 d0 68}  //weight: 5, accuracy: High
        $x_7_5 = {10 49 00 45 00 54 00 65 00 78 00 74 00 00 00 00 00}  //weight: 7, accuracy: High
        $x_7_6 = "search-pin(" ascii //weight: 7
        $x_7_7 = {29 2e 64 6c 6c 00 44 6c 6c 49 6e 73 74 61 6c 6c 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_7_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_7_*) and 1 of ($x_3_*))) or
            ((3 of ($x_7_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

