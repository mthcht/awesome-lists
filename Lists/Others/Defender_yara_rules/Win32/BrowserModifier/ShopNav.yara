rule BrowserModifier_Win32_ShopNav_11137_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ShopNav"
        threat_id = "11137"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ShopNav"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "srng/svcdnld.php" ascii //weight: 2
        $x_2_2 = "In DownloadNewExec(): Could not get Internet session handle." ascii //weight: 2
        $x_3_3 = "\\Program Files\\Srng" ascii //weight: 3
        $x_2_4 = "Program Files" ascii //weight: 2
        $x_1_5 = "srng/logf.php" ascii //weight: 1
        $x_1_6 = "srng/jrnl.php" ascii //weight: 1
        $x_1_7 = "srng/dnld.php" ascii //weight: 1
        $x_1_8 = "srng/reg.php" ascii //weight: 1
        $x_2_9 = "SrngVer" ascii //weight: 2
        $x_2_10 = "Software\\Srng" ascii //weight: 2
        $x_3_11 = "SrngInit.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_ShopNav_11137_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ShopNav"
        threat_id = "11137"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ShopNav"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|failed to register uninstaller|" ascii //weight: 1
        $x_1_2 = "| didn't accept |" ascii //weight: 1
        $x_1_3 = "| failed store eula |" ascii //weight: 1
        $x_1_4 = "| failed to read eula |" ascii //weight: 1
        $x_1_5 = "| failed to allocate eula |" ascii //weight: 1
        $x_1_6 = "Do you accept the terms of this Agreement?" ascii //weight: 1
        $x_1_7 = "I have read the End-User License Agreement" ascii //weight: 1
        $x_1_8 = "Failed to download instructions :: url=%s :: WinMain :: " ascii //weight: 1
        $x_5_9 = "http://%s/uninst2.cgi?affid=%s&ver=%s&iid=%s&grp=%s" ascii //weight: 5
        $x_8_10 = "sysupdate.shopnav.com" ascii //weight: 8
        $x_5_11 = {61 70 70 73 2e 77 65 62 73 65 72 76 69 63 65 68 6f 73 74 73 2e 63 6f 6d 00 00 00 00 62 6c 6f 67 2e 70 68 70}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

