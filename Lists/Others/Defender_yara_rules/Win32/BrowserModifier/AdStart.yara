rule BrowserModifier_Win32_AdStart_17891_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/AdStart"
        threat_id = "17891"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "AdStart"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SWin32.DLL" ascii //weight: 2
        $x_3_2 = "IEEnhancer" ascii //weight: 3
        $x_3_3 = "/adlApp/" ascii //weight: 3
        $x_3_4 = "SOFTWARE\\y036" ascii //weight: 3
        $x_3_5 = "get_uid.asp" ascii //weight: 3
        $x_1_6 = "match_type" ascii //weight: 1
        $x_3_7 = "sp32.xml" ascii //weight: 3
        $x_2_8 = "search_trigger" ascii //weight: 2
        $x_1_9 = "popup.html" ascii //weight: 1
        $x_1_10 = "key_begin" ascii //weight: 1
        $x_1_11 = "search_term" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

