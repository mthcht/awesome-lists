rule BrowserModifier_Win32_Heazycrome_234061_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Heazycrome"
        threat_id = "234061"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Heazycrome"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "If LCase(fso.GetExtensionName(file.Path)) = \\\"lnk\\\"" ascii //weight: 20
        $x_20_2 = "EventFilter sethomePage2" ascii //weight: 20
        $x_1_3 = "Const linkChrome = \\\"http://9o0gle.com/\\\"" ascii //weight: 1
        $x_1_4 = "Const link = \\\"http://navsmart.info\\\"" ascii //weight: 1
        $x_1_5 = "Const link = \\\"http://www.navsmart.info/\\\"" ascii //weight: 1
        $x_1_6 = "Const link = \\\"http://yeabests.cc\\\"" ascii //weight: 1
        $x_1_7 = "Const link = \\\"http://jyhjyy.top\\\"" ascii //weight: 1
        $x_1_8 = "Const link = \\\"http://navigation.iwatchavi.com/\\\"" ascii //weight: 1
        $x_1_9 = "xmlHttp.open \\\"GET\\\", \\\"http://bbtbfr.pw/GetHPHost" ascii //weight: 1
        $x_1_10 = "tmp.mof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

