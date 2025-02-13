rule BrowserModifier_Win32_Kipidow_232993_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Kipidow"
        threat_id = "232993"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Kipidow"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://hao.360.cn/?src=lm&ls=n466c3df49f" wide //weight: 1
        $x_1_2 = "KPDownCaption" wide //weight: 1
        $x_1_3 = "KPDesktopRun" wide //weight: 1
        $x_1_4 = "kpdown.ini" wide //weight: 1
        $x_1_5 = "//khit.cn/xldl.zip" ascii //weight: 1
        $x_1_6 = "bin_kp\\KPDown\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

