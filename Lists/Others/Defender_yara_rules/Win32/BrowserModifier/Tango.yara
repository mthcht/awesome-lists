rule BrowserModifier_Win32_Tango_150863_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Tango"
        threat_id = "150863"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Tango"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://apps.tangotoolbar.com" ascii //weight: 1
        $x_1_2 = "mshta.exe http://remove.gettango.com/" ascii //weight: 1
        $x_1_3 = "http://websearch.gettango.com/?" ascii //weight: 1
        $x_1_4 = "%sURL=%s&T=%s&ERROR=%d" ascii //weight: 1
        $x_1_5 = "About Tango Toolbar" ascii //weight: 1
        $x_1_6 = "http://www.tangosearch.com/" ascii //weight: 1
        $x_1_7 = "http://search.lycos.com/default.asp?src=clear" ascii //weight: 1
        $x_1_8 = ".?AVCDialogAboutTango@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

