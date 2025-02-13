rule BrowserModifier_Win32_24t_15214_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/24t"
        threat_id = "15214"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "24t"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FPUMaskValue" ascii //weight: 10
        $x_1_3 = "\\system\\ppc.dll" ascii //weight: 1
        $x_1_4 = "/24t.dll" ascii //weight: 1
        $x_1_5 = "HomePage&Toolbar Guard" ascii //weight: 1
        $x_1_6 = "c:/r.reg" ascii //weight: 1
        $x_1_7 = "\"Start Page\"=\"http://24-7-search.com/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

