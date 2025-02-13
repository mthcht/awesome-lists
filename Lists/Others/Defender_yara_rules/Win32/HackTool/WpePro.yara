rule HackTool_Win32_WpePro_2147627942_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/WpePro"
        threat_id = "2147627942"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WpePro"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WPEPRO" ascii //weight: 1
        $x_1_2 = "WpeSpy.dll" ascii //weight: 1
        $x_1_3 = "WinsockSpy.Client" ascii //weight: 1
        $x_1_4 = "CLoggingOptionsPage" ascii //weight: 1
        $x_1_5 = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

