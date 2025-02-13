rule HackTool_Win32_TwitterPassDump_2147712489_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/TwitterPassDump"
        threat_id = "2147712489"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TwitterPassDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SterJo Twitter Password Finder" ascii //weight: 2
        $x_2_2 = "/sterjosoft.com/" wide //weight: 2
        $x_1_3 = "Opera Stable\\Login Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

