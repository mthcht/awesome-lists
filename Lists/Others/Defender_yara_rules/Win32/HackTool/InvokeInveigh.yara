rule HackTool_Win32_InvokeInveigh_2147831229_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/InvokeInveigh"
        threat_id = "2147831229"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "InvokeInveigh"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-inveigh " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

