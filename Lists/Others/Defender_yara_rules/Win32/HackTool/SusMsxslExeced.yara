rule HackTool_Win32_SusMsxslExeced_MK_2147970495_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SusMsxslExeced.MK"
        threat_id = "2147970495"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SusMsxslExeced"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msxsl" wide //weight: 1
        $x_1_2 = ".xsl" wide //weight: 1
        $n_1_3 = "r4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce3" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

