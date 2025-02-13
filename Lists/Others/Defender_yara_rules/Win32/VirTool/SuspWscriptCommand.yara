rule VirTool_Win32_SuspWscriptCommand_A_2147768932_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspWscriptCommand.A"
        threat_id = "2147768932"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWscriptCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "/b" wide //weight: 1
        $x_1_3 = "/e:jscript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

