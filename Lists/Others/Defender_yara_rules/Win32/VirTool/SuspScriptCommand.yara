rule VirTool_Win32_SuspScriptCommand_A_2147769833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspScriptCommand.A"
        threat_id = "2147769833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScriptCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/b" wide //weight: 1
        $x_1_2 = "/e:jscript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

