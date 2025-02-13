rule VirTool_Win32_AtExecCommand_2147769992_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AtExecCommand"
        threat_id = "2147769992"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AtExecCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /C" wide //weight: 1
        $x_1_2 = "> C:\\Windows\\Temp" wide //weight: 1
        $x_1_3 = ".tmp 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

