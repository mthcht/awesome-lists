rule VirTool_Win32_WmiExecCommand_2147769993_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/WmiExecCommand"
        threat_id = "2147769993"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WmiExecCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /Q /c" wide //weight: 1
        $x_1_2 = "1> \\\\127.0.0.1\\ADMIN$\\_" wide //weight: 1
        $x_1_3 = "2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

