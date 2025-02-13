rule VirTool_Win32_SmbExecCommand_2147769940_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SmbExecCommand"
        threat_id = "2147769940"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SmbExecCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /C echo " wide //weight: 1
        $x_1_3 = " ^> " wide //weight: 1
        $x_1_4 = " /C start " wide //weight: 1
        $x_1_5 = " & del " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

