rule VirTool_Win32_MSFPsExecCommand_2147765155_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/MSFPsExecCommand"
        threat_id = "2147765155"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MSFPsExecCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = " /C echo " wide //weight: 2
        $x_2_3 = " ^> " wide //weight: 2
        $x_2_4 = {20 00 3e 00 20 00 [0-8] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00}  //weight: 2, accuracy: Low
        $x_1_5 = " /C start " wide //weight: 1
        $x_1_6 = " & del " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

