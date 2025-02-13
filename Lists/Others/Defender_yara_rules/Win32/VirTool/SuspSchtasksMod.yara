rule VirTool_Win32_SuspSchtasksMod_A_2147849834_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspSchtasksMod.A!cbl4"
        threat_id = "2147849834"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSchtasksMod"
        severity = "Critical"
        info = "cbl4: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 [0-8] 20 00 2f 00 43 00 68 00 61 00 6e 00 67 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = " /S " wide //weight: 1
        $x_1_4 = " /U " wide //weight: 1
        $x_1_5 = " /P " wide //weight: 1
        $x_1_6 = " /TN \\Microsoft\\Windows\\" wide //weight: 1
        $x_1_7 = " /TR C:\\Windows\\System32\\wmimetricsq.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

