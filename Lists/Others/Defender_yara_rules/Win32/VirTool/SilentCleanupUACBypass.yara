rule VirTool_Win32_SilentCleanupUACBypass_A_2147799479_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SilentCleanupUACBypass.A"
        threat_id = "2147799479"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SilentCleanupUACBypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /Run " wide //weight: 1
        $x_1_3 = " /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" wide //weight: 1
        $x_1_4 = " /I" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SilentCleanupUACBypass_B_2147837440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SilentCleanupUACBypass.B"
        threat_id = "2147837440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SilentCleanupUACBypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe \\system32\\cleanmgr.exe /autoclean" wide //weight: 1
        $x_1_2 = " /d " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

