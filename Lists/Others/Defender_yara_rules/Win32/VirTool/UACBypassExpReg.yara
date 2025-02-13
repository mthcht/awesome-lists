rule VirTool_Win32_UACBypassExpReg_B_2147918851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExpReg.B"
        threat_id = "2147918851"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExpReg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " /name Microsoft.BackupAndRestoreCenter" wide //weight: 1
        $n_10_3 = "ed7d0bc7-2924-4f5b-a54b-b403c5d63066" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

