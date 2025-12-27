rule VirTool_Win32_SuspFileDeletion_A_2147956573_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspFileDeletion.A"
        threat_id = "2147956573"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspFileDeletion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = " /c del /q " wide //weight: 1
        $x_1_3 = " c:\\Windows\\" wide //weight: 1
        $n_100_4 = "picus_rewind" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

