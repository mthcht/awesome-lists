rule VirTool_Win32_SuspRenPsexec_A_2147849934_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRenPsexec.A"
        threat_id = "2147849934"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRenPsexec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = ".exe \\\\" wide //weight: 1
        $x_1_3 = " -accepteula " wide //weight: 1
        $x_1_4 = " -s " wide //weight: 1
        $x_1_5 = " -c C:\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

