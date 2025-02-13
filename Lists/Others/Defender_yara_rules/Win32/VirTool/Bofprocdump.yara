rule VirTool_Win32_Bofprocdump_A_2147901296_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofprocdump.A"
        threat_id = "2147901296"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofprocdump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dumping PID" ascii //weight: 1
        $x_1_2 = "Wrote dump to file" ascii //weight: 1
        $x_1_3 = "Don't forget to delete" ascii //weight: 1
        $x_1_4 = "procdump failed" ascii //weight: 1
        $x_1_5 = "bofstop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

