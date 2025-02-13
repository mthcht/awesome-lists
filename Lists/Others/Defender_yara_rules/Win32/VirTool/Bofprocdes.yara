rule VirTool_Win32_Bofprocdes_A_2147901291_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofprocdes.A"
        threat_id = "2147901291"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofprocdes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Killing all handles in PID" ascii //weight: 1
        $x_1_2 = "Closed all handles in pid" ascii //weight: 1
        $x_1_3 = "killit failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

