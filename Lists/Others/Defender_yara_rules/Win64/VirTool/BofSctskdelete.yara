rule VirTool_Win64_BofSctskdelete_A_2147901301_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BofSctskdelete.A"
        threat_id = "2147901301"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BofSctskdelete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get the root folder" ascii //weight: 1
        $x_1_2 = "delete the requested task folder" ascii //weight: 1
        $x_1_3 = "stop the task" ascii //weight: 1
        $x_1_4 = "Deleted the task" ascii //weight: 1
        $x_1_5 = "deleteTask failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

