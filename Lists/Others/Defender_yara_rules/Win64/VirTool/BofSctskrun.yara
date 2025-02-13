rule VirTool_Win64_BofSctskrun_A_2147901302_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BofSctskrun.A"
        threat_id = "2147901302"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BofSctskrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create Task Scheduler interface" ascii //weight: 1
        $x_1_2 = "SysAllocString" ascii //weight: 1
        $x_1_3 = "get the root folder" ascii //weight: 1
        $x_1_4 = "run the task" ascii //weight: 1
        $x_1_5 = "stop the task" ascii //weight: 1
        $x_1_6 = "run task returned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

