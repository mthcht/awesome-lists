rule VirTool_Win64_BofSctskcreate_A_2147901300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/BofSctskcreate.A"
        threat_id = "2147901300"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "BofSctskcreate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get the root folder" ascii //weight: 1
        $x_1_2 = "Got user name and security descriptor" ascii //weight: 1
        $x_1_3 = "Task already exists" ascii //weight: 1
        $x_1_4 = "Registered task" ascii //weight: 1
        $x_1_5 = "Created task path" ascii //weight: 1
        $x_1_6 = "createTask hostname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

