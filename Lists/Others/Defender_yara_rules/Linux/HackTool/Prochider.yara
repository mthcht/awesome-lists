rule HackTool_Linux_Prochider_A_2147820333_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Prochider.A!xp"
        threat_id = "2147820333"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Prochider"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Process Stack Faker" ascii //weight: 1
        $x_1_2 = "Usage: %s [options] command arg1 arg2" ascii //weight: 1
        $x_1_3 = "renice process" ascii //weight: 1
        $x_1_4 = "fake process name" ascii //weight: 1
        $x_1_5 = "spawned process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

