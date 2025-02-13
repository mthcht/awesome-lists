rule VirTool_MacOS_Myrddin_GV_2147793999_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/Myrddin.GV!MTB"
        threat_id = "2147793999"
        type = "VirTool"
        platform = "MacOS: "
        family = "Myrddin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/exec/exec_unix.go" ascii //weight: 1
        $x_1_2 = "/Ne0nd0g/merlin/" ascii //weight: 1
        $x_1_3 = "/commands.ExecuteShellcodeQueueUserAPC" ascii //weight: 1
        $x_1_4 = "/commands/shell_darwin.go" ascii //weight: 1
        $x_1_5 = "/usr/local/go/src/os/executable_darwin.go" ascii //weight: 1
        $x_1_6 = "mythic.Task" ascii //weight: 1
        $x_1_7 = "SendMerlinMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

