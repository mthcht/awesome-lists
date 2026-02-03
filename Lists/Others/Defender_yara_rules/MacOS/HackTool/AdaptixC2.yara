rule HackTool_MacOS_AdaptixC2_A_2147962233_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/AdaptixC2.A!MTB"
        threat_id = "2147962233"
        type = "HackTool"
        platform = "MacOS: "
        family = "AdaptixC2"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.taskScreenshot" ascii //weight: 1
        $x_1_2 = "main.jobDownloadStart" ascii //weight: 1
        $x_1_3 = "main.taskJobKill" ascii //weight: 1
        $x_1_4 = "main.taskUpload" ascii //weight: 1
        $x_1_5 = "main.taskShell" ascii //weight: 1
        $x_1_6 = "main.jobRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

