rule VirTool_Win64_Freyjaz_A_2147895157_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Freyjaz.A!MTB"
        threat_id = "2147895157"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Freyjaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell_executor.Run" ascii //weight: 1
        $x_1_2 = "cmd_executor.Run" ascii //weight: 1
        $x_1_3 = "MythicUUID" ascii //weight: 1
        $x_1_4 = "SendFileToMythic" ascii //weight: 1
        $x_1_5 = ".SetMythicID" ascii //weight: 1
        $x_1_6 = ".SetSleepJitter" ascii //weight: 1
        $x_1_7 = ".GetProcessName" ascii //weight: 1
        $x_1_8 = "socks.Run" ascii //weight: 1
        $x_1_9 = ".Keylog" ascii //weight: 1
        $x_1_10 = ".IsElevated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

