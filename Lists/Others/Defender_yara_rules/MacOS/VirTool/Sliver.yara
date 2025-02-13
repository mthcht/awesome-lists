rule VirTool_MacOS_Sliver_A_2147851385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/Sliver.A!MTB"
        threat_id = "2147851385"
        type = "VirTool"
        platform = "MacOS: "
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BackdoorReq" ascii //weight: 1
        $x_1_2 = "SSHCommandReq" ascii //weight: 1
        $x_1_3 = "ScreenshotReq" ascii //weight: 1
        $x_1_4 = "runtime.persistentalloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MacOS_Sliver_B_2147888492_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/Sliver.B!MTB"
        threat_id = "2147888492"
        type = "VirTool"
        platform = "MacOS: "
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenshotReq" ascii //weight: 1
        $x_1_2 = "SSHCommandReq" ascii //weight: 1
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

