rule HackTool_MacOS_SandCat_B_2147931783_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SandCat.B!MTB"
        threat_id = "2147931783"
        type = "HackTool"
        platform = "MacOS: "
        family = "SandCat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mitre/gocat/agent" ascii //weight: 1
        $x_1_2 = "sandcat/gocat/execute/shells" ascii //weight: 1
        $x_1_3 = "DownloadPayloadToMemory" ascii //weight: 1
        $x_1_4 = "gocat/agent.getUsername" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

