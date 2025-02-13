rule HackTool_Linux_Traitor_2147815598_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Traitor!MTB"
        threat_id = "2147815598"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Traitor"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dirtyThatPipe" ascii //weight: 1
        $x_1_2 = "dockersock.writableDockerSocketExploit" ascii //weight: 1
        $x_1_3 = "poll.splicePipe" ascii //weight: 1
        $x_1_4 = "liamg/traitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

