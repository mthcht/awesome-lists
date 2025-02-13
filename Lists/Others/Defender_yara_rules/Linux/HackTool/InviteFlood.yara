rule HackTool_Linux_InviteFlood_B_2147921687_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/InviteFlood.B!MTB"
        threat_id = "2147921687"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "InviteFlood"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inviteflood" ascii //weight: 1
        $x_1_2 = "Flood Stage" ascii //weight: 1
        $x_1_3 = "hack_library.c" ascii //weight: 1
        $x_1_4 = "-a flood tool" ascii //weight: 1
        $x_1_5 = "SIP PAYLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_InviteFlood_A_2147922749_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/InviteFlood.A!MTB"
        threat_id = "2147922749"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "InviteFlood"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 c6 00 00 8b 45 ec 89 04 24 e8 fa ed ff ff 89 45 e0 81 7d e0 ff 00 00 00 7f ?? 8b 45 ec 0f b6 00 0f be c0 83 e8 30 83 f8 09}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 28 8b 45 0c 89 c2 c1 fa 1f c1 ea 1c 01 d0 c1 f8 04 89 45 ec 8b 45 0c 89 c2 c1 fa 1f c1 ea 1c 01 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

