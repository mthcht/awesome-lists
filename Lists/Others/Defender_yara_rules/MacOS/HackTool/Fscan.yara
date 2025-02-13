rule HackTool_MacOS_Fscan_A_2147921859_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Fscan.A!MTB"
        threat_id = "2147921859"
        type = "HackTool"
        platform = "MacOS: "
        family = "Fscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadow1ng/fscan" ascii //weight: 1
        $x_1_2 = "Plugins.NetBiosInfo" ascii //weight: 1
        $x_2_3 = "SshConn.Password.func3" ascii //weight: 2
        $x_1_4 = "hackgov" ascii //weight: 1
        $x_1_5 = "Plugins.SmbGhostScan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_MacOS_Fscan_B_2147922953_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Fscan.B!MTB"
        threat_id = "2147922953"
        type = "HackTool"
        platform = "MacOS: "
        family = "Fscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "FcgiScan" ascii //weight: 5
        $x_5_2 = "Plugins.PortScan" ascii //weight: 5
        $x_5_3 = "SmbGhostScan" ascii //weight: 5
        $x_1_4 = "Plugins.makeSMB1Trans2ExploitPacket" ascii //weight: 1
        $x_1_5 = "GetIsDomainNameServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

