rule VirTool_MacOS_MythicPoseidon_A_2147889476_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/MythicPoseidon.A!MTB"
        threat_id = "2147889476"
        type = "VirTool"
        platform = "MacOS: "
        family = "MythicPoseidon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.sendFileToMythic" ascii //weight: 1
        $x_1_2 = "main.handleRemoveInternalTCPConnections" ascii //weight: 1
        $x_1_3 = "/poseidon.go" ascii //weight: 1
        $x_1_4 = "/portscan.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

