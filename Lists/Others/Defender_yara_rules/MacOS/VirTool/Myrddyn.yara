rule VirTool_MacOS_Myrddyn_A_2147821104_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/Myrddyn.A!MTB"
        threat_id = "2147821104"
        type = "VirTool"
        platform = "MacOS: "
        family = "Myrddyn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Mythic/agent_code/poseidon.go" ascii //weight: 2
        $x_1_2 = "/Mythic/agent_code/keylog/keylog.go" ascii //weight: 1
        $x_1_3 = "screencapture.go" ascii //weight: 1
        $x_1_4 = "agent_code/persist_launchd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

