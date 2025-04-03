rule HackTool_MacOS_MythicAgent_X_2147937822_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/MythicAgent.X"
        threat_id = "2147937822"
        type = "HackTool"
        platform = "MacOS: "
        family = "MythicAgent"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MythicAgent" ascii //weight: 1
        $x_1_2 = "poseidon/Payload" ascii //weight: 1
        $x_1_3 = "http_initial_config=" ascii //weight: 1
        $x_1_4 = "proxy_bypass=" ascii //weight: 1
        $x_1_5 = "SendFileToMythic" ascii //weight: 1
        $x_1_6 = "sudo_poseidon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

