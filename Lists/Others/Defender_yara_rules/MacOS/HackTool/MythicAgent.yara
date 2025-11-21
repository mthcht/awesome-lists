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

rule HackTool_MacOS_MythicAgent_X2_2147958026_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/MythicAgent.X2"
        threat_id = "2147958026"
        type = "HackTool"
        platform = "MacOS: "
        family = "MythicAgent"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "estPassword" ascii //weight: 100
        $x_100_2 = "udo_poseidon" ascii //weight: 100
        $x_100_3 = "hellcode_template" ascii //weight: 100
        $x_100_4 = "ProxyBypass" ascii //weight: 100
        $x_100_5 = "ScanPortRanges" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_MythicAgent_X3_2147958027_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/MythicAgent.X3"
        threat_id = "2147958027"
        type = "HackTool"
        platform = "MacOS: "
        family = "MythicAgent"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "json:\"Killdate\"" ascii //weight: 100
        $x_100_2 = "keystrokes" ascii //weight: 100
        $x_100_3 = "c2_profile" ascii //weight: 100
        $x_100_4 = "json:\"sandboxpath\"" ascii //weight: 100
        $x_100_5 = "json:\"webhook" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

