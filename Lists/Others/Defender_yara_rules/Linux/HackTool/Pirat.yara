rule HackTool_Linux_Pirat_A_2147928876_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Pirat.A!MTB"
        threat_id = "2147928876"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Pirat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "peirates.injectIntoAPodViaAPIServer" ascii //weight: 1
        $x_1_2 = "peirates.ServerInfo" ascii //weight: 1
        $x_1_3 = "enumerate_dns.go" ascii //weight: 1
        $x_1_4 = "peirates.KopsAttackAWS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

