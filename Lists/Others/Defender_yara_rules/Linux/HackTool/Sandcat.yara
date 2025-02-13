rule HackTool_Linux_Sandcat_A_2147894006_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Sandcat.A!MTB"
        threat_id = "2147894006"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Sandcat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/sandcat.go" ascii //weight: 5
        $x_1_2 = "victimsize" ascii //weight: 1
        $x_1_3 = "/payload.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

