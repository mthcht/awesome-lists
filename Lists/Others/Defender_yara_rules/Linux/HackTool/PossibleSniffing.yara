rule HackTool_Linux_PossibleSniffing_A_2147842925_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PossibleSniffing.A"
        threat_id = "2147842925"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PossibleSniffing"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = " -i" wide //weight: 5
        $x_1_2 = "port 21 or port 23" wide //weight: 1
        $x_1_3 = "port 23 or port 21" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

