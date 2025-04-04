rule HackTool_MacOS_SuspAccountDiscovery_A1_2147937935_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspAccountDiscovery.A1"
        threat_id = "2147937935"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspAccountDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cat /etc/passwd" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

