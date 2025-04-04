rule HackTool_MacOS_SuspSharedResourceDiscovery_A1_2147937939_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSharedResourceDiscovery.A1"
        threat_id = "2147937939"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSharedResourceDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "smbutil view -g //" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

