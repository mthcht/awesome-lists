rule HackTool_MacOS_SuspSoftwareDiscovery_B1_2147937936_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSoftwareDiscovery.B1"
        threat_id = "2147937936"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSoftwareDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6c 00 69 00 73 00 74 00 62 00 75 00 64 00 64 00 79 00 [0-128] 2f 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2f 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 61 00 70 00 70 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 69 00 6e 00 66 00 6f 00 2e 00 70 00 6c 00 69 00 73 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSoftwareDiscovery_B2_2147937937_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSoftwareDiscovery.B2"
        threat_id = "2147937937"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSoftwareDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6c 00 69 00 73 00 74 00 62 00 75 00 64 00 64 00 79 00 [0-128] 2f 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2f 00 73 00 61 00 66 00 61 00 72 00 69 00 2e 00 61 00 70 00 70 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 69 00 6e 00 66 00 6f 00 2e 00 70 00 6c 00 69 00 73 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

