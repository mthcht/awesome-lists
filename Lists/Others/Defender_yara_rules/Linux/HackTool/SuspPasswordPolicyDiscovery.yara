rule HackTool_Linux_SuspPasswordPolicyDiscovery_A_2147942584_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPasswordPolicyDiscovery.A"
        threat_id = "2147942584"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPasswordPolicyDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chage -l" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

