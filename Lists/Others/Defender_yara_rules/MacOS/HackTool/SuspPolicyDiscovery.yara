rule HackTool_MacOS_SuspPolicyDiscovery_A1_2147937938_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspPolicyDiscovery.A1"
        threat_id = "2147937938"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspPolicyDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pwpolicy getaccountpolicies" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

