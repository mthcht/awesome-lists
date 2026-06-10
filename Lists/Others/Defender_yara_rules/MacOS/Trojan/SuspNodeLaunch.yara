rule Trojan_MacOS_SuspNodeLaunch_Z_2147971291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspNodeLaunch.Z!MTB"
        threat_id = "2147971291"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspNodeLaunch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

