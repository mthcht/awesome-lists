rule Trojan_MacOS_SuspFileDown_DSK2_2147971842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspFileDown.DSK2!MTB"
        threat_id = "2147971842"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspFileDown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "open -a /tmp/bin --args hellolargeworld.com:443" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

