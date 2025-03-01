rule Trojan_AndroidOS_smsAgent_B_2147744796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/smsAgent.B!MTB"
        threat_id = "2147744796"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "smsAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+919108389046" ascii //weight: 1
        $x_1_2 = "aktivated" ascii //weight: 1
        $x_1_3 = "dcheck" ascii //weight: 1
        $x_1_4 = "ssendaa" ascii //weight: 1
        $x_1_5 = "setMobileDataEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

