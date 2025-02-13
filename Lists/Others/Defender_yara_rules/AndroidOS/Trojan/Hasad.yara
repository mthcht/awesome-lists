rule Trojan_AndroidOS_Hasad_A_2147841000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hasad.A!MTB"
        threat_id = "2147841000"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hasad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.cliphot.me" ascii //weight: 1
        $x_1_2 = "TrackingService" ascii //weight: 1
        $x_1_3 = "com/hdc/sdk/autosub" ascii //weight: 1
        $x_1_4 = "hdcsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

