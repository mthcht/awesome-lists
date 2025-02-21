rule Trojan_MacOS_WildFire_A_2147934088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WildFire.A!MTB"
        threat_id = "2147934088"
        type = "Trojan"
        platform = "MacOS: "
        family = "WildFire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_neverGonnaGiveYouUp" ascii //weight: 1
        $x_1_2 = "_neverGonnaRunAroundAndDesertYou" ascii //weight: 1
        $x_1_3 = "_neverGonnaLetYouDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

