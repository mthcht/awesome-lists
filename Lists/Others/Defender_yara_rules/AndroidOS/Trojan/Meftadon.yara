rule Trojan_AndroidOS_Meftadon_A_2147844117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Meftadon.A!MTB"
        threat_id = "2147844117"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Meftadon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xxxxxx.zzzzzz.glue.ActivityModuleStart" ascii //weight: 1
        $x_1_2 = "need_knock" ascii //weight: 1
        $x_1_3 = "ttp//bibonado.com" ascii //weight: 1
        $x_1_4 = "metafond" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

