rule Trojan_AndroidOS_Erop_A_2147833940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Erop.A!MTB"
        threat_id = "2147833940"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Erop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/eroplayer" ascii //weight: 1
        $x_1_2 = "is_sms" ascii //weight: 1
        $x_1_3 = "onRulesButtonClick" ascii //weight: 1
        $x_1_4 = "bornapk.com" ascii //weight: 1
        $x_1_5 = "onSmsButtonClick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

