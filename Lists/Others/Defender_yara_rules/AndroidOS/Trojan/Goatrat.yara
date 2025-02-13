rule Trojan_AndroidOS_Goatrat_P_2147852283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Goatrat.P"
        threat_id = "2147852283"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Goatrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "destroyViaHttp" ascii //weight: 1
        $x_1_2 = "W5rWzDxq" ascii //weight: 1
        $x_1_3 = "WebRTC is up!" ascii //weight: 1
        $x_1_4 = "getErrorReasonaaa" ascii //weight: 1
        $x_1_5 = "Set Username (usernameVariavel)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

