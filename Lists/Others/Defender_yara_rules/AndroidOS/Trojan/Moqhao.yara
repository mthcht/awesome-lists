rule Trojan_AndroidOS_Moqhao_A_2147787715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Moqhao.A"
        threat_id = "2147787715"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Moqhao"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "KMReceiver" ascii //weight: 3
        $x_3_2 = "KSMReceiver" ascii //weight: 3
        $x_1_3 = "K_GET_SMS" ascii //weight: 1
        $x_1_4 = "K_JS_LOGIN" ascii //weight: 1
        $x_1_5 = "K_SMS_CONTENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

