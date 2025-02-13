rule Trojan_AndroidOS_Koomer_RT_2147921651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koomer.RT"
        threat_id = "2147921651"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koomer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kooseaminergl" ascii //weight: 1
        $x_1_2 = "ESmsEngStarted" ascii //weight: 1
        $x_1_3 = "MSG_GET_PHONE_NUMBER" ascii //weight: 1
        $x_1_4 = "StatusIsbegin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

