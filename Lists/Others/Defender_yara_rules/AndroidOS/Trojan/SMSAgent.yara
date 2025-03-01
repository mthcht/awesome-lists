rule Trojan_AndroidOS_SMSAgent_F_2147794865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSAgent.F"
        threat_id = "2147794865"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setIsH5WxPaying" ascii //weight: 1
        $x_1_2 = "2 sendSucByMsg --------- phone = " ascii //weight: 1
        $x_1_3 = "STRINSMSSENDACTION & isSMSSendSucceed = " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

