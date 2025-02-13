rule Trojan_AndroidOS_Kotel_A_2147825012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kotel.A!MTB"
        threat_id = "2147825012"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kotel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/pho/nec/sg/ui" ascii //weight: 1
        $x_1_2 = "checkPhoneNumExistAndSendMsgAndLock" ascii //weight: 1
        $x_1_3 = "getOfferTrackUrl" ascii //weight: 1
        $x_1_4 = "handleSMSSendOK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

