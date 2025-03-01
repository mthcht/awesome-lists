rule Trojan_AndroidOS_TimeThief_A_2147799190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/TimeThief.A!MTB"
        threat_id = "2147799190"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "TimeThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callphoneNumber" ascii //weight: 1
        $x_1_2 = "RQS_PICK_CONTACT" ascii //weight: 1
        $x_1_3 = "getContactPhone" ascii //weight: 1
        $x_1_4 = "com/androidethiopia/ethiotelecom/CallMeActivity" ascii //weight: 1
        $x_1_5 = "altMultiplePhoneNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

