rule Trojan_AndroidOS_Razel_A_2147835834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Razel.A!MTB"
        threat_id = "2147835834"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Razel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stealContacts" ascii //weight: 1
        $x_1_2 = "stealSMS" ascii //weight: 1
        $x_1_3 = "_stealLog" ascii //weight: 1
        $x_1_4 = "_findPics" ascii //weight: 1
        $x_1_5 = "stealWhatsapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

