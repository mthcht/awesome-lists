rule Trojan_AndroidOS_Binka_A_2147823811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Binka.A!MTB"
        threat_id = "2147823811"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Binka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isStartCALL" ascii //weight: 1
        $x_1_2 = "sent_Call_Details" ascii //weight: 1
        $x_1_3 = "isStartSMS" ascii //weight: 1
        $x_1_4 = "chekAdminAccess" ascii //weight: 1
        $x_1_5 = "sent_smslist_to_server" ascii //weight: 1
        $x_1_6 = "isContactList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

