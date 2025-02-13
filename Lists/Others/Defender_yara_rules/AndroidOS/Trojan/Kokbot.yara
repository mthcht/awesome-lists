rule Trojan_AndroidOS_Kokbot_A_2147851721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kokbot.A"
        threat_id = "2147851721"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kokbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getContacts() 1 mobile" ascii //weight: 1
        $x_1_2 = "upLoadContacts()  Contacts list" ascii //weight: 1
        $x_1_3 = "', messagePhone='" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

