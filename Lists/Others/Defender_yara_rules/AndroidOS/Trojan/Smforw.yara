rule Trojan_AndroidOS_Smforw_A_2147847751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smforw.A"
        threat_id = "2147847751"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "has_set_send_email_account" ascii //weight: 2
        $x_2_2 = "is_init_end_time" ascii //weight: 2
        $x_2_3 = "email_message_contacts_switch" ascii //weight: 2
        $x_2_4 = "has_send_phone_info" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smforw_S_2147888298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smforw.S"
        threat_id = "2147888298"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "secretTalkApp" ascii //weight: 1
        $x_1_2 = "ready to receive sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smforw_S_2147888298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smforw.S"
        threat_id = "2147888298"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/servlet/SendMassage2" ascii //weight: 2
        $x_2_2 = "DeAdminReciver" ascii //weight: 2
        $x_2_3 = "/servlet/ContactsUpload" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smforw_H_2147898649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smforw.H"
        threat_id = "2147898649"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "index.php?type=receivesms&telnum=" ascii //weight: 2
        $x_2_2 = "Allow_AutoCall" ascii //weight: 2
        $x_2_3 = "SMS_BlockState" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

