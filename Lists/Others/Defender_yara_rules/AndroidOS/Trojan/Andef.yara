rule Trojan_AndroidOS_Andef_A_2147839289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Andef.A!MTB"
        threat_id = "2147839289"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Andef"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getContactPhone" ascii //weight: 1
        $x_1_2 = "sendToBlack_Click" ascii //weight: 1
        $x_1_3 = "chkNotGetSMS" ascii //weight: 1
        $x_1_4 = "chkNotGetCall" ascii //weight: 1
        $x_1_5 = "txt_add_black_warning_params_message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

