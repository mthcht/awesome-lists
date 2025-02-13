rule Trojan_AndroidOS_Copybara_A_2147921056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Copybara.A!MTB"
        threat_id = "2147921056"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Copybara"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send_inj_lst" ascii //weight: 1
        $x_1_2 = "Send_CallPhoneNumber" ascii //weight: 1
        $x_1_3 = "Get_Device_CallLogs" ascii //weight: 1
        $x_1_4 = "Send_SMSMessage_ToNumber" ascii //weight: 1
        $x_1_5 = "Send_KeyLo_Views" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

