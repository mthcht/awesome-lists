rule TrojanSpy_AndroidOS_Gugi_A_2147817406_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gugi.A!MTB"
        threat_id = "2147817406"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gugi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ru.drink.lime" ascii //weight: 2
        $x_1_2 = "set_sms_status" ascii //weight: 1
        $x_1_3 = "set_task_status" ascii //weight: 1
        $x_1_4 = "80.87.205.126" ascii //weight: 1
        $x_1_5 = "exist_bank_app" ascii //weight: 1
        $x_1_6 = "r.d.l.sms_sent" ascii //weight: 1
        $x_1_7 = "client_password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Gugi_B_2147826610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gugi.B!MTB"
        threat_id = "2147826610"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gugi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seC/weewyu/iOijuC" ascii //weight: 1
        $x_1_2 = "commandObServer" ascii //weight: 1
        $x_1_3 = "com.googie.system.MainActivity" ascii //weight: 1
        $x_1_4 = "get sms_list" ascii //weight: 1
        $x_1_5 = "const_id_send_sms" ascii //weight: 1
        $x_1_6 = "alarm_check_connected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Gugi_C_2147827512_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gugi.C!MTB"
        threat_id = "2147827512"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gugi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/googie/system" ascii //weight: 1
        $x_1_2 = "setStatusOkTask" ascii //weight: 1
        $x_1_3 = "saveSmsServer" ascii //weight: 1
        $x_1_4 = "returnSmsListTid" ascii //weight: 1
        $x_1_5 = "sendContacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

