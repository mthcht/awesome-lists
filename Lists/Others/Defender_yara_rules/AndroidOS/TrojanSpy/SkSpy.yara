rule TrojanSpy_AndroidOS_SkSpy_A_2147812613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SkSpy.A"
        threat_id = "2147812613"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SkSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#block_numbers" ascii //weight: 1
        $x_1_2 = "#change_url" ascii //weight: 1
        $x_1_3 = "#control_number" ascii //weight: 1
        $x_1_4 = "#disable_forward_calls" ascii //weight: 1
        $x_1_5 = "#intercept_sms_start" ascii //weight: 1
        $x_1_6 = "#listen_sms_stop" ascii //weight: 1
        $x_1_7 = "ADMIN_URL_PREF" ascii //weight: 1
        $x_1_8 = "INTERCEPTING_INCOMING_ENABLED" ascii //weight: 1
        $x_1_9 = "LISTENED_INCOMING_SMS" ascii //weight: 1
        $x_1_10 = "#wipe_data" ascii //weight: 1
        $x_1_11 = "/SDCardServiceStarter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

