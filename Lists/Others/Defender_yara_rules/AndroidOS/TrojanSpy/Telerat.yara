rule TrojanSpy_AndroidOS_Telerat_A_2147780779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Telerat.A!MTB"
        threat_id = "2147780779"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Telerat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getallsms_realrat" ascii //weight: 1
        $x_1_2 = "install_realrat" ascii //weight: 1
        $x_1_3 = "realrat.fuck.cmd_realrat" ascii //weight: 1
        $x_1_4 = "SMSInterceptor" ascii //weight: 1
        $x_1_5 = "PhoneSms" ascii //weight: 1
        $x_1_6 = "hide_realrat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Telerat_B_2147788228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Telerat.B!MTB"
        threat_id = "2147788228"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Telerat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsInterceptor" ascii //weight: 1
        $x_1_2 = "ListenToOutgoingMessages" ascii //weight: 1
        $x_1_3 = "incoming_number" ascii //weight: 1
        $x_1_4 = "api.rayanoos.ir/bot" ascii //weight: 1
        $x_1_5 = "allsms.zip" ascii //weight: 1
        $x_1_6 = "www.sunpax.ga/upload.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Telerat_C_2147828949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Telerat.C!MTB"
        threat_id = "2147828949"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Telerat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botrat" ascii //weight: 1
        $x_1_2 = "telerat2.txt" ascii //weight: 1
        $x_1_3 = "_smsins_messagesent" ascii //weight: 1
        $x_1_4 = "_bot_token" ascii //weight: 1
        $x_1_5 = "_upload_photo" ascii //weight: 1
        $x_1_6 = "getlastsms" ascii //weight: 1
        $x_1_7 = "_findallcontacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

