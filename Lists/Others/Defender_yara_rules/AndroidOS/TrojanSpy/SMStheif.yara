rule TrojanSpy_AndroidOS_SMStheif_A_2147809766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMStheif.A!MTB"
        threat_id = "2147809766"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMStheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoneMonitor" ascii //weight: 1
        $x_1_2 = "SMSMonitor" ascii //weight: 1
        $x_1_3 = "getSmsInPhone" ascii //weight: 1
        $x_1_4 = "getCallRecordInPhone" ascii //weight: 1
        $x_1_5 = "SendSmsReceiver" ascii //weight: 1
        $x_1_6 = "uploadRecordFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMStheif_C_2147809767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMStheif.C!MTB"
        threat_id = "2147809767"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMStheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "grabbed_list" ascii //weight: 10
        $x_10_2 = "GRABBED_SMS" ascii //weight: 10
        $x_10_3 = "saveMessage" ascii //weight: 10
        $x_10_4 = "sendSmsAndSaveNumber" ascii //weight: 10
        $x_10_5 = "tel_num" ascii //weight: 10
        $x_10_6 = "getCurrentTelephoneParams" ascii //weight: 10
        $x_1_7 = "panel.re" ascii //weight: 1
        $x_1_8 = "panelvr.in" ascii //weight: 1
        $x_1_9 = "panelvr.mobi" ascii //weight: 1
        $x_1_10 = "vrpanel.biz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SMStheif_B_2147818191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMStheif.B!MTB"
        threat_id = "2147818191"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMStheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.kfyt.arhkt" ascii //weight: 1
        $x_1_2 = "168xin@163.com" ascii //weight: 1
        $x_1_3 = "getTelNum" ascii //weight: 1
        $x_1_4 = "GetContactList" ascii //weight: 1
        $x_1_5 = "getSmsInPhone" ascii //weight: 1
        $x_1_6 = "delDxnr" ascii //weight: 1
        $x_1_7 = "senddxxx" ascii //weight: 1
        $x_1_8 = "This is reboot fucking you" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

