rule TrojanSpy_AndroidOS_NewBank_A_2147838252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/NewBank.A!MTB"
        threat_id = "2147838252"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "NewBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/newbank/bank!saveBank.do" ascii //weight: 1
        $x_1_2 = "SMSServiceLafter" ascii //weight: 1
        $x_1_3 = "getSmsAndSendBack" ascii //weight: 1
        $x_1_4 = "newbank/com.android.sms.apk" ascii //weight: 1
        $x_1_5 = "bank!saveSms.do" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

