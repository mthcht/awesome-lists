rule TrojanSpy_AndroidOS_Nickispy_A_2147648455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Nickispy.A"
        threat_id = "2147648455"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Nickispy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/nicky/lyyws/xmall" ascii //weight: 1
        $x_1_2 = "jin.56mo.com" ascii //weight: 1
        $x_1_3 = "/sdcard/shangzhou/callrecord/" ascii //weight: 1
        $x_1_4 = "XM_SmsListener$SmsContent" ascii //weight: 1
        $x_1_5 = "XM_CallRecordService$TeleListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Nickispy_B_2147648456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Nickispy.B"
        threat_id = "2147648456"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Nickispy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Brocast ACTION_BOOT_COMPLETED receiver" ascii //weight: 1
        $x_1_2 = "has been runned" ascii //weight: 1
        $x_1_3 = "phonespy.END_CALL" ascii //weight: 1
        $x_1_4 = "PHONE_SPY_TAG" ascii //weight: 1
        $x_1_5 = "Brocast TEST receiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

