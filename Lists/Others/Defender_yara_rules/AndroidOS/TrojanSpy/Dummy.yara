rule TrojanSpy_AndroidOS_Dummy_A_2147837894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Dummy.A!MTB"
        threat_id = "2147837894"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Dummy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenShotColl" ascii //weight: 1
        $x_1_2 = "MyObserverCallLogs" ascii //weight: 1
        $x_1_3 = "ChromeHistoryColl" ascii //weight: 1
        $x_1_4 = "SocialMessagesCollector" ascii //weight: 1
        $x_1_5 = "Lcom/appwork.dummy" ascii //weight: 1
        $x_1_6 = "Lcom/app/projectappkora" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

