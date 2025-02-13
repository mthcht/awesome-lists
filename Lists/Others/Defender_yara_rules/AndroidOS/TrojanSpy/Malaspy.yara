rule TrojanSpy_AndroidOS_Malaspy_A_2147833112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Malaspy.A!MTB"
        threat_id = "2147833112"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Malaspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.malaspy" ascii //weight: 1
        $x_1_2 = "SpyDroidDbAdapter" ascii //weight: 1
        $x_1_3 = "alertIfMonkey" ascii //weight: 1
        $x_1_4 = "GmailMessagesObserver" ascii //weight: 1
        $x_1_5 = "SendKeepAliveAT" ascii //weight: 1
        $x_1_6 = "BrowSerObserver" ascii //weight: 1
        $x_1_7 = "removeActiveAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

