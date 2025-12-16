rule TrojanSpy_AndroidOS_GigaFlower_AMTB_2147959561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GigaFlower!AMTB"
        threat_id = "2147959561"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GigaFlower"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendLockScreenPasswordRequest" ascii //weight: 2
        $x_2_2 = "18.140.4.4" ascii //weight: 2
        $x_1_3 = "readAndSendSms" ascii //weight: 1
        $x_1_4 = "LoadAppsInfoTask" ascii //weight: 1
        $x_1_5 = "isAccessibilityEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

