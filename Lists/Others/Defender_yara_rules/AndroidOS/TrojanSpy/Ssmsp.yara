rule TrojanSpy_AndroidOS_Ssmsp_A_2147783354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ssmsp.A!MTB"
        threat_id = "2147783354"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ssmsp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LocationLoggerService" ascii //weight: 1
        $x_1_2 = "SentMessageGather" ascii //weight: 1
        $x_1_3 = "post.php" ascii //weight: 1
        $x_1_4 = "SMSApp" ascii //weight: 1
        $x_1_5 = "Lsms/uploader/SMSObserver" ascii //weight: 1
        $x_1_6 = "WebsiteUploader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

