rule Backdoor_AndroidOS_Sniffer_A_2147822883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Sniffer.A!MTB"
        threat_id = "2147822883"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Sniffer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsCallReceiver" ascii //weight: 1
        $x_1_2 = "UrlSniffer" ascii //weight: 1
        $x_1_3 = "SMSObserver" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
        $x_1_5 = "/UploadCaptureImage" ascii //weight: 1
        $x_1_6 = "/SaveCallRecorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

