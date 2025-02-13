rule Trojan_AndroidOS_Saiva_S_2147781669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Saiva.S!MTB"
        threat_id = "2147781669"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Saiva"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/downloader/AppDownloaderActivity" ascii //weight: 1
        $x_1_2 = "/downloader/SmsReceiver" ascii //weight: 1
        $x_1_3 = "/getTask.php" ascii //weight: 1
        $x_1_4 = "&balance" ascii //weight: 1
        $x_1_5 = "Last bookmark" ascii //weight: 1
        $x_1_6 = "blackNumbers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Saiva_A_2147831237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Saiva.A!MTB"
        threat_id = "2147831237"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Saiva"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blackNumbers" ascii //weight: 1
        $x_1_2 = "sendtimer" ascii //weight: 1
        $x_1_3 = "/downloader/SmsReceiver" ascii //weight: 1
        $x_1_4 = "deliveredPI" ascii //weight: 1
        $x_1_5 = "AppDownloaderActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

