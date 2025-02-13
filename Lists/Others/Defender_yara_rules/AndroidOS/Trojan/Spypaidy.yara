rule Trojan_AndroidOS_Spypaidy_A_2147836894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spypaidy.A"
        threat_id = "2147836894"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spypaidy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.richsjeson.kotlin.sms.UploadContacts$Companion$doUpload$1" ascii //weight: 1
        $x_1_2 = "wifiPwd" ascii //weight: 1
        $x_1_3 = "sendSmsSilent" ascii //weight: 1
        $x_1_4 = "hideNotificationAfterO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

