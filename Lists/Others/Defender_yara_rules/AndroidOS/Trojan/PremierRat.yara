rule Trojan_AndroidOS_PremierRat_A_2147783131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PremierRat.A"
        threat_id = "2147783131"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PremierRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sendCaptureScreenShot.php" ascii //weight: 1
        $x_1_2 = "/RMPanel.apk" ascii //weight: 1
        $x_1_3 = "broadcast_calls_histroy_json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_PremierRat_B_2147783132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PremierRat.B"
        threat_id = "2147783132"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PremierRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android.os.lOCK_OPENED" ascii //weight: 1
        $x_1_2 = "AlarmRecReadSms" ascii //weight: 1
        $x_1_3 = "android.os.ReadSmses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

