rule Trojan_AndroidOS_FakeNotify_A_2147652165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeNotify.A"
        threat_id = "2147652165"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeNotify"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "res/raw/data.db" ascii //weight: 1
        $x_1_2 = "DownloadAndInstall" ascii //weight: 1
        $x_1_3 = "licenseScreens" ascii //weight: 1
        $x_1_4 = "addSentSms" ascii //weight: 1
        $x_1_5 = "RepeatingAlarmService START !!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

