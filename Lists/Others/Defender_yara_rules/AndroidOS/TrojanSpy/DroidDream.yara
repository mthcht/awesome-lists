rule TrojanSpy_AndroidOS_DroidDream_A_2147643790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DroidDream.A"
        threat_id = "2147643790"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DroidDream"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadProvidersManager.apk" ascii //weight: 1
        $x_1_2 = "sqlite.db" ascii //weight: 1
        $x_1_3 = "/root/AlarmReceiver" ascii //weight: 1
        $x_1_4 = "go4root" ascii //weight: 1
        $x_1_5 = "rageagainstthecage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

