rule TrojanSpy_AndroidOS_DroidWatcher_A_2147808062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DroidWatcher.A"
        threat_id = "2147808062"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DroidWatcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Android/data/q.sh" ascii //weight: 1
        $x_1_2 = "DW_Cliboard" ascii //weight: 1
        $x_1_3 = "GPS mpdule not isGpsTrackingEnabled" ascii //weight: 1
        $x_1_4 = "TGP_ENABLED" ascii //weight: 1
        $x_1_5 = "WindModule.Shoter_.ScreenshotService" ascii //weight: 1
        $x_1_6 = "whats app get new chatt..inh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

