rule TrojanSpy_AndroidOS_Mamont_A_2147910823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mamont.A!MTB"
        threat_id = "2147910823"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.saiko.rent" ascii //weight: 5
        $x_5_2 = "ua.warden.onlyfans" ascii //weight: 5
        $x_1_3 = "readLast10Messages" ascii //weight: 1
        $x_1_4 = "/codeinput.php" ascii //weight: 1
        $x_1_5 = "sendNotify" ascii //weight: 1
        $x_1_6 = "remoteMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

