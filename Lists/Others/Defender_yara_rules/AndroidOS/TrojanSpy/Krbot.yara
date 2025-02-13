rule TrojanSpy_AndroidOS_Krbot_A_2147755803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Krbot.A!MTB"
        threat_id = "2147755803"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Krbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.example.dat.a8andoserverx" ascii //weight: 1
        $x_1_2 = "/DCIM/.fdat" ascii //weight: 1
        $x_1_3 = "/DCIM/.csp" ascii //weight: 1
        $x_1_4 = "MyWakelockTgggag" ascii //weight: 1
        $x_1_5 = "/DCIM/.dat/Out_" ascii //weight: 1
        $x_1_6 = "file:///sdcard/.app.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

