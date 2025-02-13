rule TrojanSpy_AndroidOS_Fakenocam_A_2147759335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakenocam.A!MTB"
        threat_id = "2147759335"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakenocam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?type=comeOnCall" ascii //weight: 1
        $x_1_2 = "a2_hyundaecard.mp3" ascii //weight: 1
        $x_1_3 = "/HeartBeatReceiver" ascii //weight: 1
        $x_1_4 = "deleteCallLog" ascii //weight: 1
        $x_1_5 = "pm install -r" ascii //weight: 1
        $x_1_6 = "killBackgroundProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

