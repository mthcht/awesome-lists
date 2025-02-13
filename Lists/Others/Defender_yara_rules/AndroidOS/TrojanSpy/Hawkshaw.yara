rule TrojanSpy_AndroidOS_Hawkshaw_B_2147772496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Hawkshaw.B!MTB"
        threat_id = "2147772496"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Hawkshaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hawkshaw.tasks.media.ScreenRecord" ascii //weight: 1
        $x_1_2 = "/app/hidden" ascii //weight: 1
        $x_1_3 = "/keylogger/keylogger/" ascii //weight: 1
        $x_1_4 = "me.hawkshaw.receiver" ascii //weight: 1
        $x_1_5 = "deleteAllDownloadToLocalTasks" ascii //weight: 1
        $x_1_6 = "device-info upload successful" ascii //weight: 1
        $x_1_7 = "me.hawkshaw.model.UploadTask;" ascii //weight: 1
        $x_1_8 = "me.hawkshaw.tasks.LocationMonitorFused" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_Hawkshaw_B_2147783599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Hawkshaw.B"
        threat_id = "2147783599"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Hawkshaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "me.hawkshaw" ascii //weight: 1
        $x_1_2 = "me/hawkshaw/HawkshawMainActivity" ascii //weight: 1
        $x_1_3 = "me/hawkshaw/tasks/telephony/CallRecorder" ascii //weight: 1
        $x_1_4 = "/device-info/audio" ascii //weight: 1
        $x_1_5 = "cmd.get(\"arg1\")" ascii //weight: 1
        $x_1_6 = "suthar-accessibility" ascii //weight: 1
        $x_1_7 = "/files/logs.txt" ascii //weight: 1
        $x_1_8 = "ipify.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

