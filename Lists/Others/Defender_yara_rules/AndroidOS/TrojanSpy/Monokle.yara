rule TrojanSpy_AndroidOS_Monokle_A_2147808758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Monokle.A!MTB"
        threat_id = "2147808758"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Monokle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keylogger" ascii //weight: 1
        $x_1_2 = "disableCameraSound" ascii //weight: 1
        $x_1_3 = "/system/gatekeeper.password.key" ascii //weight: 1
        $x_1_4 = "/system/media/audio/ui/VideoRecord.og" ascii //weight: 1
        $x_1_5 = "Audio record SMS to file" ascii //weight: 1
        $x_1_6 = "rm -r /system/app/MonitorSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

