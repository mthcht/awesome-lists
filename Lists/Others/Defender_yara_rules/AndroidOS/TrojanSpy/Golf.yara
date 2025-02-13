rule TrojanSpy_AndroidOS_Golf_A_2147744326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Golf.A!MTB"
        threat_id = "2147744326"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Golf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_ecap32x" ascii //weight: 1
        $x_1_2 = "getRunningAppProcesses" ascii //weight: 1
        $x_1_3 = "_voiceRecord going to audioRecorder.startVoiceRecorder()" ascii //weight: 1
        $x_1_4 = "Main service not running going to start it..." ascii //weight: 1
        $x_1_5 = "Dog is set for action" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

