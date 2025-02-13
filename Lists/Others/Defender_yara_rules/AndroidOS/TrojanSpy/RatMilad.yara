rule TrojanSpy_AndroidOS_RatMilad_A_2147833191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RatMilad.A!MTB"
        threat_id = "2147833191"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RatMilad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendCallLogs" ascii //weight: 1
        $x_1_2 = "textme.network" ascii //weight: 1
        $x_1_3 = "contactList" ascii //weight: 1
        $x_1_4 = "sendGPSToServer" ascii //weight: 1
        $x_1_5 = "SoundRecorder" ascii //weight: 1
        $x_1_6 = "sendSMSList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

