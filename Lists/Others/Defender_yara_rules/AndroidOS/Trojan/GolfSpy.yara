rule Trojan_AndroidOS_GolfSpy_A_2147794015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GolfSpy.A"
        threat_id = "2147794015"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GolfSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CommunicatorService" ascii //weight: 1
        $x_1_2 = "ToolsNavigateService" ascii //weight: 1
        $x_1_3 = "Camera Pictures Received in Last 7 Days" ascii //weight: 1
        $x_1_4 = "audioRecorder.startVoiceRecorder" ascii //weight: 1
        $x_1_5 = "Device isEmulator!!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

