rule MonitoringTool_AndroidOS_Spy24_A_300434_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spy24.A!MTB"
        threat_id = "300434"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spy24"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/spy24/wifi/recordAudio/" ascii //weight: 2
        $x_1_2 = "getLastInstagramMessage" ascii //weight: 1
        $x_1_3 = "startSchuler" ascii //weight: 1
        $x_1_4 = "locationFromSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

