rule TrojanSpy_AndroidOS_GPSSpy_A_2147792919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GPSSpy.A!MTB"
        threat_id = "2147792919"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GPSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tracking already enabled!" ascii //weight: 1
        $x_1_2 = "gpspoints/addPoint" ascii //weight: 1
        $x_1_3 = "BootDetector" ascii //weight: 1
        $x_1_4 = "/sms/controller" ascii //weight: 1
        $x_1_5 = "routecentral.maxicom.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

