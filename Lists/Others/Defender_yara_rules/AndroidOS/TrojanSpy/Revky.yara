rule TrojanSpy_AndroidOS_Revky_YA_2147755951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Revky.YA!MTB"
        threat_id = "2147755951"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Revky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rev/keylog/logs.ser" ascii //weight: 1
        $x_1_2 = "notifications/notifications.ser" ascii //weight: 1
        $x_1_3 = "rev/screenshots" ascii //weight: 1
        $x_1_4 = "system/bin/screencap -p" ascii //weight: 1
        $x_1_5 = "revcode/screenshots" ascii //weight: 1
        $x_1_6 = "revcode/recordings" ascii //weight: 1
        $x_1_7 = "RecordCallsService STATE_START_RECORDING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

