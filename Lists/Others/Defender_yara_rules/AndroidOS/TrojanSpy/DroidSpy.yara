rule TrojanSpy_AndroidOS_DroidSpy_A_2147844115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DroidSpy.A!MTB"
        threat_id = "2147844115"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DroidSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postContactsList" ascii //weight: 1
        $x_1_2 = "readWebpanelCommands" ascii //weight: 1
        $x_1_3 = "deleDatabaseRecord" ascii //weight: 1
        $x_1_4 = "deviceLastKnownLocation" ascii //weight: 1
        $x_1_5 = "wipeHardReset" ascii //weight: 1
        $x_1_6 = "com.sec.provider.mobile.android" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

