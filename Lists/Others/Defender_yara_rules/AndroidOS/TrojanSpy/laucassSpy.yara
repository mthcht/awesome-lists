rule TrojanSpy_AndroidOS_laucassSpy_A_2147783173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/laucassSpy.A!MTB"
        threat_id = "2147783173"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "laucassSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "remote_record" ascii //weight: 1
        $x_1_2 = "com.laucass.androsmscontrol" ascii //weight: 1
        $x_1_3 = "hide_keyword_sms" ascii //weight: 1
        $x_1_4 = "PhoneControlDeviceAdminReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

