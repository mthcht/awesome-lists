rule Trojan_AndroidOS_Faketoken_F_2147901526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Faketoken.F!MTB"
        threat_id = "2147901526"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Faketoken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callAccessAdmin" ascii //weight: 1
        $x_1_2 = "com/system/f" ascii //weight: 1
        $x_1_3 = "custom.alarm.info" ascii //weight: 1
        $x_1_4 = "EXTRA_SK" ascii //weight: 1
        $x_1_5 = "ADD_DEVICE_ADMIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

