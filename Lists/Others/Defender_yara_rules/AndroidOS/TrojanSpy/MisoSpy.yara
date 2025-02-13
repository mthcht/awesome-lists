rule TrojanSpy_AndroidOS_MisoSpy_A_2147824239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/MisoSpy.A!MTB"
        threat_id = "2147824239"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "MisoSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/SinRecv;" ascii //weight: 1
        $x_1_2 = "/LSecScreen;" ascii //weight: 1
        $x_1_3 = "RequestStruct_RecPhoneInfo" ascii //weight: 1
        $x_1_4 = "arrayOfSmsMessage" ascii //weight: 1
        $x_1_5 = "startAddDeviceAdminAty" ascii //weight: 1
        $x_1_6 = "content://sms/inbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

