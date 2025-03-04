rule TrojanSpy_AndroidOS_Fakeapp_F_2147850116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakeapp.F!MTB"
        threat_id = "2147850116"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "showContacts" ascii //weight: 1
        $x_1_2 = "checkPermissionLoad" ascii //weight: 1
        $x_1_3 = "killApp" ascii //weight: 1
        $x_1_4 = "smslist" ascii //weight: 1
        $x_5_5 = "Lcom/fsdkfdjshkj/MainActivity" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

