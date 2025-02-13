rule TrojanSpy_AndroidOS_BajaSpy_A_2147837895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/BajaSpy.A!MTB"
        threat_id = "2147837895"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "BajaSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/servlet/SendMassage" ascii //weight: 1
        $x_5_2 = "kk/chunyu/MainActivity" ascii //weight: 5
        $x_1_3 = "mybank" ascii //weight: 1
        $x_1_4 = "/system/app/superuser.apk" ascii //weight: 1
        $x_1_5 = "snedPhone" ascii //weight: 1
        $x_1_6 = "SMSObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

