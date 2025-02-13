rule TrojanSpy_AndroidOS_WyrmSpy_C_2147851371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/WyrmSpy.C!MTB"
        threat_id = "2147851371"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "WyrmSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com/flash18/MainActivity" ascii //weight: 5
        $x_5_2 = "FakeActivity" ascii //weight: 5
        $x_1_3 = "ChangeQuickRedirect" ascii //weight: 1
        $x_1_4 = "service_invoker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

