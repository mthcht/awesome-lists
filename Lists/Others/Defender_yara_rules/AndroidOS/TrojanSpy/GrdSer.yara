rule TrojanSpy_AndroidOS_GrdSer_A_2147810012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GrdSer.A!MTB"
        threat_id = "2147810012"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GrdSer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gradleservice.info" ascii //weight: 2
        $x_1_2 = ".MainActivityFake" ascii //weight: 1
        $x_1_3 = "Google protect is enabled" ascii //weight: 1
        $x_1_4 = "processPassword(document.getElementsByName('password')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

