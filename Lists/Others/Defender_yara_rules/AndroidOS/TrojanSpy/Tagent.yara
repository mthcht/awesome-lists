rule TrojanSpy_AndroidOS_Tagent_A_2147814398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Tagent.A"
        threat_id = "2147814398"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Tagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "errorWhere" ascii //weight: 1
        $x_1_2 = "everyone.evl" ascii //weight: 1
        $x_1_3 = "call rec status is" ascii //weight: 1
        $x_1_4 = "Records Log every" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

