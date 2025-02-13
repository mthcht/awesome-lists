rule TrojanSpy_AndroidOS_YangaMon_A_2147648168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/YangaMon.A"
        threat_id = "2147648168"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "YangaMon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android.fzbk.info/AndroidInterface/Reg.aspx" ascii //weight: 1
        $x_1_2 = "MonitorService.beginFee" ascii //weight: 1
        $x_1_3 = "smsFeeInfo" ascii //weight: 1
        $x_1_4 = "haiyang:createdb=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

