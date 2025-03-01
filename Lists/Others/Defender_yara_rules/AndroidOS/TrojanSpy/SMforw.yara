rule TrojanSpy_AndroidOS_SMforw_E_2147794226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMforw.E"
        threat_id = "2147794226"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GRNumNC|*|" ascii //weight: 1
        $x_1_2 = "SEND_SMS_NUM" ascii //weight: 1
        $x_1_3 = "CONNECT_SUCCEED" ascii //weight: 1
        $x_1_4 = "CgData|*|" ascii //weight: 1
        $x_1_5 = "conMan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

