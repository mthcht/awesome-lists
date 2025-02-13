rule TrojanSpy_AndroidOS_FakeSecSuit_A_2147657476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeSecSuit.A"
        threat_id = "2147657476"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeSecSuit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ActivationId" ascii //weight: 1
        $x_1_2 = "Alternative Control is on. We cant use scheduller" ascii //weight: 1
        $x_1_3 = "to=%s&i=%s&m=%s&aid=%s&h=%s&v=%s" ascii //weight: 1
        $x_1_4 = "secsuite.db" ascii //weight: 1
        $x_1_5 = "GetAntivirusLink" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

