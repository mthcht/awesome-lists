rule TrojanSpy_AndroidOS_FakeToken_A_2147655044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeToken.A"
        threat_id = "2147655044"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeToken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendContactsToServer" ascii //weight: 1
        $x_1_2 = "Ltoken/bot/AutorunReceiver" ascii //weight: 1
        $x_1_3 = "Ltoken/bot/SendSmsResult" ascii //weight: 1
        $x_1_4 = "Ltoken/bot/ServerResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

