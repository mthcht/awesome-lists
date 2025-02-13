rule TrojanSpy_AndroidOS_FakeRewards_A_2147853326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeRewards.A!MTB"
        threat_id = "2147853326"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeRewards"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "readLatestMessage: new child name" ascii //weight: 1
        $x_1_2 = "fetchSMSMessages" ascii //weight: 1
        $x_1_3 = "content://sms/inbox" ascii //weight: 1
        $x_1_4 = "isPackageInstalled: linking" ascii //weight: 1
        $x_1_5 = "callLoginActivity: App url equal" ascii //weight: 1
        $x_1_6 = "callLoginActivity: http://onlinewsv.com/apps/icfiles/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

