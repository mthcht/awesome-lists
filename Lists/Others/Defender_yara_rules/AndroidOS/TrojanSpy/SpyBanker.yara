rule TrojanSpy_AndroidOS_SpyBanker_B_2147828449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyBanker.B"
        threat_id = "2147828449"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowInService" ascii //weight: 1
        $x_1_2 = "getCallUpdateTime" ascii //weight: 1
        $x_1_3 = "IN=COMING_CALL" ascii //weight: 1
        $x_1_4 = "WindowOutService2" ascii //weight: 1
        $x_1_5 = "getBlackListUpdateTime" ascii //weight: 1
        $x_1_6 = "getChangeNumberWhiteList" ascii //weight: 1
        $x_1_7 = "INCOMING_CALL_STATE_OFFHOOK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyBanker_Y_2147832272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyBanker.Y"
        threat_id = "2147832272"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ETUSERNAME" ascii //weight: 1
        $x_2_2 = "Email Id is required!" ascii //weight: 2
        $x_2_3 = "com.sk.axisbank" ascii //weight: 2
        $x_1_4 = "https://axisbankstore.co" ascii //weight: 1
        $x_1_5 = "https://axisedgestore.com/" ascii //weight: 1
        $x_1_6 = "https://axisbankpoints.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

