rule TrojanSpy_AndroidOS_Goatrat_A_2147842767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Goatrat.A!MTB"
        threat_id = "2147842767"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Goatrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "srv.yakuzacheckers.com/web-admin/" ascii //weight: 1
        $x_1_2 = "goatrat" ascii //weight: 1
        $x_1_3 = "ScreenSharingService" ascii //weight: 1
        $x_1_4 = "/rtp-web-admin/" ascii //weight: 1
        $x_1_5 = "DiscordWebhook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Goatrat_C_2147890539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Goatrat.C!MTB"
        threat_id = "2147890539"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Goatrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.hmdm.remoteservice" ascii //weight: 1
        $x_1_2 = "ACTION_SCREEN_SHARING_PERMISSION_NEEDED" ascii //weight: 1
        $x_1_3 = "EXTRA_WEBRTCUP" ascii //weight: 1
        $x_1_4 = "test_src_ip" ascii //weight: 1
        $x_1_5 = "/rest/plugins/apuppet/public/session" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

