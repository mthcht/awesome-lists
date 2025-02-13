rule TrojanSpy_AndroidOS_Noino_A_2147831333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Noino.A!MTB"
        threat_id = "2147831333"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Noino"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AndroidUiService.apk" ascii //weight: 1
        $x_1_2 = "get_onion_bonus_url" ascii //weight: 1
        $x_1_3 = "last_sms_pin_time" ascii //weight: 1
        $x_1_4 = ",onionmobishare.action_offline_start_download" ascii //weight: 1
        $x_1_5 = "'onionmobishare.kit.click.finish.install" ascii //weight: 1
        $x_1_6 = "com.kpt.xploree.app.demo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

