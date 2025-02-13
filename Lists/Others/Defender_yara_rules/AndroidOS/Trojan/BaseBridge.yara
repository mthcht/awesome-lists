rule Trojan_AndroidOS_BaseBridge_A_2147646889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BaseBridge.A"
        threat_id = "2147646889"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BaseBridge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "first_app_perferences" ascii //weight: 1
        $x_1_2 = "battery/BalckActivity" ascii //weight: 1
        $x_1_3 = "battery/BaseBroadcastReceiver" ascii //weight: 1
        $x_1_4 = "battery/ZlPhoneService" ascii //weight: 1
        $x_1_5 = "%phonenum=? and mouthcount>=mouthtimes" ascii //weight: 1
        $x_1_6 = "DROP TABLE IF EXISTS telphone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BaseBridge_B_2147646890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BaseBridge.B"
        threat_id = "2147646890"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BaseBridge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "battery/BalckActivity2" ascii //weight: 1
        $x_1_2 = "KillThreeSixZero" ascii //weight: 1
        $x_1_3 = "receiver/ReceiverBlackActiveStart2" ascii //weight: 1
        $x_1_4 = "/battery/BridgeProvider" ascii //weight: 1
        $x_1_5 = "hasNotInstalled_360 :" ascii //weight: 1
        $x_1_6 = "sl4arP0RcD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BaseBridge_A_2147650805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BaseBridge.gen!A"
        threat_id = "2147650805"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BaseBridge"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xxx.apk" ascii //weight: 1
        $x_1_2 = "anServerB" ascii //weight: 1
        $x_1_3 = "anServerB.so" ascii //weight: 1
        $x_1_4 = "eHh4LmFwaw==" ascii //weight: 1
        $x_1_5 = "YW5TZXJ2ZXJCLnNv" ascii //weight: 1
        $x_1_6 = "SMSApp.apk" ascii //weight: 1
        $x_1_7 = "global_b_version_id" ascii //weight: 1
        $x_1_8 = "Got processid:" ascii //weight: 1
        $x_1_9 = "first_app_perferences" ascii //weight: 1
        $x_1_10 = "a_BServer3" ascii //weight: 1
        $x_1_11 = "hasBRuning" ascii //weight: 1
        $x_1_12 = "7xBNzKFCzKFW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

