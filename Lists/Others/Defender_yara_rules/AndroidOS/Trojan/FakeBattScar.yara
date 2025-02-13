rule Trojan_AndroidOS_FakeBattScar_A_2147650661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeBattScar.A"
        threat_id = "2147650661"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeBattScar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Battery Doctor would like to disable your WiFi, Bluetooth, and Dim your screen." ascii //weight: 1
        $x_1_2 = "PushAds.java" ascii //weight: 1
        $x_1_3 = "Pushing CC Ads....." ascii //weight: 1
        $x_1_4 = "SDK is disabled, please enable to receive Ads !" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

