rule Trojan_AndroidOS_Fakewallet_C_2147842142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakewallet.C!MTB"
        threat_id = "2147842142"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakewallet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bosinfo.mytokenpocket.vip" ascii //weight: 1
        $x_1_2 = "com/tokenbank/activity/splash" ascii //weight: 1
        $x_1_3 = "/v1/info/get_permission" ascii //weight: 1
        $x_1_4 = "btc-wallet/segwit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

