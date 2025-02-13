rule Trojan_Win64_SeidrStealer_DA_2147924465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SeidrStealer.DA!MTB"
        threat_id = "2147924465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SeidrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/output/wallets/electrum" ascii //weight: 10
        $x_10_2 = "api.telegram.org/bot" ascii //weight: 10
        $x_1_3 = "webdata" ascii //weight: 1
        $x_1_4 = "cookie" ascii //weight: 1
        $x_1_5 = "session" ascii //weight: 1
        $x_1_6 = "autofill" ascii //weight: 1
        $x_1_7 = "logindata" ascii //weight: 1
        $x_1_8 = "Card Number:" ascii //weight: 1
        $x_1_9 = "Password:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

