rule Trojan_MSIL_TeapotStealer_CH_2147940924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TeapotStealer.CH!MTB"
        threat_id = "2147940924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TeapotStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<GetAllCookies>" ascii //weight: 2
        $x_2_2 = "<GetDebugWsUrl>" ascii //weight: 2
        $x_2_3 = "<ProcessChromiumCookies>" ascii //weight: 2
        $x_2_4 = "<ProcessFirefoxCookies>" ascii //weight: 2
        $x_2_5 = "<CollectAndUploadCookies>" ascii //weight: 2
        $x_2_6 = "<CollectPasswords>" ascii //weight: 2
        $x_1_7 = "Wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

