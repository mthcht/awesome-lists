rule Trojan_MSIL_RocketXStealer_PA_2147753569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RocketXStealer.PA!MTB"
        threat_id = "2147753569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RocketXStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DashCore\\wallet.dat" wide //weight: 1
        $x_1_2 = "BitcoinCore\\wallet.dat" wide //weight: 1
        $x_1_3 = "RocketXStealer" ascii //weight: 1
        $x_1_4 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_5 = "\\Google\\Chrome\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_6 = "credit_cards" wide //weight: 1
        $x_1_7 = "Browsers\\Passwords.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

