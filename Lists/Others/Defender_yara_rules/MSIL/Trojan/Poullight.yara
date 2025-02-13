rule Trojan_MSIL_Poullight_PA_2147753568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Poullight.PA!MTB"
        threat_id = "2147753568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Poullight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BTC-Ethereum" wide //weight: 1
        $x_1_2 = "BTC-Monero" wide //weight: 1
        $x_1_3 = "Browsers\\Passwords.txt" wide //weight: 1
        $x_1_4 = "Clipboard.txt" wide //weight: 1
        $x_1_5 = "Stealer Files" wide //weight: 1
        $x_1_6 = "ScreenShot.png" wide //weight: 1
        $x_1_7 = "WebCam.jpg" wide //weight: 1
        $x_1_8 = "Google\\Chrome\\User Data" wide //weight: 1
        $x_1_9 = "Yandex\\YandexBrowser\\User Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Poullight_SA_2147755339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Poullight.SA!MSR"
        threat_id = "2147755339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Poullight"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Browsers\\Passwords.txt" wide //weight: 1
        $x_1_2 = "copyboard.txt" wide //weight: 1
        $x_1_3 = "ScreenShot.png" wide //weight: 1
        $x_1_4 = "WebCam.jpg" wide //weight: 1
        $x_1_5 = "Google\\Chrome\\User Data" wide //weight: 1
        $x_1_6 = "Torch\\User Data" wide //weight: 1
        $x_1_7 = "Poullight" wide //weight: 1
        $x_1_8 = "Stealer by" wide //weight: 1
        $x_1_9 = "monero-core" wide //weight: 1
        $x_1_10 = "Bitcoin-Qt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

