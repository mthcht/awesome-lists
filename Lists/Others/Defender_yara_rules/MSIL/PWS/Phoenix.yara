rule PWS_MSIL_Phoenix_GG_2147798228_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Phoenix.GG!MTB"
        threat_id = "2147798228"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phoenix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Grabber" ascii //weight: 10
        $x_1_2 = "\\MetaMask\\" ascii //weight: 1
        $x_1_3 = "Wallets" ascii //weight: 1
        $x_1_4 = "\\Ronin\\" ascii //weight: 1
        $x_1_5 = "\\Binance\\" ascii //weight: 1
        $x_1_6 = "<Pass encoding=\"base64\">" ascii //weight: 1
        $x_1_7 = "Clipboard." ascii //weight: 1
        $x_1_8 = "\\OpenVPN" ascii //weight: 1
        $x_1_9 = "255.255.255.255" ascii //weight: 1
        $x_1_10 = "Login:" ascii //weight: 1
        $x_1_11 = "Games:" ascii //weight: 1
        $x_1_12 = "ftp.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

