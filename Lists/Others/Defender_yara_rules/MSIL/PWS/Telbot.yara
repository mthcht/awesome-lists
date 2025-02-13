rule PWS_MSIL_Telbot_GA_2147807553_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Telbot.GA!MTB"
        threat_id = "2147807553"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Telbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Botnet" ascii //weight: 1
        $x_1_2 = "Telegram" ascii //weight: 1
        $x_1_3 = "http://ipinfo.io/ip" ascii //weight: 1
        $x_1_4 = "solarwinds" ascii //weight: 1
        $x_1_5 = "Ethereal" ascii //weight: 1
        $x_1_6 = "MegaDumper" ascii //weight: 1
        $x_1_7 = "dnspy" ascii //weight: 1
        $x_1_8 = "BotClient" ascii //weight: 1
        $x_1_9 = "HI, YOU ARE BOT VICTIM" ascii //weight: 1
        $x_1_10 = "Chrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

