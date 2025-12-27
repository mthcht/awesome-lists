rule Trojan_MSIL_PWSStealer_D_2147959617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PWSStealer.D!AMTB"
        threat_id = "2147959617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PWSStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendTelegramMessage" ascii //weight: 1
        $x_1_2 = "GetDiscordTokens" ascii //weight: 1
        $x_1_3 = "<AntiVM>" ascii //weight: 1
        $x_1_4 = "botToken" ascii //weight: 1
        $x_1_5 = "<SendDatas>" ascii //weight: 1
        $x_1_6 = "KillVPNs" ascii //weight: 1
        $x_2_7 = "Stealer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

