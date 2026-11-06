rule Trojan_MSIL_DarknessStealer_SG_2147981333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarknessStealer.SG!MTB"
        threat_id = "2147981333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarknessStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DarknessStealer" ascii //weight: 3
        $x_3_2 = "DarknessGrabber" ascii //weight: 3
        $x_3_3 = "SendDiscordWebhookWithFile" ascii //weight: 3
        $x_2_4 = "Discord Tokens.txt" ascii //weight: 2
        $x_2_5 = "WiFi_Passwords.txt" ascii //weight: 2
        $x_2_6 = "Discord_Tokens.txt" ascii //weight: 2
        $x_2_7 = "DiscordTokens.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarknessStealer_AMTB_2147981672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarknessStealer!AMTB"
        threat_id = "2147981672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarknessStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DarknessGrabber" ascii //weight: 2
        $x_2_2 = "DarknessStealer" ascii //weight: 2
        $x_1_3 = "SendDiscordWebhookWithFile" ascii //weight: 1
        $x_1_4 = "Gift Codes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

