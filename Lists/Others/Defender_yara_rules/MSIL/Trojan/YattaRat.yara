rule Trojan_MSIL_YattaRat_AT_2147982795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/YattaRat.AT!MTB"
        threat_id = "2147982795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "YattaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yatta_client" ascii //weight: 1
        $x_1_2 = "yatta_snd_current" ascii //weight: 1
        $x_1_3 = "close yatta_snd" ascii //weight: 1
        $x_1_4 = "play yatta_snd" ascii //weight: 1
        $x_1_5 = "stop yatta_snd" ascii //weight: 1
        $x_1_6 = "yatta_wallpaper_current" ascii //weight: 1
        $x_1_7 = "yatta_client.DiscordRecovery+<GetDiscordPaths>" ascii //weight: 1
        $x_1_8 = "yatta_client.DiscordRecovery+<GetChromiumPaths>" ascii //weight: 1
        $x_1_9 = "yatta_scream" ascii //weight: 1
        $x_1_10 = "KEYLOG_START" ascii //weight: 1
        $x_1_11 = "KEYLOG_STOP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

