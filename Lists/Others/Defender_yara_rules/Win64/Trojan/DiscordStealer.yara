rule Trojan_Win64_DiscordStealer_AHB_2147946419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordStealer.AHB!MTB"
        threat_id = "2147946419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 57 c0 0f 11 45 ?? 4c 89 ?? ?? 4c 89 ?? ?? 0f 10 00 0f 11 45 ?? 0f 10 48 10 0f 11 4d ?? 4c 89 ?? 10 48 c7 40 18 0f 00 00 00 c6 00 00 48 8b 54 24 ?? 48 83 fa 0f}  //weight: 5, accuracy: Low
        $x_1_2 = "\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_3 = "webhook.site" ascii //weight: 1
        $x_1_4 = "\\discordcanary" ascii //weight: 1
        $x_1_5 = "\\Lightcord" ascii //weight: 1
        $x_1_6 = "\\discordptb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

