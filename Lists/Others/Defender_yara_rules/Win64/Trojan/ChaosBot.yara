rule Trojan_Win64_ChaosBot_AMTB_2147956300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChaosBot!AMTB"
        threat_id = "2147956300"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChaosBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4a 20 48 8b 42 28 48 8b 40 18 48 8d 15 6a eb 56 00 e9 d9 00 00 00 48 8b 4a 20 48 8b 42 28 48 8b 40 18 48 8d 15 93 eb 56 00 41 b8 13 00 00 00 48 83 c4 40 5e 48 ff e0 48 8b 4a 20 48 8b 42 28 48 8b 40 18 48 8d 15 1b eb 56 00 e9 c1 00 00 00 48 8b 4a 20 48 8b 42 28 48 8b 40 18}  //weight: 2, accuracy: High
        $x_2_2 = "discord_control.pdb" ascii //weight: 2
        $x_1_3 = "guild_scheduled_welcome_channelspremium_subscriber" ascii //weight: 1
        $x_1_4 = "RULE_DELETECTION_REMOVE_ALL-C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ChaosBot_ARA_2147959969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChaosBot.ARA!MTB"
        threat_id = "2147959969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChaosBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4c 8b 04 11 4c 33 04 08 4c 89 84 0d 00 01 00 00 48 83 c1 08 eb e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

