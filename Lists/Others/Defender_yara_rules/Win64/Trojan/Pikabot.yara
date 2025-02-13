rule Trojan_Win64_Pikabot_AK_2147892314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pikabot.AK!MTB"
        threat_id = "2147892314"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 f0 4c 89 fa 48 89 f9 48 83 c7 02 e8 ?? ?? ?? ?? 48 89 d8 31 d2 48 83 c3 01 48 f7 f5 41 0f b6 44 15 00 30 06 48 83 c6 01 49 39 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Pikabot_KNNQ_2147898831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pikabot.KNNQ!MTB"
        threat_id = "2147898831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 3a 00 00 00 48 f7 f1 0f b6 44 14 ?? 41 8b d0 33 d0 8b 8c 24 ?? ?? ?? ?? 0f af 8c 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 2b c1 03 44 24 ?? 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 0f af 8c 24 ?? ?? ?? ?? 2b c1 03 44 24 ?? 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

