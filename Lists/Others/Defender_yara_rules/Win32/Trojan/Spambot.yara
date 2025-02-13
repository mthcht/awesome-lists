rule Trojan_Win32_Spambot_B_2147598044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spambot.B"
        threat_id = "2147598044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spambot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 57 56 53 [0-48] 31 db 66 90 c7 04 24 ?? ?? ?? ?? 0f b6 b3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 d2 89 c1 89 d8 f7 f1 89 f0 83 c3 01 83 ec 04 32 82 ?? ?? ?? ?? 88 83 ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 75 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spambot_SMC_2147750587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spambot.SMC!MTB"
        threat_id = "2147750587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spambot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 74 08 ?? 8d 14 16 81 e2 ?? ?? ?? ?? 8a 5c 10 00 88 5c 08 00 8b de 88 5c 10 00 33 db 8a 5c 08 00 03 f3 81 e6 01 8b 5d ?? 8b 7d ?? 8a 1c 3b 32 5c 30 00 8b 75 ?? 8b 7d 08 88 1c 3e}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 f1 03 d7 8a 02 88 84 1d ?? ?? ?? ff 83 c3 ?? 81 fb ?? ?? ?? ?? 0f 82 27 00 8b c3 04 ?? 88 44 1e ?? 8d 43 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spambot_RPY_2147892674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spambot.RPY!MTB"
        threat_id = "2147892674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spambot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 c8 8b 45 c8 8b 40 3c 8b 4d f0 8d 44 01 04 89 45 e4 8b 45 e4 0f b7 40 10 8b 4d c8 8b 49 3c 8d 44 01 18 89 45 a0 8b 45 c8 03 45 a0 89 45 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

