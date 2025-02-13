rule Trojan_Win64_TrickBotCrypt_EN_2147796852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBotCrypt.EN!MTB"
        threat_id = "2147796852"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 04 00 88 04 11 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 54 24 30 03 d0 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 48 63 d0 48 8b 4c 24 50 0f b6 44 24 24 88 04 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrickBotCrypt_ER_2147796935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBotCrypt.ER!MTB"
        threat_id = "2147796935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 0f b6 04 21 03 c8 b8 ab 00 a0 aa f7 e1 c1 ea 0d 69 d2 03 30 00 00 2b ca 48 63 c1 48 2b c7 48 03 44 24 20 48 03 c6 42 0f b6 04 20 43 30 04 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

