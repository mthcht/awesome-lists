rule TrojanDropper_Win32_Zbot_FAU_2147631170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zbot.FAU"
        threat_id = "2147631170"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pisgrro" ascii //weight: 1
        $x_1_2 = {0f b6 08 8b ?? ?? 8b 45 08 8b 14 90 d3 ea a1 ?? ?? ?? ?? 0f b6 08 b8 ?? ?? ?? ?? 2b c1 8b ?? ?? 8b 75 08 8b 34 8e 8b c8 d3 e6 0b d6 8b ?? ?? 8b 4d 10 89 14 81 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Zbot_2147637812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zbot"
        threat_id = "2147637812"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 55 ?? 83 c2 01 89 55 ?? 83 7d ?? 29 73 1e 8b 45 ?? 0f b6 4c 05 ?? 85 c9 74 10 8b 55 ?? 81 c2 c9 02 00 00 8b 45 ?? 88 54 05 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

