rule Trojan_Win32_BotX_RDA_2147846996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BotX.RDA!MTB"
        threat_id = "2147846996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BotX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BotX_GAB_2147898280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BotX.GAB!MTB"
        threat_id = "2147898280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BotX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8d 34 19 6a ?? 8b c1 5d f7 f5 80 c2 ?? 32 14 37 41 88 16 83 f9 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BotX_GZF_2147902380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BotX.GZF!MTB"
        threat_id = "2147902380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BotX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 03 c7 d3 ea 89 45 ?? 8b 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 89 45 ?? 89 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c2 2b f0 8b c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

