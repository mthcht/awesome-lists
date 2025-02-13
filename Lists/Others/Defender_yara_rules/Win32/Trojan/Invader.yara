rule Trojan_Win32_Invader_RPV_2147840625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Invader.RPV!MTB"
        threat_id = "2147840625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Invader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 3b 45 0c 0f 83 21 00 00 00 0f b6 75 10 8b 45 08 8b 4d f8 0f b6 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 e9 d3 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Invader_RPN_2147841061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Invader.RPN!MTB"
        threat_id = "2147841061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Invader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 3c 81 8b 3d ?? ?? ?? ?? 03 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 31 cb 8b 35 ?? ?? ?? ?? 01 de 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 31 d6 0f af 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 31 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

