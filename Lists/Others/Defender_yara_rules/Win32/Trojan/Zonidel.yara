rule Trojan_Win32_Zonidel_A_2147732053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonidel.A"
        threat_id = "2147732053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonidel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoUpdateDisableNotify" wide //weight: 1
        $x_1_2 = "FirewallDisableNotify" wide //weight: 1
        $x_1_3 = "http://slpsrgpsrhojifdij.ru/" ascii //weight: 1
        $x_1_4 = "http://92.63.197.48/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Zonidel_G_2147745595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonidel.G!MTB"
        threat_id = "2147745595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonidel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 31 0c c3 30 03 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 01 15 ?? ?? ?? ?? f7 e9 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? c1 fa 03 8b c2 c1 e8 1f 03 c2}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 44 24 18 30 44 24 13 a0 ?? ?? ?? ?? 68 03 01 00 00 88 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {88 0c 13 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 c1 3b 05 ?? ?? ?? ?? 7e}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 45 5b 33 45 50 88 45 5a 0f b7 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 44 0d 54 88 02 06 00 8b 55 ?? 03 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonidel_VC_2147756731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonidel.VC!MTB"
        threat_id = "2147756731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonidel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 8b c7 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 3b 33 c8 8b 44 24 ?? 2b f1 b9 ?? ?? ?? ?? 2b c8 03 d9 4d 75 ?? 8b 6c 24 ?? 89 7d ?? 5f 89 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

