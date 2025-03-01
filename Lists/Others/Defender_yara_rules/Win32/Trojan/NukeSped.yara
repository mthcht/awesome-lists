rule Trojan_Win32_Nukesped_PA_2147742749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nukesped.PA!MTB"
        threat_id = "2147742749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 3e 32 d0 88 14 3e 46 3b f3 7c}  //weight: 1, accuracy: High
        $x_2_2 = {56 8b f1 e8 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? 8b 4e ?? 8b 56 ?? 8b 46 ?? 33 ca 33 c8 5e 8b c1 8b d1 c1 e8 18 c1 ea 10 32 c2 8b d1 c1 ea 08 32 c2 32 c1 c3}  //weight: 2, accuracy: Low
        $x_1_3 = {8a 11 32 d0 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
        $x_2_4 = {55 8b ec 83 ec ?? 89 4d ?? 8b 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? e8 ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 8b 50 ?? 33 51 ?? 8b 45 ?? 33 50 ?? 89 55 ?? 8b 4d ?? 81 e1 ff 00 00 00 8b 55 ?? c1 ea 08 81 e2 ff 00 00 00 33 ca 8b 45 ?? c1 e8 10 25 ff 00 00 00 33 c8 8b 55 ?? c1 ea 18 81 e2 ff 00 00 00 33 ca 88 4d ?? 8a 45 ?? 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

