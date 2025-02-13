rule Trojan_Win32_Valak_PA_2147748087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valak.PA!MTB"
        threat_id = "2147748087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 6c 24 14 05 ?? ?? ?? ?? 89 84 2a ?? ?? ?? ?? 0f b6 15 ?? ?? ?? 00 a3 d4 54 4d 00 0f b6 05 ?? ?? ?? 00 2b c2 3d ?? ?? 00 00 89 44 24 10 74 26 a1 ?? ?? ?? 00 8a d0 02 d3 80 ea 03 88 15 ?? ?? ?? 00 8b d7 c1 e2 04 03 d7 2b d1 03 d6}  //weight: 10, accuracy: Low
        $x_1_2 = {66 29 0c 45 ?? ?? ?? 00 8b df 0f af de 69 db 37 09 00 00 83 e8 01 85 c0 8b f3 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Valak_DEA_2147755760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valak.DEA!MTB"
        threat_id = "2147755760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 0f b7 f1 8b 44 24 1c 81 c2 ?? ?? ?? ?? 83 44 24 14 04 0f b7 ce 89 55 00 8b 6c 24 20 81 c5 ?? ?? ?? ?? 8d 04 41 03 c7 8d 04 41 03 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valak_DEB_2147755953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valak.DEB!MTB"
        threat_id = "2147755953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 18 81 c1 ?? ?? ?? ?? 8b 44 24 14 05 ?? ?? ?? ?? 89 44 24 14 89 02 8b 54 24 10 0f b7 d2 c1 e2 02 2b d6 a3 ?? ?? ?? ?? 03 d1 8b 4c 24 10 0f b7 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

