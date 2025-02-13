rule Trojan_Win32_QakbotPacker_2147813006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotPacker!MTB"
        threat_id = "2147813006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 30 [0-48] 83 e2 00 [0-48] d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 1c 30 [0-48] d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_QakbotPacker_2147813006_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotPacker!MTB"
        threat_id = "2147813006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 33 4d ?? 89 4d ?? 0f b6 15 ?? ?? ?? ?? 03 55 ?? 89 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 8a 4d ?? 88 08 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakbotPacker_AC_2147840057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotPacker.AC!MTB"
        threat_id = "2147840057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 03 1d ?? ?? ?? ?? 43 [0-48] 03 d8 43 a1 ?? ?? ?? ?? 33 18 89 1d [0-48] 8b 1d ?? ?? ?? ?? 2b d8 [0-48] 2b d8 [0-48] 2b d8 a1 ?? ?? ?? ?? 89 18 [0-48] 8b 1d ?? ?? ?? ?? 83 c3 04 2b d8 [0-48] 2b d8 89 1d ?? ?? ?? ?? 33 c0 a3 [0-48] 8b 1d ?? ?? ?? ?? 83 c3 04 03 1d ?? ?? ?? ?? 2b d8 [0-48] 2b d8 [0-48] 03 d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakbotPacker_AF_2147840443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotPacker.AF!MTB"
        threat_id = "2147840443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 66 3b ff 74 ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 3a c0 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 03 45 ?? 0f b6 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QakbotPacker_AZ_2147843270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotPacker.AZ!MTB"
        threat_id = "2147843270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 03 05 ?? ?? ?? ?? 03 d8 [0-16] 03 d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 33 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 48 a3 ?? ?? ?? ?? [0-16] 8b d8 a1 ?? ?? ?? ?? 8b 00 03 05 ?? ?? ?? ?? 03 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

