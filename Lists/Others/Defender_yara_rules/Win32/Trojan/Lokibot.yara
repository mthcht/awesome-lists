rule Trojan_Win32_lokibot_SI_2147731698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.SI!MTB"
        threat_id = "2147731698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 e8 ?? ?? ?? ?? [0-16] 43 4e 75 80 00 8b ?? fc 03 ?? f8 [0-16] 8a ?? [0-16] [0-32] [0-2] [0-16] 88 ?? [0-16] 8d 45 f8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75 ?? [0-16] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_lokibot_SI_2147731698_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.SI!MTB"
        threat_id = "2147731698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 ec 89 55 f8 89 45 fc [0-16] c6 45 ef f1 [0-16] 8b 45 fc 89 45 f4 8b 45 f4 8a 80 14 e0 47 00 30 45 ef 8b 45 f8 89 45 f0 [0-16] 8b 45 f0 8a 55 ef 88 10 [0-16] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f4 8b 45 f8 e8 ?? ?? ff ff ff 45 f8 81 7d f8 ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 83 c4 f8 89 55 fc 89 45 f8 [0-16] 8b 7d fc 03 7d f8 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_lokibot_RPC_2147795855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.RPC!MTB"
        threat_id = "2147795855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 10 8b 55 94 8a c3 32 45 93 85 c9 75}  //weight: 1, accuracy: High
        $x_1_2 = {ff 45 80 8b 45 80 3b 45 0c 0f 8c ?? ?? ?? ?? 8b 4d f8 5f 5e 33 cd 5b e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_lokibot_RPD_2147795856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.RPD!MTB"
        threat_id = "2147795856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0e 80 79 0f 00 89 08 75 40 8b 51 08 80 7a 0f 00 75 1a 8b 0a 80 79 0f 00 75 0f eb 03 8d 49 00 8b d1 8b 0a 80 79 0f 00 74 f6 89 16 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 49 04 80 79 0f 00 75 12 8b 16 3b 51 08 75 0b 89 0e 8b 49 04 80 79 0f 00 74 ee 89 0e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_lokibot_RPE_2147795857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.RPE!MTB"
        threat_id = "2147795857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 28 03 c2 8a 0c 38 39 9c 24 c0 00 00 00 74 07 b8 d0 39 57 00 2b c2 42 88 08 3b d6 7c e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_lokibot_RPE_2147795857_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.RPE!MTB"
        threat_id = "2147795857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 16 00 00 06 0a 00 06 72 64 01 00 70 7d 0d 00 00 04 28 08 00 00 06 06 fe 06 17 00 00 06 73 19 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b 07 28 03 00 00 06 6f 1c 00 00 0a 0c 12 02 28 1d 00 00 0a 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_lokibot_RPG_2147796180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lokibot.RPG!MTB"
        threat_id = "2147796180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db 8b 45 08 03 45 e8 6a 02 89 45 e4 8a 00 88 45 fb 58 d1 e8 75 fc}  //weight: 1, accuracy: High
        $x_1_2 = {75 03 8a 45 08 39 3d 30 4d 57 00 8b 7d f4 88 01 74 1f}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 06 88 10 40 49 75 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

