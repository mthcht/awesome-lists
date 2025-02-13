rule Trojan_Win64_Grandoreiro_2147837906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyB!MTB"
        threat_id = "2147837906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyB: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {33 c0 eb 1c e8 f1 01 00 00 85 c0 74 f3 ff 35 30 50 40 00 e8 ?? ?? ?? ff 59 85 c0 74 e3 8b 45 0c 50 ff 15 54 40 40}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147837907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyF!MTB"
        threat_id = "2147837907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyF: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8a 07 33 d2 88 06 46 47 85 c9 76 0b 8d 04 0a 01 45 10 42 3b d1 72 f5 8b c1 49 85 c0 75 e2}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147838842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyE!MTB"
        threat_id = "2147838842"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {53 b8 99 04 00 00 b9 98 44 40 00 8a 19 80 eb f2 c0 c3 02 28 cb c0 cb 01 88 19 49 48 75 ed b8 [0-9] 8a 19 c0 c3 07 c0 cb 02 28 cb 80 f3 91 88 19 49 48 75 ed 5b 58 81 c1 1a 2c 00 00 ff e1}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147838848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyP!MTB"
        threat_id = "2147838848"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyP: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {e9 9b 09 00 00 33 c9 e8 f7 a1 fc ff 48 8b c8 e8 03 8c fc ff 48 8d 15 7c 21 04 00 49 8b 0c 24 e8 fb 97 fc ff 48 8b f8 41 bd 02 00 00 00 45 8b c5 33 d2 48 8b c8 e8 59 9e fc ff 48 8b cf e8 45 96 fc ff 48 63 d8 89 5c 24 50 45 33 c0 33 d2 48 8b cf e8 3d 9e fc ff 48 8b cb e8 61 3a fc ff 48 8b f0 48 89 44 24 78 4c 8b cf 4c 8b c3 49 8b d6 48 8b c8 e8 5c a4 fc ff 48 8b cf e8 a0 9b fc ff 8b 4c 33 f8 8b 54 33 fc 89 54 24 70 ff c9 89 4c 24 74 33 db 8b f3 85 d2}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147839277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyC!MTB"
        threat_id = "2147839277"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {8d 95 00 00 ff ff 52 e8 ?? ?? ?? ff 83 c4 04 89 85 f8 ff fe ff 83 bd f8 ff fe ff 00 74 02 eb 0d 68 60 ea 00 00 ff 15 0c 50 40 00 eb d3 b8 01 00 00 00 8b e5 5d c3 ff 25 b8 50 40}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147839676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyA!MTB"
        threat_id = "2147839676"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {75 02 eb 58 8a 06 3c 20 74 06 3c 09 74 02 eb 05 46 e2 f1 eb 47 c7 [0-31] 8a 06 3c 46 76 02 24 df 2c 30 d7 a2 3a 47 40 00 b8 10 00 00 00 f7 25 36 47 40 00 a3 36 47 40 00 0f b6 05 3a 47 40 00 01 05 36 47 40 00 46 e2 d0}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147839677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyG!MTB"
        threat_id = "2147839677"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyG: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {b8 7d 45 35 54 33 d2 f7 75 0c 05 [0-47] 33 d2 6a 50 59 f7 f1 83 fa 79 74 20 8b 45 10 8b 4d 10 49 89 4d 10 85 c0 74 12 8b 45 08 03 45 10 8b 4d 0c 03 4d 10 8a 09 88 08 eb b9}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Grandoreiro_2147844892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grandoreiro.psyD!MTB"
        threat_id = "2147844892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyD: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8d 64 24 00 8a 08 40 84 c9 75 f9 2b c2 53 56 8b d0 b8 70}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

