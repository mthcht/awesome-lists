rule Trojan_Win32_Guildma_MR_2147749034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.MR"
        threat_id = "2147749034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6c 69 62 72 61 72 69 65 73 5c 72 61 70 74 6f 72 5c 72 61 6b 70 61 74 30 72 70 63 61 63 6b [0-5] 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {89 02 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 ?? ba ?? ?? ?? ?? e8 16 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147836143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyA!MTB"
        threat_id = "2147836143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {f7 f3 44 8e 63 f3 c6 b0 da dd 61 19 1b ba a4 67 71 77 7c 3a 31 1c 08 93 5b ea 81 ef 64 85 38 c0 65 30 8e 98 f6 6f 4b c4 7e b1 8c 8d 5f 18 ee 91 3f 98 a5 84 25 a1 47 82 67 35 a8 54 39 61 94 15 e6 72 b6 62 7d e0 c4 83 ae e6 0b 0e 3c e8 77 d9 a7 c3 dd 95 0c 08 74 2b 66 62 fd 72 74 1b df 48 c8 73 f5}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyC!MTB"
        threat_id = "2147838142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {8f 41 00 55 8b ec [0-15] 49 75 f9 53 56 b8 f8 8f 41 00 e8 59 d3 fe ff 33 c0}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyE!MTB"
        threat_id = "2147838143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {57 51 81 ef [0-47] 83 e8 05 89 45 f4 74 08 b8 [0-6] 89 45 f4 33 4d f4 83 ea 01 75 e8}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyF!MTB"
        threat_id = "2147838144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyF: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {66 7b 65 0e 66 c1 fd 0e 66 4b ad 0d 66 3a 5f 0e 66 b8 ac 0d 66 5a c2 0c 66 ec 9c 0d 66 ee f6 0e 66 71 3a 10 66 bf b6 0d 66 0d 3f 0e 66 62 3e 0e 66 86 f7 0e 66 86 f8 0e 66 fc b8 0d 66 6e 89 [0-32] 3c 0d 66 68 72 0e [0-32] 66 76 fe 0e 66 cb}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyH!MTB"
        threat_id = "2147838145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {57 c6 04 24 09 89 24 24 8b 6d 00 66 c7 04 24 ef be 68 b1 f1 f0 de 60 8d 64 24 28 e9 27 ff ff ff 68 e0 c7 50 39 80 fc ?? ?? ?? 24 83 c5 06 60 ?? ?? ?? ?? ?? 81 ee 96 a1 51 ef}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyI!MTB"
        threat_id = "2147838529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyI: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {88 e0 21 bc 35 4a 95 33 2f 8d 4f 0e 2e 72 f6 8a 11 8c 15 c8 11 cc c8 93 ?? fc dc fa 8c 88 97 4c 48 97 0c cf 73 6a b6 55 72 d7}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyQ!MTB"
        threat_id = "2147838531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec b9 d4 04 00 00 6a 00 6a 00 49 75 f9 51 53 56 57 b8 38 ee 14 13 e8 6f 67 ff ff 33 c0 55 68 ce ff 15 13 64 ff 30 64 89 20 33 c0 55 68 26 fe 15 13 64 ff 30 64 89 20 8d 55 e4 33 c0}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyS!MTB"
        threat_id = "2147838533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyS: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec b9 07 00 00 00 6a 00 6a 00 49 75 f9 53 56 b8 f8 8f 41 00 e8 59 d3 fe ff 33 c0 55 68 b5 92 41 00 64 ff 30 64 89 20 68 00 01 00 00 68 60 c2 42 00 6a 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyU!MTB"
        threat_id = "2147838843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyU: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {75 08 5f 33 c0 5e 40 5b c9 c3 56 50 ff 15 24 20 40 00 ff 75 f0 8b 3d 18 20 40 00 89 45 e4 ff d7 8b 4d e4 8d 44 41 04 50 6a 08 ff 75 f4 ff d3 89 45 ec 3b c6 0f 84 42 ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147838844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyV!MTB"
        threat_id = "2147838844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyV: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 75 f0 ff d7 8b 5d e4 8d 4c 00 02 8b 45 ec 03 c3 3b ce 76 13 8b 55 f0 2b d0 89 4d f4 8a 0c 02 88 08 40 ff 4d f4 75 f5 56 68 80 00 00 00 6a 02 56 6a 02 68 00 00 00 40 ff 75 fc ff 15 38 20 40 00 89 45 f4 83 f8 ff 0f 84 55 ff ff ff 56 8d 45 e8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147844894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyN!MTB"
        threat_id = "2147844894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyN: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ba de 00 00 00 8a 06 e9 00 00 00 00 32 c2 88 07 90 46 90 47 49 90 83 f9 00 90 0f 85 e5 ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147844895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyO!MTB"
        threat_id = "2147844895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8a 06 32 c2 90 88 07 90 46 90 e9 00 00 00 00 47 90 49 90 83 f9 00 90 0f 85 e3 ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Guildma_2147844896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Guildma.psyW!MTB"
        threat_id = "2147844896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Guildma"
        severity = "Critical"
        info = "psyW: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {89 0d 76 50 50 00 ff 15 14 40 50 00 a3 98 52 50 00 c7 05 20 52 50 00 dd 32 50 00 c7 05 1c 52 50 00 02 00 00 00 eb 04 00 00 00 00 c7 05 24 52 50 00 00 00 00 00 c7 05 28 52 50 00 00 00 00 00 c7 05 18 52 50 00 30 00 00 00 6a 00 ff 15 10 40 50 00 a3 2c 52 50 00 c7 05 40 52 50 00 88 40 50 00 c7 05 38 52 50 00 0f 00 00 00 a3 6e 50 50 00 68 00 7f 00 00 6a 00 ff 15 78 40 50 00 a3 30 52 50 00 a3 44 52 50 00 68 00 7f 00 00 6a 00 ff 15 74 40 50 00 a3 34 52 50 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

