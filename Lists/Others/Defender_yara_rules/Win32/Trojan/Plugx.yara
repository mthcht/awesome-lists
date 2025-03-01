rule Trojan_Win32_Plugx_B_2147660507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.B"
        threat_id = "2147660507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 e9 88 4e (02|03)}  //weight: 1, accuracy: Low
        $x_1_2 = {6a ff ff d6 6a ff ff d6 6a ff ff d6}  //weight: 1, accuracy: High
        $x_1_3 = "NvSmart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Plugx_C_2147663992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.C"
        threat_id = "2147663992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 6a 40 03 f0 6a 10 56 ff d7 85 c0 74 35 b8 ?? ?? ?? ?? 2b c6 83 e8 05 88 46 01 8b c8 8b d0 c1 e8 18 c1 e9 08 88 46 04 c1 ea 10 8d 44 24 08 50 c6 06 e9 88 4e 02 88 56 03 8b 4c 24 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 83 fe ff 74 3c 6a 00 8d 44 24 0c 50 68 00 00 10 00 57 56 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {50 45 00 00 75 54 56 8b 71 28 57 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Plugx_D_2147694993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.D"
        threat_id = "2147694993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 3c 85 00 00 00 00 bb fd ff ff ff 2b df 03 c3 8b f9 c1 e7 04 8d 4c 0f 05 8b fa c1 e7 06 bb f9 ff ff ff 2b df 8b 7c 24 14 03 d3 8b 5c 24 1c 69 db 01 01 00 00 83 c3 09 89 5c 24 1c 02 da 02 d9 02 d8 30 1c 3e 46 3b f5 72 b6}  //weight: 2, accuracy: High
        $x_1_2 = {8a 08 40 84 c9 75 f9 2b c2 83 c0 fc 3b c6 76 16 50 8d 54 24 70 52 8d 84 24 78 01 00 00 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {ff d7 8b 4c 24 0c 8a 54 24 10 89 0e 8d 44 24 08 50 88 56 04 8b 4c 24 0c 51 6a 05 56 ff d7 5f}  //weight: 1, accuracy: High
        $x_1_4 = {83 e8 05 88 5c 24 11 88 5c 24 12 88 5c 24 13 88 5c 24 14 89 44 24 11 8d 44 24 0c 50 6a 04 6a 05 56 c6 44 24 20 e9 89 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Plugx_E_2147695624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.E"
        threat_id = "2147695624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 31 db 8a 04 11 b3 ?? 28 d8 30 d8 00 d8 88 04 11 83 f9 00 74 03 49 eb e6}  //weight: 1, accuracy: Low
        $x_1_2 = "h.hlpT" ascii //weight: 1
        $x_1_3 = {c6 00 68 c7 40 01 ff ff ff ff c6 40 05 68 c7 40 06 ?? ?? ?? ?? c6 40 0a c3}  //weight: 1, accuracy: Low
        $x_1_4 = {3c 00 74 09 38 d0 74 05 30 d0 88 04 0b 83 f9 00 74 03 49 eb e6}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 f8 ff d0 6a ff e8 ?? ?? ?? ?? 6a ff e8 ?? ?? ?? ?? 6a ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Plugx_F_2147696446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.F!dha"
        threat_id = "2147696446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 3b fe 74 76 6a 00 57 ff 15 ?? ?? ?? ?? 89 45 08 89 03 8d 45 e8 50 68 ?? ?? ?? ?? c7 45 e8 56 69 72 74 c7 45 ec 75 61 6c 41 c7 45 f0 6c 6c 6f 63 c6 45 f4 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f8 e8 2b c6 83 e8 05 89 45 f9 8b 45 f8 89 06 8a 45 fc 88 46 04 33 c0}  //weight: 1, accuracy: High
        $x_1_3 = {2b c1 50 57 51 e8 d0 00 00 00 8b 35 ?? ?? ?? ?? 8d 85 f4 fe ff ff 83 c4 0c 68 ?? ?? ?? ?? 50 ff d6 68 ?? ?? ?? ?? 8d 85 f4 fe ff ff 50 ff d6 8d 45 fc 50 8d 55 f8 8d 8d f4 fe ff ff e8 b7 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Plugx_G_2147696500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.G!dha"
        threat_id = "2147696500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 72 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 57 8d 7d f8 ab ab c7 45 f4 61 62 63 64 89 5d f8 8d 41 0c 89 45 fc 8d 75 f4 8b f9 a5 a5 a5 8d 7c 19 0c 8d 75 f4 a5 a5}  //weight: 1, accuracy: High
        $x_1_3 = {8b fa c1 e7 07 c1 e3 09 bd 93 23 71 34 2b ef 03 d5 bf a4 c7 ad 46 2b fb 01 7c 24 14 8b 7c 24 20 8a d8 02 d9 02 da 89 54 24 1c 8a d3 8b 5c 24 14 02 d3 32 14 37 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Plugx_G_2147696500_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.G!dha"
        threat_id = "2147696500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 6a 00 ff 55 f8 61 8b 0d 00 30 00 10 [0-16] 8d 81 ?? 30 00 10 83 c1 06 [0-16] c7 00 53 6c 65 65 66 c7 40 04 70 00 89 0d 00 30 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 8b 0d 00 30 00 10 89 45 fc 8d 81 ?? 30 00 10 83 c1 09 c7 00 6c 73 74 72 c7 40 04 63 70 79 57}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 1c 01 80 c3 ?? 80 f3 ?? 80 eb 00 88 18 40 4f 75 ee 83 c2}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 0d 00 30 00 10 8d 81 ?? 30 00 10 83 c1 09 [0-16] c7 00 52 65 61 64 c7 40 04 46 69 6c 65 [0-48] 81 79 1c 18 00 1a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Plugx_V_2147731811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.V!dha"
        threat_id = "2147731811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 14 92 03 d2 8b c1 2b c2 8a 90 20 9b 00 10 30 14 31 41 3b cf 7c df}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 81 ec 28 03 00 00 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 66 8c 15 ?? ?? ?? ?? 66 8c 0d ?? ?? ?? ?? 66 8c 1d ?? ?? ?? ?? 66 8c 05 ?? ?? ?? ?? 66 8c 25 ?? ?? ?? ?? 66 8c 2d ?? ?? ?? ?? 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Plugx_V_2147731811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.V!dha"
        threat_id = "2147731811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 85 f6 ?? ?? 03 cb 8a 54 07 01 32 14 29 40 3b c6 88 11 ?? ?? 8b 4c 24 ?? 8b 54 24 ?? 8d 42 ?? 3b d8 76 ?? 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c ?? ?? 8b 54 ?? ?? 83 c4 ?? 43 3b da 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 33 c9 85 c0 ?? ?? 8b 45 ?? 03 c6 03 d8 8a 54 0f ?? 32 13 41 3b 4d ?? 88 10 72 ?? 8b 5d ?? 8b 45 ?? 83 c0 ?? 3b f0 ?? ?? ff ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 59 46 3b 75 0c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Plugx_AA_2147752059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.AA!MTB"
        threat_id = "2147752059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "z2bqw7k90rJYALIQUxZK%sO=hd5C4piVMFlaRucWy31GTNH-mED8fnXtPvSojeB6g" ascii //weight: 1
        $x_1_2 = "SK_Parasite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Plugx_2147840587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugx.psyA!MTB"
        threat_id = "2147840587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {b8 90 04 46 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 08 50 45 43 6f 6d}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

