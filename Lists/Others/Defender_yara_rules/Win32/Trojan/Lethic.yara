rule Trojan_Win32_Lethic_C_2147619786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.C"
        threat_id = "2147619786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "silinuggahxx4576" ascii //weight: 1
        $x_1_2 = "port5.alwaysproxy.info" ascii //weight: 1
        $x_1_3 = "C:\\RECYCLER\\S-1-5-21-0243336031-4052116379-881863308-0850" ascii //weight: 1
        $x_1_4 = "12CFG914-K641-26SF-N31P" ascii //weight: 1
        $x_4_5 = {68 80 00 00 00 8b 45 ?? 83 c0 0c 50 ff 15 ?? ?? ?? ?? 8b 4d ?? 83 c1 0c 51 ff 15 ?? ?? ?? ?? c6 85 ?? ?? ff ff 00 68 ?? ?? ?? ?? 8d 95 ?? ?? ff ff 52 ff 15}  //weight: 4, accuracy: Low
        $x_5_6 = {68 af 04 00 00 8b 85 ?? ?? ff ff 8b 88 58 01 00 00 ff d1 66 89 85 ?? ?? ff ff 66 c7 85 ?? ?? ff ff 02 00 6a 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lethic_B_2147628286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.B"
        threat_id = "2147628286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c1 8b 4d 08 88 01 8b 55 fc 83 c2 01 89 55 fc a1}  //weight: 2, accuracy: High
        $x_1_2 = {6a 07 8b 55 08 83 c2 0c 52 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 08 89 41 38 68 ?? ?? ?? ?? 8b 55 ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 8c 01 f8 00 00 00 89 4d f8 68 ?? ?? ?? ?? 8b 55 f8 52 e8 ?? ?? ?? ?? 85 c0 74 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lethic_H_2147647288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.H"
        threat_id = "2147647288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8c 01 f8 00 00 00 89 4d f8 68 ?? ?? ?? ?? 8b 55 f8 52 e8 ?? ?? ?? ?? 85 c0 74 0b 8b 45 f8 83 c0 28 89 45 f8 eb e3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 d0 11 00 00 8b 55 ec 83 c2 0c 52 8b 45 e8}  //weight: 1, accuracy: High
        $x_1_3 = {89 85 58 fd ff ff 33 c9 75 cb 8b 95 44 fd ff ff 81 c2 c8 11 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_I_2147684646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.I"
        threat_id = "2147684646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 89 01 68 ?? ?? ?? ?? 8b 55 ?? 52 ff 15 ?? ?? ?? ?? 8b 4d 08 89 41 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 82 ?? 01 00 00 ff d0 3d 33 27 00 00 75 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_K_2147690742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.K"
        threat_id = "2147690742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 b8 99 99 99 99 c6 00 40 c6 40 01 41 c6 40 02 42 c6 40 03 43 c6 40 04 44 c6 40 05 45 33 c0 50 50 68 11 11 11 11 68 22 22 22 22 50 50 b8 33 33 33 33 ff d0 61 68 55 55 55 55 c3}  //weight: 1, accuracy: High
        $x_1_2 = {51 68 11 11 11 11 8b 55 ?? 52 8b 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 4d ?? 51 68 22 22 22 22 8b 55 ?? 52 8b 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 4d ?? 51 68 33 33 33 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_L_2147691450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.L"
        threat_id = "2147691450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e8 61 40 00 8d 85 f0 fd ff ff 50 ff 15 4c 50 40 00 8b 4d 08 51 8d 95 f0 fd ff ff 52 e8 81 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {68 03 01 00 00 68 00 67 40 00 8b 4d 08 81 c1 80 06 00 00 51 ff 15 20 50 40 00 6a 7f 68 64 67 40 00 8b 55 08 81 c2 88 08 00 00 52 ff 15 20 50 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {51 68 11 11 11 11 8b 55 ?? 52 8b 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 4d ?? 51 68 22 22 22 22 8b 55 ?? 52 8b 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 4d ?? 51 68 33 33 33 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_N_2147721322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.N"
        threat_id = "2147721322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 21 8a 55 10 88 55 fd 6a 06 8d 45 f8}  //weight: 1, accuracy: High
        $x_2_2 = {75 25 8b 55 08 8b 82 ?? ?? 00 00 ff d0 3d 33 27 00 00 75 0f 6a 05 8b 4d 08 8b 91 ?? ?? 00 00 ff d2}  //weight: 2, accuracy: Low
        $x_1_3 = {83 7d f8 01 72 ?? 0f b6 85 ?? ?? ff ff 83 f8 68 75 0f 0f b6 8d ?? ?? ff ff 81 f9 c3 00 00 00 74}  //weight: 1, accuracy: Low
        $x_1_4 = {74 3e c6 85 ?? ?? ff ff 68 8b 55 0c 89 95 ?? ?? ff ff c6 85 ?? ?? ff ff c3 6a 00 6a 06}  //weight: 1, accuracy: Low
        $x_1_5 = {74 2f c6 45 ?? 68 8b 4d 0c 89 4d ?? c6 45 ?? c3 6a 00 6a 06}  //weight: 1, accuracy: Low
        $x_1_6 = {ff d2 83 f8 01 0f 85 ?? ?? 00 00 8b 85 ?? ?? ff ff 81 b8 ?? ?? 00 00 10 10 00 00 0f 83}  //weight: 1, accuracy: Low
        $x_3_7 = {c6 40 05 51 33 c0 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 50 b8 ?? ?? ?? ?? ff d0 61 68 ?? ?? ?? ?? c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lethic_N_2147721323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.N!!Lethic.gen!A"
        threat_id = "2147721323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        info = "Lethic: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 21 8a 55 10 88 55 fd 6a 06 8d 45 f8}  //weight: 1, accuracy: High
        $x_2_2 = {75 25 8b 55 08 8b 82 ?? ?? 00 00 ff d0 3d 33 27 00 00 75 0f 6a 05 8b 4d 08 8b 91 ?? ?? 00 00 ff d2}  //weight: 2, accuracy: Low
        $x_1_3 = {83 7d f8 01 72 ?? 0f b6 85 ?? ?? ff ff 83 f8 68 75 0f 0f b6 8d ?? ?? ff ff 81 f9 c3 00 00 00 74}  //weight: 1, accuracy: Low
        $x_1_4 = {74 3e c6 85 ?? ?? ff ff 68 8b 55 0c 89 95 ?? ?? ff ff c6 85 ?? ?? ff ff c3 6a 00 6a 06}  //weight: 1, accuracy: Low
        $x_1_5 = {74 2f c6 45 ?? 68 8b 4d 0c 89 4d ?? c6 45 ?? c3 6a 00 6a 06}  //weight: 1, accuracy: Low
        $x_1_6 = {ff d2 83 f8 01 0f 85 ?? ?? 00 00 8b 85 ?? ?? ff ff 81 b8 ?? ?? 00 00 10 10 00 00 0f 83}  //weight: 1, accuracy: Low
        $x_3_7 = {c6 40 05 51 33 c0 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 50 b8 ?? ?? ?? ?? ff d0 61 68 ?? ?? ?? ?? c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lethic_O_2147722621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.O!bit"
        threat_id = "2147722621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d 08 89 01 68 ?? ?? ?? ?? 8b 55 f4 52 ff 15 ?? ?? ?? ?? 8b 4d 08 89 41 04}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 4d 08 89 41 38 68 ?? ?? ?? ?? 8b 55 ?? 52 ff 15}  //weight: 3, accuracy: Low
        $x_1_3 = {fd ff ff 33 95 ?? fd ff ff 89 95 ?? fd ff ff 8b 85 ?? fd ff ff 33 85 ?? fd ff ff 89 85 ?? fd ff ff 8b 8d ?? fd ff ff 89 8d ?? fd ff ff 8b 95 ?? fd ff ff 89 95 ?? fd ff ff 8b 85 ?? fd ff ff 05 ?? ?? ?? ?? 8b 8d ?? fd ff ff 81 d1 ?? ?? ?? ?? 89 85 ?? fd ff ff 89 8d ?? fd ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = "powershell.exe Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_5 = "76487-337-8429955-22614" ascii //weight: 1
        $x_1_6 = "76487-644-3177037-23510" ascii //weight: 1
        $x_1_7 = "55274-640-2673064-23950" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lethic_Q_2147723892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.Q!bit"
        threat_id = "2147723892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 0f be 08 85 c9 74 58 8b 55 0c 0f be 02 0c 20 25 ff 00 00 00 8b 4d fc 33 c8 89 4d fc 8b 55 0c 83 c2 01 89 55 0c c7 45 f8 00 00 00 00 eb 09}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d fc d1 e9 8b 55 fc 83 e2 01 a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 0f af c2 33 c8 89 4d fc eb d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_R_2147726622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.R!bit"
        threat_id = "2147726622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_2 = {0f b6 03 8b c8 c1 e9 04 83 f9 0a 7d 05 80 c1 ?? eb 03 80 c1 ?? 83 e0 0f 88 8a ?? ?? ?? ?? 83 f8 0a 7d 04 04 ?? eb 02 04 ?? 88 82 ?? ?? ?? ?? 6a 10 83 c2 02 58 4b 3b d0 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 c1 e0 19 33 c1 c1 e0 02 33 c1 c1 e0 02 33 c1 03 c0 33 c1 03 c0 33 c1 25 ?? ?? ?? ?? d1 e9 0b c1 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_EC_2147892925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.EC!MTB"
        threat_id = "2147892925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 11 01 d0 88 c7 8a 26 80 cc 01 88 d8 f6 e4 88 c4 8a 06 28 e0 88 01 88 f9 88 d8 d2 e0 00 c7 88 3e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lethic_C_2147907103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lethic.C!MTB"
        threat_id = "2147907103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lethic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 07 41 0a c9 41 0f c0 cf 8a 4f ?? 45 0f bf f8 66 41 81 f7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

