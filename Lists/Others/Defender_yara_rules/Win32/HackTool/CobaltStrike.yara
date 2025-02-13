rule HackTool_Win32_CobaltStrike_A_2147763051_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.A!!CobaltStrike.A"
        threat_id = "2147763051"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_5 = {33 c9 41 51 6a 02 58 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 51 50 ff 33 51 50 ff 75 ?? 51 50 68 a2}  //weight: 10, accuracy: Low
        $x_10_6 = {40 3d 00 10 00 00 7c f1 07 00 80 ?? ?? ?? ?? ?? (2e|69) 40}  //weight: 10, accuracy: Low
        $x_10_7 = {68 00 00 10 00 [0-60] 50 68 7f 66 04 40 ff 76 1c [0-8] 81 7d fc fc ff 0f 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_A_2147763652_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.A"
        threat_id = "2147763652"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_6 = {33 c9 41 51 6a 02 58 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 51 50 ff 33 51 50 ff 75 ?? 51 50 68 a2}  //weight: 10, accuracy: Low
        $x_10_7 = {40 3d 00 10 00 00 7c f1 07 00 80 ?? ?? ?? ?? ?? 03 01 01 01 2e 69 4e 40}  //weight: 10, accuracy: Low
        $x_10_8 = {68 00 00 10 00 [0-60] 50 68 7f 66 04 40 ff 76 1c [0-8] 81 7d fc fc ff 0f 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_B_2147776556_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.B!!CobaltStrike.B"
        threat_id = "2147776556"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_5 = {33 c9 41 51 6a 02 58 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 51 50 ff 33 51 50 ff 75 ?? 51 50 68 a2}  //weight: 10, accuracy: Low
        $n_100_6 = "Behavior:" ascii //weight: -100
        $n_100_7 = "Trojan:" ascii //weight: -100
        $n_100_8 = "mpattribute" ascii //weight: -100
        $n_100_9 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_C_2147776557_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.C!!CobaltStrike.C"
        threat_id = "2147776557"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_5 = {40 3d 00 10 00 00 7c f1 07 00 80 ?? ?? ?? ?? ?? (2e|69) 40}  //weight: 10, accuracy: Low
        $n_100_6 = "Behavior:" ascii //weight: -100
        $n_100_7 = "Trojan:" ascii //weight: -100
        $n_100_8 = "mpattribute" ascii //weight: -100
        $n_100_9 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_D_2147776558_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.D!!CobaltStrike.D"
        threat_id = "2147776558"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_5 = {68 00 00 10 00 [0-60] 50 68 7f 66 04 40 ff 76 1c [0-8] 81 7d fc fc ff 0f 00}  //weight: 10, accuracy: Low
        $n_100_6 = "Behavior:" ascii //weight: -100
        $n_100_7 = "Trojan:" ascii //weight: -100
        $n_100_8 = "mpattribute" ascii //weight: -100
        $n_100_9 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_B_2147777015_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.B"
        threat_id = "2147777015"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_6 = {33 c9 41 51 6a 02 58 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 8b 55 ?? 51 50 ff 32 51 50 ff 33 51 50 ff 75 ?? 51 50 68 a2}  //weight: 10, accuracy: Low
        $n_100_7 = "Behavior:" ascii //weight: -100
        $n_100_8 = "Trojan:" ascii //weight: -100
        $n_100_9 = "mpattribute" ascii //weight: -100
        $n_100_10 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_C_2147777016_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.C"
        threat_id = "2147777016"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_6 = {40 3d 00 10 00 00 7c f1 07 00 80 ?? ?? ?? ?? ?? 03 01 01 01 2e 69 4e 40}  //weight: 10, accuracy: Low
        $n_100_7 = "Behavior:" ascii //weight: -100
        $n_100_8 = "Trojan:" ascii //weight: -100
        $n_100_9 = "mpattribute" ascii //weight: -100
        $n_100_10 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_D_2147777017_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.D"
        threat_id = "2147777017"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 4f 4e 4f 4e 4c ?? ?? 4e 4c 4e 4f 4e 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {75 da c9 c3 8b 0d ?? ?? ?? ?? 8b 04 d1 8b 54 d1 04 c3}  //weight: 1, accuracy: Low
        $x_10_6 = {68 00 00 10 00 [0-60] 50 68 7f 66 04 40 ff 76 1c [0-8] 81 7d fc fc ff 0f 00}  //weight: 10, accuracy: Low
        $n_100_7 = "Behavior:" ascii //weight: -100
        $n_100_8 = "Trojan:" ascii //weight: -100
        $n_100_9 = "mpattribute" ascii //weight: -100
        $n_100_10 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_CobaltStrike_F_2147784076_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.F!!CobaltStrike.F"
        threat_id = "2147784076"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 6a 0d 8b c1 5b f7 f3 8a 44 ?? 08 30 ?? 41}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 3b 89 c8 31 d2 01 cf 41 89 7d e0 bf 0d 00 00 00 f7 f7 8a 44 13 08 8b 55 e0 30 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 89 cf bb 0d 00 00 00 31 d2 03 38 89 c8 41 f7 f3 8b 45 08 8a 44 10 08 8a 44 10 08 30 07}  //weight: 1, accuracy: High
        $n_100_4 = "Behavior:" ascii //weight: -100
        $n_100_5 = "Trojan:" ascii //weight: -100
        $n_100_6 = "mpattribute" ascii //weight: -100
        $n_100_7 = "HackTool:" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule HackTool_Win32_CobaltStrike_F_2147797949_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.F"
        threat_id = "2147797949"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 6a 0d 8b c1 5b f7 f3 8a 44 ?? 08 30 ?? 41}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 3b 89 c8 31 d2 01 cf 41 89 7d e0 bf 0d 00 00 00 f7 f7 8a 44 13 08 8b 55 e0 30 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 89 cf bb 0d 00 00 00 31 d2 03 38 89 c8 41 f7 f3 8b 45 08 8a 44 10 08 8a 44 10 08 30 07}  //weight: 1, accuracy: High
        $n_100_4 = "Behavior:" ascii //weight: -100
        $n_100_5 = "Trojan:" ascii //weight: -100
        $n_100_6 = "mpattribute" ascii //weight: -100
        $n_100_7 = "HackTool:" ascii //weight: -100
        $n_100_8 = {7f 00 00 18 00 00 00 00 00 00 00 ff ff ff ff}  //weight: -100, accuracy: High
        $n_100_9 = {f7 7f 00 00 2a 00 00 00 00 00 00 00 ff ff ff ff}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule HackTool_Win32_CobaltStrike_G_2147798572_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.G"
        threat_id = "2147798572"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 00 00 00 00 00 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? 03}  //weight: 1, accuracy: Low
        $n_100_2 = {70 3f 00 47 0e 00 00 1c 04 00 00 e0 01 24 00 64 55 55 55 55 56 56 56 56}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_CobaltStrike_G_2147798576_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.G!!CobaltStrike.G"
        threat_id = "2147798576"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "G: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 00 00 00 00 00 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? 03}  //weight: 1, accuracy: Low
        $n_100_2 = {70 3f 00 47 0e 00 00 1c 04 00 00 e0 01 24 00 64 55 55 55 55 56 56 56 56}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_CobaltStrike_H_2147811537_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.H"
        threat_id = "2147811537"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 5a 52 45 e8 00 00 00 00 5b 89 df 55 89 e5 81 c3 45 7d 00 00 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_CobaltStrike_I_2147844519_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.I"
        threat_id = "2147844519"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 ca 8b 54 ca 04 c3 e8 ?? ?? ?? ?? 66 83 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 10 40 84 d2 75 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_CobaltStrike_K_2147902923_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.K"
        threat_id = "2147902923"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 6a 0d 8b c1 5b f7 f3 8a 44 32 0c 30 07 41}  //weight: 1, accuracy: High
        $x_1_2 = {8b 3b f7 f6 01 cf 41 8a 44 13 0c 30 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win32_CobaltStrike_I_2147902925_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.I!!CobaltStrike.I"
        threat_id = "2147902925"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "I: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 ca 8b 54 ca 04 c3 e8 ?? ?? ?? ?? 66 83 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 10 40 84 d2 75 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_CobaltStrike_K_2147902927_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CobaltStrike.K!!CobaltStrike.K"
        threat_id = "2147902927"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "High"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "K: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 6a 0d 8b c1 5b f7 f3 8a 44 32 0c 30 07 41}  //weight: 1, accuracy: High
        $x_1_2 = {8b 3b f7 f6 01 cf 41 8a 44 13 0c 30 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

