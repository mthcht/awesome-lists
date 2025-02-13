rule Trojan_Win32_Piptea_A_2147612332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.A"
        threat_id = "2147612332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 08 ff 75 fc [0-8] 8d 04 81 50 [0-4] ff 30 e8 ?? ?? ff ff 83 c4 0c eb}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 08 8b 45 fc [0-8] 8d 04 81 50 [0-4] ff 30 e8 ?? ?? ff ff 83 c4 0c eb}  //weight: 1, accuracy: Low
        $x_1_3 = {03 48 28 89 4d ?? ff 55}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 45 f0 6b c0 28 ?? ?? ?? ?? ?? ?? ?? 03 54 08 14 89 55 e0 ff 75 e8 ff 75 e0 ff 75 e4 ?? ?? ?? ?? 00 83 c4 0c e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 e9 05 03 0d ?? ?? ?? ?? 33 c1 [0-4] 2b c8 89 4d [0-5] c1 e0 04 03 05}  //weight: 1, accuracy: Low
        $x_1_6 = {58 0f b6 40 02 85 c0 74 05 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Piptea_C_2147621218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.C"
        threat_id = "2147621218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 79 37 9e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {55 54 5d 64 a1 18 00 00 00 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 40 02 85 c0 74 ?? e9}  //weight: 1, accuracy: Low
        $x_1_4 = {03 48 28 89 4d d0 ff 55 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Piptea_D_2147622137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.D"
        threat_id = "2147622137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 48 28 89 4d ?? ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 dc 50 ff 15 ?? ?? ?? ?? 83 7d f0 00 76 18}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 c0 b9 79 37 9e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Piptea_E_2147622604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.E"
        threat_id = "2147622604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 10 6a 00 8d 45 ?? 50 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 79 37 9e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 40 02 85 c0 74 ?? e9}  //weight: 1, accuracy: Low
        $x_1_4 = {03 48 28 89 4d ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Piptea_F_2147623189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.F"
        threat_id = "2147623189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 79 37 9e c7 45 ?? ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d ec 03 48 28 89 4d ?? ff 55 ?? c9 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {2b c1 89 45 ec [0-4] c1 e0 04 89 45 fc 8b 45 ec c1 e8 05 89 45 f0 [0-4] ff 75 fc}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 04 81 50 e8 ?? fe ff ff 83 c4 0c eb ?? c9 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 40 02 85 c0 74 ?? e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_6 = {68 0c 30 3e 00 6a 01 e8 ?? fb ff ff 83 c4 10 ff 75 ec 68 0c 30 3e 00 ff 75 f8 6a 0a 6a 0a e8 ?? 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Piptea_G_2147627018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.G"
        threat_id = "2147627018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 02 57 6a 00 5f 74 ?? 53 (bb ?? ?? ?? ??|68 ?? ?? ?? ??) 57 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 0c 47 47 83 c3 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c6 28 4f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Piptea_H_2147628233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.H"
        threat_id = "2147628233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {58 83 c0 01 03 02 02 02 8b 4d 89 45 ff 75 07 00 ff 75}  //weight: 3, accuracy: Low
        $x_3_2 = {c1 e8 10 c1 e0 10 5d}  //weight: 3, accuracy: High
        $x_3_3 = {ff 75 f4 58 83 c0 04 89 45 f4 e9}  //weight: 3, accuracy: High
        $x_3_4 = {81 bd 64 f7 ff ff 00 00 20 00 73 ?? e8}  //weight: 3, accuracy: Low
        $x_1_5 = {ff 72 34 58 89 45}  //weight: 1, accuracy: High
        $x_1_6 = {8b 42 34 89 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Piptea_A_2147629787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.gen!A"
        threat_id = "2147629787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 50 58 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 38 4d 5a [0-16] 81 3c 01 50 45 00 00 74 07 2d 00 00 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 f4 50 6a 01 8d 45 ff 50 53 89 7d f4 [0-16] ff 15 ?? ?? ?? ?? 03 75 f4 ff 4d f8 75 ?? 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Piptea_I_2147641175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.I"
        threat_id = "2147641175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 87 b0 00 00 00 8b 8f ac 00 00 00 8b 04 01 89 87 b0 00 00 00 8b d0 a1 ?? ?? ?? ?? 89 87 a8 00 00 00 c1 e2 10 c1 e8 10 0b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3a 90 74 01 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Piptea_J_2147646737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Piptea.J"
        threat_id = "2147646737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Piptea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 11 c1 e0 10 c1 ea 10 0b d0 89 15 ?? ?? ?? ?? 8b 87 b8 00 00 00 83 c0 ?? 89 87 b8 00 00 00 eb 08 61}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 f8 01 45 f4 83 7d f4 ?? 72 c5 ff 75 fc e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 06 8a 1f 2a c3 88 06 46 47 84 c0 75 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

