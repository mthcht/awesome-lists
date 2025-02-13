rule DoS_Win32_CaddyWiper_B_2147816578_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.B!dha"
        threat_id = "2147816578"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 5c 00 c7 [0-5] 2e 00 5c 00 c7 [0-5] 50 00 48 00 c7 [0-5] 59 00 53 00 c7 [0-5] 49 00 43 00 c7 [0-5] 41 00 4c 00 c7 [0-5] 44 00 52 00 c7 [0-5] 49 00 36 00 c7 [0-5] 45 00 39 00}  //weight: 2, accuracy: Low
        $x_1_2 = {68 00 00 00 c0 8d 85 ?? ?? ?? ?? 50 ff 95 ?? ?? ?? ?? 8b f0 83 fe ff 74 5d 53 56 ff 95 ?? ?? ?? ?? 8b f8 b8 00 00 a0 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 55 c7 [0-5] 73 65 72 73 88 [0-5] [0-16] c7 [0-5] 44 3a 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {44 73 52 6f c7 [0-5] 6c 65 47 65 c7 [0-5] 74 50 72 69 c7 [0-5] 6d 61 72 79 c7 [0-5] 44 6f 6d 61 c7 [0-5] 69 6e 49 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {44 65 76 69 c7 [0-5] 63 65 49 6f c7 [0-5] 43 6f 6e 74 c7 [0-5] 72 6f 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DoS_Win32_CaddyWiper_RE_2147816580_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.RE!MTB"
        threat_id = "2147816580"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 03 45 f4 8a 4d fb 88 08 8b 55 f4 83 c2 01 89 55 f4 8b 45 0c 03 45 f4 8a 08 88 4d fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DoS_Win32_CaddyWiper_D_2147829393_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.D!dha"
        threat_id = "2147829393"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 48 10 8b 45 ?? 99 83 e2 03 03 c2 56 c1 f8 02 33 f6 57 8b f9 85 c0 7e}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DoS_Win32_CaddyWiper_E_2147829394_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.E!dha"
        threat_id = "2147829394"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 c0 50 6a 10 50 e8 ?? ?? ?? ?? 59 59 53 8d 85 ?? ?? ?? ?? 50 53 53 68 80 07 00 00 ff ?? ?? 68 54 c0 07 00 ff ?? ?? ff ?? ?? eb}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DoS_Win32_CaddyWiper_F_2147832985_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.F!dha"
        threat_id = "2147832985"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {89 5c 24 50 ?? 89 5c 24 38 ?? 89 5c 24 58 48 ?? ?? ?? ?? 89 5c 24 60 41 b9 80 07 00 00 48 ?? ?? ?? ?? 4d 8b c4 ba 54 c0 07 00 49 8b cd}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DoS_Win32_CaddyWiper_G_2147833398_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.G!dha"
        threat_id = "2147833398"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 78 30 01 75 ?? 8b ?? ?? ?? ?? ?? 53 8d ?? ?? ?? ?? ?? 51 53 53 68 80 07 00 00 50 68 54 c0 07 00 52 89 58 50 89 58 54 89 58 58 89 58 5c ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DoS_Win32_CaddyWiper_H_2147839081_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/CaddyWiper.H!dha"
        threat_id = "2147839081"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "CaddyWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 7f 30 01 75 ?? 83 c7 50 33 c0 ab ab ab 53 ab 8d 85 ?? ?? ?? ?? 50 53 53 68 80 07 00 00 ff b5 ?? ?? ?? ?? 68 54 c0 07 00 ff ?? ?? ff}  //weight: 100, accuracy: Low
        $x_100_2 = {53 65 74 46 c7 45 ?? 69 6c 65 50 c7 45 ?? 6f 69 6e 74 66 c7 45 ?? 65 72}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

