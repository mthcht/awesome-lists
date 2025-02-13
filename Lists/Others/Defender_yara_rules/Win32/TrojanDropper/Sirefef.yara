rule TrojanDropper_Win32_Sirefef_D_2147799761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!D"
        threat_id = "2147799761"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e4 26 16 91 cc 1d 46 59 39 03 00 00 3c 77 cd 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_D_2147799761_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!D"
        threat_id = "2147799761"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8b 45 f4 8b 4d ?? 0f b7 04 41 ff 75 14 8b 4d ?? ff 75 10 8b 04 81 ff 75 0c 03 45 08 ff d0}  //weight: 100, accuracy: Low
        $x_1_2 = {8b d6 03 ce 2b d0 8b 45 ?? 8b (5d|7d) 00 8a 8c (19|39) ?? ?? ?? ?? 88 8c 02}  //weight: 1, accuracy: Low
        $x_1_3 = {03 ce 8b d6 2b d0 8b 45 ?? 8b (5d|7d) 00 8a 8c (19|39) ?? ?? ?? ?? 88 8c 02}  //weight: 1, accuracy: Low
        $x_1_4 = {f7 f3 8b d6 2b d0 8b 45 ?? 8b (5d|7d) 00 8a 8c (19|39) ?? ?? ?? ?? 88 8c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Sirefef_B_2147800860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.B"
        threat_id = "2147800860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 70 58 85 f6 75 ?? be 53 50 43 33 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 51 00 00 66 89 44 24 30 b8 00 52 00 00 66 89 44 24 32 b8 00 50 00 00 66 89 44 24 34 b8 73 72 00 00 66 89 44 24 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147800860_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.B"
        threat_id = "2147800860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f1 2e 8e 40 42 35 47 42 ca 72 89 4d f0 8b 0d ?? ?? 40 00 89 45 ec a1 ?? ?? 40 00 81 f1 0a 30 76 9d 35 88 b3 5e bb 89 4d f8 32 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 9d 90 68 ?? ?? 41 00 6a 00 6a 00 68 ?? ?? 41 00 6a fe ff 15 ?? ?? 41 00}  //weight: 1, accuracy: Low
        $x_1_3 = "ZwQueueApcThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147800860_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.B"
        threat_id = "2147800860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b f8 3b fe 74 42 53 68 ?? ?? ?? ?? 6a fc 57 ff 15 ?? ?? ?? ?? 6a 01 57}  //weight: 3, accuracy: Low
        $x_3_2 = {83 7d 0c 18}  //weight: 3, accuracy: High
        $x_1_3 = {8b c4 53 6a 20 83 c0 f0 50 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {8b dc 8d 47 60 50 6a 20 83 c3 f0 53 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {8b fc 8d 43 60 50 6a 20 83 c7 f0 57 ff 15}  //weight: 1, accuracy: High
        $x_1_6 = {8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15}  //weight: 1, accuracy: High
        $x_5_7 = {8d 48 28 8b 40 14 c1 e8 02 8b 54 24 08 31 11 83 c1 04 48 75 f4}  //weight: 5, accuracy: High
        $x_7_8 = {8b 48 fc 83 c0 28 4a f3 a4 75 ea 33 c0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 ab c7 85 ?? ?? ?? ?? 10 00 01 00 c7}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Sirefef_B_2147800860_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.B"
        threat_id = "2147800860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {8b 48 fc 83 c0 28 4a f3 a4 75 ea 33 c0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 ab c7 85 ?? ?? ?? ?? 10 00 01 00 c7}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147800860_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.B"
        threat_id = "2147800860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 70 58 85 f6 75 ?? be 53 50 43 33 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 51 00 00 66 89 44 24 30 b8 00 52 00 00 66 89 44 24 32 b8 00 50 00 00 66 89 44 24 34 b8 73 72 00 00 66 89 44 24 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147800860_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.B"
        threat_id = "2147800860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f1 2e 8e 40 42 35 47 42 ca 72 89 4d f0 8b 0d ?? ?? 40 00 89 45 ec a1 ?? ?? 40 00 81 f1 0a 30 76 9d 35 88 b3 5e bb 89 4d f8 32 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 9d 90 68 ?? ?? 41 00 6a 00 6a 00 68 ?? ?? 41 00 6a fe ff 15 ?? ?? 41 00}  //weight: 1, accuracy: Low
        $x_1_3 = "ZwQueueApcThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_I_2147801024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.I"
        threat_id = "2147801024"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 53 77 41 70 e8 ?? ?? ?? ?? 3b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 24 89 45 f8 3b c3 74 ?? 8b 45 08 8b 00 89 45 ?? 8b 06 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_I_2147801024_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.I"
        threat_id = "2147801024"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 53 77 41 70 e8 ?? ?? ?? ?? 3b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 24 89 45 f8 3b c3 74 ?? 8b 45 08 8b 00 89 45 ?? 8b 06 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147801474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!B"
        threat_id = "2147801474"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 bc 94 07 00 00 8b 45 e4 8b 4d 08 03 0c b8 89 4d ec 8b 45 ec}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d b8 8b 55 bc 33 c0 81 c7 ?? ?? ?? ?? 83 d0 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147801474_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!B"
        threat_id = "2147801474"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 72 00 66 00 69 00 65 00 75 00 74 00 69 00 66 00 64 00 6a 00 6c 00 67 00 66 00 6a 00 64 00 6c 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d7 85 c0 0f 84 ?? ?? ?? ?? 46 81 fe 03 04 00 00 72 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147801474_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!B"
        threat_id = "2147801474"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 5a 02 00 00 81 d2 10 54 00 00 33 c1 8b ce 33 ca}  //weight: 1, accuracy: High
        $x_1_2 = {8b 84 30 7c a2 e7 ff 8d 84 08 89 9e ff ff 8b 4d 08 03 c8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 e4 8b 4d e4 33 c7 c1 e8 02 f7 d1 c1 e1 1e 0b c1 89 45 ac}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 e8 8b 4d e8 33 c7 c1 e8 02 c1 e1 1e c1 e2 1e 0b c8 89 4d 98 8d 9d 64 ff ff ff c7 45 ec 05 00 00 00 ff 73 04}  //weight: 1, accuracy: High
        $x_1_5 = {b9 6b 77 00 00 66 03 c1 0f b7 4d f4 0f af c1 66 89 45 f4 b8 3a 59 00 00 66 89 45 f8}  //weight: 1, accuracy: High
        $x_1_6 = {8b 4d 14 0f ac c8 02 c1 e9 02 8b 4d 10 8b 55 14 33 c6 33 d2 0b c2}  //weight: 1, accuracy: High
        $x_1_7 = {c1 e9 02 8b 4d d0 8b 55 d4 c1 e1 1e 8b 4d ec 33 c7 33 d2 0b c2 8a 0c 08}  //weight: 1, accuracy: High
        $x_1_8 = {8b 45 08 c1 e1 1e 8b 4d 0c 0f ac c8 02 c1 e9 02 8b 4d 08 8b 55 0c 33 c6 33 d2 0b c2 03 c7}  //weight: 1, accuracy: High
        $x_1_9 = {c1 e2 1e c1 e8 02 0b d0 8d 04 d5 78 00 00 00 8b 55 0c 8b 04 02 89 45 0c 8b 45 f0 8b 55 f4 0f ac d0 02 c1 ea 02}  //weight: 1, accuracy: High
        $x_1_10 = {8b 40 3c 8b 09 8d 44 01 28 8b 00 01 45 f8 8b 45 0c 89 45 0c 8b 45 f0 8b 4d f4 0f ac c8 ?? c1 e9}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 75 14 8b 06 99 8b 06 8b ca 99 0f a4 c2 04 c1 e0 04 c1 e9 1c 8b f0 0b f1 33 c0 0b d0 8b c6 8b ca 8b 55 f0 8b 75 f4}  //weight: 1, accuracy: High
        $x_1_12 = {8b 0e 8b 56 04 0f ac d1 04 89 4d 0c 8b 0e 31 45 0c c1 e1 1c 33 c9 0b 4d 0c c1 ea 04 8b 56 04 89 4d 08 8b 4d 10 8b 55 14 0f ac d1 04 89 4d 0c 8b 4d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147801474_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!B"
        threat_id = "2147801474"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 81 c1 ?? db fe ff 83 d2 ff b8 ?? 21 01 00 33 c8 89 4c 24 20 83 f2 00 89 54 24 24 c7 44 24 18 2f fa ff ff c7 44 24 1c ff ff ff ff [0-8] 8b 54 24 18 8b 7c 24 1c 8b 4c 24 20 8b 74 24 24 3b ca 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 d9 00 00 00 0f b6 00 c7 05 ?? ?? ?? ?? d7 42 00 00 3b f0 8b 45 fc 0f 86 2a 00 00 00 8b 00 8b 55 fc 8b ce c1 e9 08 85 c9 0f 85 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 0c e8 fc ff ff 8b 44 24 0c bb 93 12 00 00 33 c3 bf 95 11 00 00 03 c7 0f 84 39 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f a4 c2 02 8b ca 33 d2 0b ca 8b 16 8b 7e 04 c1 e0 02 0b 45 10 33 f9 33 d0 81 f2 e6 2d 4e 24 81 f7 8c d5 ab dc 89 16 89 7e 04}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 f8 5c 14 00 00 c7 45 fc 0e 3f 00 00 c7 45 e4 26 4a 00 00 c7 45 e8 6f 56 00 00 c7 45 ec 50 49 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 dc de 08 00 00 c7 45 e0 70 3d 00 00 c7 45 e4 98 1c 00 00 8b 45 e4 ba 9c ef ff ff 2b d0 8b 45 e0 81 e2 82 34 00 00 0b d0 8b c1 2b c2 8b 55 dc 2b c2}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 f4 6d 4a 00 00 c7 45 f8 a8 0c 00 00 89 75 c8 c7 45 dc cf 59 00 00 c7 45 e8 2a 20 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {c7 44 24 0c ?? f9 ff ff bb ?? 3c 02 00 bf ?? 3a 02 00 e9 ?? 00 00 00 8b 44 24 0c 33 c3 03 c7}  //weight: 1, accuracy: Low
        $x_1_9 = {83 ec 44 c7 45 e0 a8 46 00 00 c7 45 e4 cd 63 00 00 c7 45 e8 7c 60 00 00 c7 45 d4 b0 54 00 00 c7 45 d8 37 65 00 00 c7 45 dc d9 72 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {c7 45 d8 37 65 00 00 c7 45 dc d9 72 00 00 c7 45 ec 69 46 00 00 c7 45 f0 10 7a 00 00 c7 45 f4 b2 51 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {32 22 00 00 8b 45 fc 81 05 ?? ?? ?? ?? 88 05 00 00 25 ff 00 00 00 c7 05 ?? ?? ?? ?? a7 2e 00 00 3b d0 06 00 81 0d}  //weight: 1, accuracy: Low
        $x_1_12 = {c7 45 f0 dc 3e 00 00 c7 45 f4 6d 0e 00 00 c7 45 fc e0 0f 00 00 c7 45 f8 98 71 00 00 c7 45 dc 72 16 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {c7 45 c8 fe 32 00 00 c7 45 cc 3d 00 00 00 c7 45 d0 79 7e 00 00 c7 45 d4 6c 68 00 00 c7 45 d8 b1 66 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {c7 45 f8 98 71 00 00 c7 45 dc 72 16 00 00 c7 45 e0 74 1c 00 00 c7 45 e4 a9 58 00 00 c7 45 e8 60 4f 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {c7 45 e4 c1 26 00 00 c7 45 e8 f8 44 00 00 c7 45 d4 37 08 00 00 c7 45 d8 9d 0d 00 00 c7 45 d0 20 6b 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {8b 55 f4 b9 ?? 03 00 00 66 33 4c 82 02 ba ?? 03 00 00 (e9 66|66) (e9 0f|0f) 89 4d d0 8b 4d f4 0f b7 0c 81 (e9 81 f1 ?? 03|81 f1 ?? 03) 03 ca 8b 55 d0}  //weight: 1, accuracy: Low
        $x_1_17 = {c7 44 24 20 33 22 34 ff c7 44 24 24 ff ff ff ff c7 44 24 28 ?? 22 34 ff c7 44 24 2c ff ff ff ff c7 44 24 30 33 23 34 ff 07 00 33 c0 e9}  //weight: 1, accuracy: Low
        $x_1_18 = {c7 44 24 18 03 01 01 01 23 33 3b 22 (34|14) ff c7 44 24 1c ff ff ff ff c7 44 24 ?? ?? 22 (34|14) ff c7 44 24 ?? ff ff ff ff c7 44 24 ?? 03 01 01 01 23 33 3b 23 (34|14) ff}  //weight: 1, accuracy: Low
        $x_1_19 = {c7 44 24 24 ff ff ff ff 8b 4c 24 20 8b 44 24 24 bf ?? 8a 89 00 33 cf 33 c3 be ?? 57 a2 00 03 ce}  //weight: 1, accuracy: Low
        $x_1_20 = {c7 44 24 2c ff ff ff ff 8b 4c 24 28 8b 44 24 2c bf ?? 8a 89 00 33 cf 33 c3 33 d2 be ?? 57 a2 00 03 ce 13 c3}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 45 fc 2b c1 8b 4d f8 69 c0 40 48 00 00 f7 f1 (e9 8b|8b) c1 e6 06 (e9 8b 8c 0e bc 16|8b 8c 0e bc 16) 33 d2 8d 84 01 5a a4 ff ff 8b 4d 08 03 c8 (e9 89|89)}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 45 08 a3 ?? ?? ?? ?? 8b 45 0c a3 ?? ?? ?? ?? 8d 45 04 89 44 24 (10|18) 8b 44 24 (18|20) 8b 4c 24 (1c|24) (35|bb) ?? 8a 89 00 [0-2] 05 ?? 57 a2 00 89 44 24 (14|20)}  //weight: 1, accuracy: Low
        $x_1_23 = {8b 45 08 a3 ?? ?? ?? ?? 8b 45 0c a3 ?? ?? ?? ?? 8d 45 04 89 45 fc 8b 45 f0 8b 4d f4 35 ?? 8a 89 00 05 ?? 57 a2 00 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_24 = {8d 45 04 89 44 24 18 8b 44 24 10 8b 4c 24 14 35 ?? 8a 89 00 05 ?? 57 a2 00 89 44 24 10 c7 44 24 10 ?? ?? ?? ?? 8b 45 10 89 44 24 10}  //weight: 1, accuracy: Low
        $x_1_25 = {8b 55 08 89 15 ?? ?? ?? ?? 8b 55 0c 89 15 ?? ?? ?? ?? 8d 55 04 89 54 24 (18|20) 8b 54 24 (10|18) 8b 74 24 (14|1c) 81 f2 ?? a3 91 00 81 c2 ?? 67 b2 00 89 54 24 (10|18)}  //weight: 1, accuracy: Low
        $x_1_26 = {8b 45 08 a3 ?? ?? ?? ?? 8b 45 0c a3 ?? ?? ?? ?? 8d 45 04 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? (35 ?? a3 91 00 05 ?? 67|be ?? a3 91 00 33 c6 05 ?? 67 b2 00) 89 44 24}  //weight: 1, accuracy: Low
        $x_1_27 = {89 01 66 8b 00 66 89 45 14 66 8b 45 14 bb ?? (56|75) 00 00 66 (03|2b) c3 bb ?? (7b|89) 00 00 66 33 c3 66 8b 1d ?? ?? ?? ?? 66 3b c3}  //weight: 1, accuracy: Low
        $x_1_28 = {0f b7 45 e8 66 2b c1 b9 3e 50 00 00 35 28 07 00 00 0d 41 68 00 00 66 89 45 f0}  //weight: 1, accuracy: High
        $x_1_29 = {89 01 66 8b 00 66 89 45 14 66 8b 45 14 bb 4e 06 00 00 66 2b c3 83 c3 69 66 33 c3 66 8b 1d ?? ?? ?? ?? 66 3b c3}  //weight: 1, accuracy: Low
        $x_1_30 = {0f 85 3b 00 00 00 ff 75 f0 ff 75 0c e8 ?? ?? ?? ?? 89 45 e4 8b 45 e4 85 c0 0f 84 15 00 00 00 8b 45 e0 0f b7 04 70 8b 4d dc 8b 04 81 89 45 ec e9 aa ff ff ff 46 e9 ?? ff ff ff 33 c0}  //weight: 1, accuracy: Low
        $x_1_31 = {2d 7d 3b df 71 89 45 fc 8b 45 f8 8b 15 ?? ?? ?? ?? 05 a5 0e 00 00 d1 e8 d1 ea 32 c2 02 45 0c 8b 55 fc 04 47 88 04 32}  //weight: 1, accuracy: Low
        $x_1_32 = {8b 45 f8 3b c6 c7 05 ?? ?? ?? ?? 55 1a 00 00 0f 82 26 ff ff ff 5b e9 b5 00 00 00 c7 05 ?? ?? ?? ?? 00 5e 00 00 0f b6 00}  //weight: 1, accuracy: Low
        $x_1_33 = {33 cf 8b 7d ?? 33 c6 03 c2 8b 55 ?? 13 cf 8b 7d ?? 03 c2 13 cf 89 45 ?? 89 4d ?? bf 1e 01 00 00}  //weight: 1, accuracy: Low
        $x_1_34 = {c7 45 f4 78 4e 00 00 c7 45 f8 01 00 00 00 c7 45 e8 d3 71 00 00 c7 45 ec 6c 49 00 00}  //weight: 1, accuracy: High
        $x_1_35 = {35 d4 22 00 00 0b c1 89 45 f8 b8 84 4e 00 00 66 89 45 fc 66 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_36 = {66 37 35 54 34 50 57 4f 6f 5d 60 6d 3d 3f 70 48 85 53 60 4d 5b 58 4e 6b 5a 5c 6b 5e 86 50 67 8c}  //weight: 1, accuracy: High
        $x_1_37 = {c7 45 f8 2a 0c 00 00 c7 45 fc 63 3a 00 00 c7 45 e0 ac 10 00 00 c7 45 e8 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_38 = {83 f1 00 33 c6 ba ?? a0 68 00 03 c2 83 d1 00 89 8d ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_39 = {83 ec 14 c7 45 f4 a5 32 00 00 c7 45 f8 16 4d 00 00 c7 45 fc 16 2e 00 00}  //weight: 1, accuracy: High
        $x_1_40 = {c7 45 fc 38 5b 00 00 c7 45 e4 e2 29 00 00 c7 45 e8 90 13 00 00}  //weight: 1, accuracy: High
        $x_1_41 = {c7 45 dc c2 16 00 00 c7 45 e8 db 70 00 00 c7 45 f8 77 3b 00 00}  //weight: 1, accuracy: High
        $x_1_42 = {c7 45 ec b9 27 00 00 c7 45 f4 00 0b 00 00 c7 45 f0 fa 1e 00 00}  //weight: 1, accuracy: High
        $x_1_43 = {c7 45 f4 71 2c 00 00 c7 45 fc 3a 5e 00 00 c7 45 f0 e2 30 00 00}  //weight: 1, accuracy: High
        $x_1_44 = {c7 45 f0 07 5b 00 00 c7 45 f4 ef 1c 00 00 c7 45 e8 7b 57 00 00}  //weight: 1, accuracy: High
        $x_1_45 = {c7 45 e8 f6 1d 00 00 c7 45 ec c3 6f 00 00 c7 45 f0 d4 1e 00 00}  //weight: 1, accuracy: High
        $x_1_46 = {c7 45 f4 a8 35 00 00 c7 45 f8 21 5c 00 00 c7 45 fc a5 61 00 00}  //weight: 1, accuracy: High
        $x_1_47 = {c7 45 f8 42 4f 00 00 c7 45 fc 6e 69 00 00 c7 45 f0 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_48 = {c7 45 fc 3c 7e 00 00 c7 45 f0 e0 12 00 00 c7 45 f4 51 0d 00 00}  //weight: 1, accuracy: High
        $x_1_49 = {4a 11 00 00 da 01 1e 70 3c 00 54 5f 27 73 07 46 4a 7d 0a 77}  //weight: 1, accuracy: High
        $x_1_50 = {d9 54 fb 54 17 71 6e 03 d3 23 12 5a fe 57 70 07 ec 1b 5e}  //weight: 1, accuracy: High
        $x_1_51 = {55 90 f1 86 f1 dc 05 05 05 58 56 5c cc 4a fd 2c 9f f6 04}  //weight: 1, accuracy: High
        $x_1_52 = {cd 0b 1e ab 56 e6 f1 9a a1 25 ce f5 ce ae 66 aa 29 66 32}  //weight: 1, accuracy: High
        $x_1_53 = {d7 ff 98 ff 2d fc 9b ff 05 fc 96 ff d0 ff 91 ff 34 fc ec ff}  //weight: 1, accuracy: High
        $x_1_54 = {47 75 27 7e 86 34 67 98 47 05 44 58 42 65 56 87}  //weight: 1, accuracy: High
        $x_1_55 = {0b 06 1b e2 91 5d fc 93 65 24 93 23 3b e7 7d 0f 3b 07 43 7d fc 7c}  //weight: 1, accuracy: High
        $x_1_56 = {55 93 f4 89 f4 e4 08 00 08 5b 5e 5f cf 4d f8 07 b3 be 07 cf 4d fc}  //weight: 1, accuracy: High
        $x_1_57 = {01 08 08 93 11 95 84 01 20 93 4d 10 93 55 08 93 88 9c 09 08 08 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147801474_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!B"
        threat_id = "2147801474"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c1 5a 02 00 00 81 d2 10 54 00 00 33 c1 8b ce 33 ca}  //weight: 1, accuracy: High
        $x_1_2 = {8b 84 30 7c a2 e7 ff 8d 84 08 89 9e ff ff 8b 4d 08 03 c8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 e4 8b 4d e4 33 c7 c1 e8 02 f7 d1 c1 e1 1e 0b c1 89 45 ac}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 e8 8b 4d e8 33 c7 c1 e8 02 c1 e1 1e c1 e2 1e 0b c8 89 4d 98 8d 9d 64 ff ff ff c7 45 ec 05 00 00 00 ff 73 04}  //weight: 1, accuracy: High
        $x_1_5 = {b9 6b 77 00 00 66 03 c1 0f b7 4d f4 0f af c1 66 89 45 f4 b8 3a 59 00 00 66 89 45 f8}  //weight: 1, accuracy: High
        $x_1_6 = {8b 4d 14 0f ac c8 02 c1 e9 02 8b 4d 10 8b 55 14 33 c6 33 d2 0b c2}  //weight: 1, accuracy: High
        $x_1_7 = {c1 e9 02 8b 4d d0 8b 55 d4 c1 e1 1e 8b 4d ec 33 c7 33 d2 0b c2 8a 0c 08}  //weight: 1, accuracy: High
        $x_1_8 = {8b 45 08 c1 e1 1e 8b 4d 0c 0f ac c8 02 c1 e9 02 8b 4d 08 8b 55 0c 33 c6 33 d2 0b c2 03 c7}  //weight: 1, accuracy: High
        $x_1_9 = {c1 e2 1e c1 e8 02 0b d0 8d 04 d5 78 00 00 00 8b 55 0c 8b 04 02 89 45 0c 8b 45 f0 8b 55 f4 0f ac d0 02 c1 ea 02}  //weight: 1, accuracy: High
        $x_1_10 = {8b 00 8b 89 a4 01 00 00 8b 40 3c 8b 09 8d 44 01 28 8b 00 01 45 f8 8b 45 0c 89 45 0c 8b 45 f0 8b 4d f4 0f ac c8 02 c1 e9 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Sirefef_B_2147801474_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!B"
        threat_id = "2147801474"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 81 c1 ?? db fe ff 83 d2 ff b8 ?? 21 01 00 33 c8 89 4c 24 20 83 f2 00 89 54 24 24 c7 44 24 18 2f fa ff ff c7 44 24 1c ff ff ff ff [0-8] 8b 54 24 18 8b 7c 24 1c 8b 4c 24 20 8b 74 24 24 3b ca 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 d9 00 00 00 0f b6 00 c7 05 ?? ?? ?? ?? d7 42 00 00 3b f0 8b 45 fc 0f 86 2a 00 00 00 8b 00 8b 55 fc 8b ce c1 e9 08 85 c9 0f 85 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 0c e8 fc ff ff 8b 44 24 0c bb 93 12 00 00 33 c3 bf 95 11 00 00 03 c7 0f 84 39 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f a4 c2 02 8b ca 33 d2 0b ca 8b 16 8b 7e 04 c1 e0 02 0b 45 10 33 f9 33 d0 81 f2 e6 2d 4e 24 81 f7 8c d5 ab dc 89 16 89 7e 04}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 f8 5c 14 00 00 c7 45 fc 0e 3f 00 00 c7 45 e4 26 4a 00 00 c7 45 e8 6f 56 00 00 c7 45 ec 50 49 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 dc de 08 00 00 c7 45 e0 70 3d 00 00 c7 45 e4 98 1c 00 00 8b 45 e4 ba 9c ef ff ff 2b d0 8b 45 e0 81 e2 82 34 00 00 0b d0 8b c1 2b c2 8b 55 dc 2b c2}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 f4 6d 4a 00 00 c7 45 f8 a8 0c 00 00 89 75 c8 c7 45 dc cf 59 00 00 c7 45 e8 2a 20 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {c7 44 24 0c ?? f9 ff ff bb ?? 3c 02 00 bf ?? 3a 02 00 e9 ?? 00 00 00 8b 44 24 0c 33 c3 03 c7}  //weight: 1, accuracy: Low
        $x_1_9 = {83 ec 44 c7 45 e0 a8 46 00 00 c7 45 e4 cd 63 00 00 c7 45 e8 7c 60 00 00 c7 45 d4 b0 54 00 00 c7 45 d8 37 65 00 00 c7 45 dc d9 72 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {c7 45 d8 37 65 00 00 c7 45 dc d9 72 00 00 c7 45 ec 69 46 00 00 c7 45 f0 10 7a 00 00 c7 45 f4 b2 51 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Sirefef_E_2147801539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.gen!E"
        threat_id = "2147801539"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 05 b8 53 50 43 33 68 00 00 ?? ?? 50 ff 35 ?? ?? ?? ?? ff 55 ?? c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4d fc 51 68 02 23 00 00 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 7c 10 68 ?? ?? ?? ?? 6a 00 ff 35 ?? ?? ?? ?? ff 55 fc}  //weight: 1, accuracy: Low
        $x_10_3 = {8b 75 08 8b 4b 54 f3 a4 0f b7 53 06 0f b7 43 14 8d 44 18 18 85 d2 74 ?? 83 c0 14}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Sirefef_A_2147803887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.A!dll"
        threat_id = "2147803887"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 25 00 77 00 5a 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 62 00 61 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 39 04 00 00 80 8b 46 04 8b 58 10 0f 85 82 01 00 00 f6 40 14 01 0f 84 78 01 00 00 39 98 c4 00 00 00 0f 83 6c 01 00 00 64 a1 18 00 00 00 3b 58 04 0f 83 5d 01 00 00 81 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_A_2147803887_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.A!dll"
        threat_id = "2147803887"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 25 00 77 00 5a 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 62 00 61 00 73 00 65 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 39 04 00 00 80 8b 46 04 8b 58 10 0f 85 82 01 00 00 f6 40 14 01 0f 84 78 01 00 00 39 98 c4 00 00 00 0f 83 6c 01 00 00 64 a1 18 00 00 00 3b 58 04 0f 83 5d 01 00 00 81 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_A_2147803888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.A"
        threat_id = "2147803888"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 fc 6a 40 59 8d bd dc fe ff ff 8d 85 dc fe ff ff f3 a5 50 8d b5 dc fd ff ff e8 ?? ?? ?? ?? 8b 45 fc 6a 40 8b f0 8d bd dc fe ff ff 59 f3 a5 be ff 00 00 00 03 c6 8b 4d f8 0f b6 0c 01 8a 8c 0d dc fe ff ff 88 08 8b ce 4e 48 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_A_2147803888_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.A"
        threat_id = "2147803888"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 39 4e 88 8c 05 ?? ?? ff ff 48 85 f6 77 eb 01 55 f8 ff 4d fc 6a 40 59 8d b5 ?? ?? ff ff f3 a5 75 d1 6a 0a 6a 66}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f8 85 ff 74 4e 6a 10 58 e8 ?? ?? 00 00 8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 ?? ?? 40 00 56 6a 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_A_2147803888_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.A"
        threat_id = "2147803888"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 fc 6a 40 59 8d bd dc fe ff ff 8d 85 dc fe ff ff f3 a5 50 8d b5 dc fd ff ff e8 ?? ?? ?? ?? 8b 45 fc 6a 40 8b f0 8d bd dc fe ff ff 59 f3 a5 be ff 00 00 00 03 c6 8b 4d f8 0f b6 0c 01 8a 8c 0d dc fe ff ff 88 08 8b ce 4e 48 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_A_2147803888_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.A"
        threat_id = "2147803888"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 39 4e 88 8c 05 ?? ?? ff ff 48 85 f6 77 eb 01 55 f8 ff 4d fc 6a 40 59 8d b5 ?? ?? ff ff f3 a5 75 d1 6a 0a 6a 66}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f8 85 ff 74 4e 6a 10 58 e8 ?? ?? 00 00 8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 ?? ?? 40 00 56 6a 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_D_2147804004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.D"
        threat_id = "2147804004"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 cd 2d ?? ?? 75 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {ad 4a 03 c2 ab 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_D_2147804004_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.D"
        threat_id = "2147804004"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 cd 2d ?? ?? 75 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {ad 4a 03 c2 ab 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_F_2147804141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.F"
        threat_id = "2147804141"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0a 8b 48 08 8b 40 0c 2b c8 f7 d9 1b c9 81 e1 03 00 00 40 89 06 8b c1 eb d4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 6b db 21 88 55 0b 0f be d2 33 da 40 80 7d 0b 00 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sirefef_F_2147804141_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sirefef.F"
        threat_id = "2147804141"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0a 8b 48 08 8b 40 0c 2b c8 f7 d9 1b c9 81 e1 03 00 00 40 89 06 8b c1 eb d4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 6b db 21 88 55 0b 0f be d2 33 da 40 80 7d 0b 00 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

