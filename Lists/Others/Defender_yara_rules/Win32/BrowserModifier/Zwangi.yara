rule BrowserModifier_Win32_Zwangi_144384_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":CreateMutexA(i 0, i 0, t \"SpaceQuery_Inst_mtx\")" ascii //weight: 1
        $x_1_2 = ":CreateMutexA(i 0, i 0, t \"SpaceQuery_Uninst_mtx\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 26 74 0a 3c 3d 74 06}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 ec 3b 55 f4 74 6a 8b 45 fc 83 c0 01 25 ff 00 00 00 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 80 3e 20 74 fa 80 3e 22 75 08 b9 22 00 00 00 46 eb 05 b9 20 00 00 00 8b de}  //weight: 1, accuracy: High
        $x_1_2 = "Zumie loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {80 3e 2d 75 64 8a 46 01 3c 78 75 5d 80 7e 02 72 75 2c}  //weight: 3, accuracy: High
        $x_1_2 = {2d 52 00 00 2d 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "]>]>]>]>" ascii //weight: 1
        $x_1_4 = "<[<[<[<[" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 1c c6 85 ?? ?? ff ff 22 8b 4d fc 83 c1 01 8b 95 ?? ?? ff ff 89 8c 95}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 12 8b 8d ?? ?? ff ff 8b 55 fc 89 94 8d ?? ?? ff ff eb 09 c6 85 ?? ?? ff ff 20 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 04 f7 d8 eb 1a 0f b6 4d 0c 85 c9 74 0e 8b 4d 08 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 3e 5d 3e 5d 3e 5d 3e 00 00 00 00 3c 5b 3c 5b 3c 5b 3c 5b}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d f0 00 76 0c 8b 45 ec 8b 4d 08 8b 11 89 10 eb dc b8 01 00 00 00 c1 e0 02}  //weight: 1, accuracy: High
        $x_1_3 = {ff 6a 08 8b 0d 98 ?? 40 00 51 8b 55 fc 52 8b 85 ?? ec ff ff 50 e8 ?? ?? 00 00 83 c4 10 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 cc 0f be 48 01 83 f9 78 0f 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8d 8c 10 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 8b 55 cc 83 c2 02 52 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d f0 00 76 0c 8b 45 ec 8b 4d 08 8b 11 89 10 eb dc b8 01 00 00 00 c1 e0 02}  //weight: 1, accuracy: High
        $x_1_3 = {2d 72 00 00 2d 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 83 f8 05 75 06 b8 80 00 00 00 c3 3d}  //weight: 1, accuracy: High
        $x_1_2 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e}  //weight: 1, accuracy: High
        $x_1_3 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f [0-32] 01 00 00 00 09 00 00 00 09 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 81 80 13 00 00 8b 54 81 fc 8b fa c1 ef 1e 33 fa 69 ff 65 89 07 6c 03 f8 89 3c 81 8b 91 80 13 00 00 42 8b c2 3d 70 02 00 00 89 91 80 13 00 00 7c ce}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 ec 3b 55 f4 74 6a 8b 45 fc 83 c0 01 25 ff 00 00 00 89 45 fc}  //weight: 1, accuracy: High
        $x_1_3 = {3c 26 74 04 3c 3d 75 02 b0 5f}  //weight: 1, accuracy: High
        $x_1_4 = {3c 3d 74 04 3c 26 75 02 b0 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d8 1b c0 83 e0 70 83 c0 10 eb ?? f7 c1 00 00 00 40}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 01 88 10 48 3d ?? ?? ?? ?? 73 ?? 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02}  //weight: 1, accuracy: High
        $x_1_4 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c0 83 e8 61 b3 1a f6 eb 02 c2 2c 61 41}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 24 08 8b 4c 24 04 f6 d8 55 56 57 1b c0 25 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8d 6c 08 ff 3b cd}  //weight: 1, accuracy: Low
        $x_1_3 = {b0 01 5b 59 c3 8b cd e8 ?? ?? ?? ?? 5f 5e c6 45 ?? 01 5d 32 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c1 99 f7 7c 24 50 33 c0 8a 04 2a 33 d2 8a 91 ?? ?? ?? ?? 03 d6 03 c2 25 ff 00 00 00 8b f0 3b ce 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 84 c0 75 06 b8 01 00 00 00 c3 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 85 c0 75 06 b8 02 00 00 00 c3 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {2b f0 8a 50 ff 48 3b c1 88 14 06 ?? f5}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 ?? ?? 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 ?? ?? 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 2d 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 0f be 48 01 83 f9 78 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 0f be 42 02 83 f8 72 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 72 00 00 2d 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 74 01 00 00 e9 ?? ?? ?? ?? 8b 55 10 89 15 a4 72 40 00 eb ?? 83 7d ec 00 75 ?? 8b 4d e8 51 ff 55 f8 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 05 a0 72 40 00 00 00 00 00 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 02 83 f8 22 75 5a eb ?? eb}  //weight: 1, accuracy: Low
        $x_1_4 = {f7 d9 ff 24 8d ?? ?? 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 ?? 83 e0 03 2b c8 ff 24 85 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_14
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a4 00 00 00 05 a0 00 00 00 85 d2 76 ?? 8b 51 04 57 8b 38 8b 04 3a 03 d7 85 c0 76 ?? 53 55 56 8b 71 04 03 f0 8b 42 04 83 e8 08 33 db a9 fe ff ff ff 8d 7a 08 76 ?? 8d 9b 00 00 00 00 33 c0 66 8b 07 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 74 24 20 66 81 3e 4d 5a c6 44 24 18 01 74 0c 68 ?? ?? 00 10 8b cf e8 ?? ?? ?? ?? 53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_15
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 e0 80 f9 61 7c 08 80 f9 7a 7f 03 80 c1 e0 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 33 d2 3a c1 0f 94 c2 8a c2 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {01 28 8b 42 04 83 e8 08 43 d1 e8 83 c7 02 3b d8 72}  //weight: 1, accuracy: High
        $x_1_3 = {99 f7 fd 33 c0 8a 04 1a 33 d2 8a 11 03 d7 03 c2 25 ff 00 00 00 8b f8 8a 14 37 8a 01 88 04 37}  //weight: 1, accuracy: High
        $x_1_4 = {74 17 8a 46 01 80 e9 ?? 46 84 c0 74 33 2c ?? b3 ?? f6 eb 02 c8 8b 44 24 ?? 8b 5c 24 ?? 2a ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_16
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 57 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 8b 4c 24 10 6a 04 68 00 10 00 00 51 56 ff d0 8b f8 eb 02 33 ff 8b 4c 24 10 8b d1 c1 e9 02 33 c0 89 7b f8 f3 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0f 84 c9 74 15 2a 0a 46 88 4e ff 8a 4a 01 42 84 c9 75 02 8b d5 47 3b fb 72 e5}  //weight: 1, accuracy: High
        $x_1_3 = {84 c0 74 14 8b 0d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 08 b8 01 00 00 00 c2 04 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_4 = {42 49 4e 00 53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_17
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8d a4 24 00 00 00 00 8a 50 01 40 84 d2 75 ?? 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {50 8b f0 ff d7 8d 0c 30 8d 80 ?? ?? ?? ?? 3d ?? ?? ?? ?? 72 ?? 2b c8 eb ?? 8d 49 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 d8 1b c0 83 e0 07 40 f7 c3 00 00 00 04 74 ?? 0d 00 02 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02}  //weight: 1, accuracy: High
        $x_1_5 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_18
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 0f be c9 8a 89 ?? ?? ?? ?? 88 08 8a 4c 02 01 40 84 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 07 75 ?? ?? 40 00 00 00 [0-66] 33 c9 83 f8 ?? 0f 95 c1 49 83 e1}  //weight: 1, accuracy: Low
        $x_1_3 = {8a c2 2a c3 88 [0-2] 8a ?? 01 ?? ?? 84 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4c 24 08 8a 10 88 11 41 40 3b c6}  //weight: 1, accuracy: High
        $x_1_5 = {8b 51 28 6a 00 6a 00 50 03 d0 ff d2 c6 05}  //weight: 1, accuracy: High
        $x_2_6 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f [0-32] 01 00 00 00 09 00 00 00 09 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_19
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec 80 02 00 00 [0-5] 8b 15 ?? 72 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 81 ec 80 02 00 00 0f b6 ?? a8 72 40 00 85 ?? 74}  //weight: 1, accuracy: Low
        $x_2_3 = {c7 05 a0 72 40 00 00 00 00 00 (eb|e9)}  //weight: 2, accuracy: Low
        $x_1_4 = {a1 a4 72 40 00 0f be 08 83 f9 22 75 ?? 8b 0d a4 72 40 00 83 c1 01}  //weight: 1, accuracy: Low
        $x_1_5 = {f7 d9 ff 24 8d ?? ?? 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 ?? 83 e0 03 2b c8 ff 24 85 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_20
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 8b 55 10 52 e8 ?? ?? ff ff 83 c4 08}  //weight: 2, accuracy: Low
        $x_2_2 = {a8 72 40 00 85 ?? 74 ?? 83 7d 0c 00 75 09 ?? 01 00 00 00 85 ?? 74 09 8b ?? 0c 89 ?? a0 72 40 00 e9}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 76 0c 81 e6 ff 7f 00 00 89 35 ?? ?? ?? ?? 83 f9 02 74 ?? 81 ce 00 80 00 00 89 35 ?? ?? ?? ?? c1 e0 08 03 c2 a3 ?? ?? ?? ?? 33 f6 56 8b 3d ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 15 a4 72 40 00 0f be 02 85 c0 75}  //weight: 1, accuracy: High
        $x_1_5 = {8b 0d a4 72 40 00 0f be 11 85 d2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_21
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 dc 81 3a 50 45 00 00 74}  //weight: 3, accuracy: High
        $x_3_2 = {8b 55 dc 81 3a 50 45 00 00 0f}  //weight: 3, accuracy: High
        $x_1_3 = "]>]>]>]>" ascii //weight: 1
        $x_1_4 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 [0-4] 4c 6f 63 6b 52 65 73 6f 75 72 63 65 [0-4] 4c 6f 61 64 52 65 73 6f 75 72 63 65 [0-4] 46 69 6e 64 52 65 73 6f 75 72 63 65 41}  //weight: 1, accuracy: Low
        $x_5_5 = {00 42 49 4e 00}  //weight: 5, accuracy: High
        $x_5_6 = {74 23 6a 04 68 00 20 00 00 8b 85 ?? ?? ff ff 50 8b 8d ?? ?? ff ff 51 ff 95 ?? ?? ff ff 89 85 ?? ?? ff ff eb 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_22
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 70 74 61 67 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 70 61 72 74 6e 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 25 73 2f 3f 25 73 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 44 24 10 81 c6 ?? ?? 00 00 50 8b ce c7 44 24 14 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4c 24 10 51 8b ce c7 44 24 14 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 54 24 10}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 59 04 85 db c7 44 24 18 00 00 00 00 75 04 33 c0 eb 18 8b 71 08 2b f3 b8 ?? ?? ?? ?? f7 ee 03 d6 c1 fa 04 8b c2 c1 e8 1f 03 c2 8b 7c 24 20 3b c7 73 33 85 db 75 04 33 c0 eb 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_23
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {c0 e0 02 8b d5 c1 fa 04 0a d0}  //weight: 50, accuracy: High
        $x_5_2 = {66 61 6d 69 6c 69 65 00 66 61 6d 69 6c 6c 65 00 66 61 6d 69 6c 79 00 66 69 6e 64 00 66 72 65 65 00 67 61 6d 65}  //weight: 5, accuracy: High
        $x_5_3 = {70 76 65 72 3d [0-4] 26 61 6d 3d [0-4] 26 61 75 3d}  //weight: 5, accuracy: Low
        $x_1_4 = "zumie" ascii //weight: 1
        $x_1_5 = "browserquest" ascii //weight: 1
        $x_1_6 = "keenfinder" ascii //weight: 1
        $x_5_7 = {63 68 65 63 6b 75 70 64 [0-4] 73 6c 6f 61 64 [0-4] 74 62 68 69 64 65 [0-4] 74 62 73 68 6f 77}  //weight: 5, accuracy: Low
        $x_1_8 = "Seekeen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_24
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 83 40 00 83 ?? 01 89 ?? 28 83 40 00 8b ?? 28 83 40 00 89 ?? 20 83 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {28 83 40 00 83 ?? 01 ?? 28 83 40 00 8b ?? 28 83 40 00 89 ?? 20 83 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {28 83 40 00 83 ?? 01 89 ?? 28 83 40 00 ?? 28 83 40 00 ?? 20 83 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 05 20 83 40 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {c7 05 28 83 40 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {30 80 40 00 88 0b 00 8b ?? fc 0f be ?? 8b ?? f8 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_25
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8d a4 24 00 00 00 00 8a 50 01 40 84 d2 75 ?? 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 08 8a 0a 33 f6 84 c9 74 0c 0f b6 c9 42 03 f1 8a 0a 84 c9 75 f4 8b c8 8a 00 33 d2 84 c0}  //weight: 1, accuracy: High
        $x_1_3 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 0f 00 04 (e0|20) 80 f9 (61|41) 7c 08 80 f9 (7a|5a) 7f 03 80 c1 (e0|20)}  //weight: 1, accuracy: Low
        $x_1_5 = {80 38 2d 89 74 24 08 74 0c 8b 06 8b 48 7c 83 c0 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_26
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 08 8b 4c 24 04 f6 d8 55 56 57 1b c0 25 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8d 6c 08 ff 3b cd be ?? ?? ?? ?? bf ?? ?? ?? ?? 73 48 53}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 83 f8 06 0f 95 c1 49 83 e1 c4 83 c1 40 8b c1 f7 ?? 00 00 00 04}  //weight: 1, accuracy: Low
        $x_1_3 = {56 8b f1 57 8b 3e 85 ff 74 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 50 8b 06 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 57 ff d0 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be c0 83 e8 61 b3 1a f6 eb [0-4] 02 c2 2c 61 41 eb 02}  //weight: 1, accuracy: Low
        $x_1_5 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_27
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0e 8b 4c 24 08 8a 10 88 11 41 40 3b c6 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {8a 01 84 c0 75 ?? 8a 02 33 c9 84 c0 74 ?? 8d a4 24 00 00 00 00 0f b6 c0 42 8d 8c 01 ?? ?? ?? ?? 8a 02 84 c0 75 ?? 33 c0 3b f1 0f 94 c0 5e}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 51 28 6a 00 6a 00 50 03 d0 ff d2 c6 05}  //weight: 1, accuracy: High
        $x_1_4 = {ff d0 c2 04 00 [0-11] 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 84 c0 75 06 b8 01 00 00 00 c3 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 85 c0 75 06 b8 02 00 00 00 c3 ff e0}  //weight: 1, accuracy: Low
        $x_1_5 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f [0-23] 01 00 00 00 09 00 00 00 09 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_28
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e0 02 00 00 00 8b 55 0c 8b 42 04 89 45 e8 8b 4d e8 89 4d f0 8b 55 f0 89 55 e4 8b 45 e0 8b 4d e4 8d 14 81 89 55 e4 8b 45 e4 89 45 ec 8b 4d ec 8b 11 52 ff 55 08 e9 15 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 ?? ?? 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 ?? ?? 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 8b 55 c8 52 ff 15 ?? ?? ?? ?? 89 45 d4}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 ?? ?? 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 ?? ?? 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 ?? ?? 00 00 8b 4d cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_29
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0f 84 c9 74 15 2a 0a 46 88 4e ff 8a 4a 01 42 84 c9 75 02 8b d5 47 3b fb 72 e5}  //weight: 5, accuracy: High
        $x_5_2 = {84 c0 74 14 8b 0d ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff 85 c0 75 08 b8 01 00 00 00 c2 04 00 ff e0 05 00 e8 ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_1_3 = {eb 02 33 c9 68 ?? ?? 00 10 89 0d 04 ?? 00 10 89 5d fc e8 ?? ?? ff ff 3b c3 74 36}  //weight: 1, accuracy: Low
        $x_1_4 = {74 16 8b 0d ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff 85 c0 74 02 ff e0 33 c0 c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 44 24 14 ff ff ff ff 74 21 6a 00 6a 00 68 10 a1 00 10 68 ?? a1 00 10 e8 6f 03 00 00 83 c4 10 50 56 ff d7 85 c0 74 03 56 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_30
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 76 0c 81 e6 ff 7f 00 00 89 35 ?? ?? ?? ?? 83 f9 02 74 ?? 81 ce 00 80 00 00 89 35 ?? ?? ?? ?? c1 e0 08 03 c2 a3 ?? ?? ?? ?? 33 f6 56 8b 3d ?? ?? ?? ?? ff}  //weight: 10, accuracy: Low
        $x_1_2 = {0f be 02 83 f8 20 74 ?? 8b 0d ?? ?? ?? ?? 0f be 11 83 fa 09 ?? ?? 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 08 83 f9 20 74 ?? 8b 15 ?? ?? ?? ?? 0f be 02 83 f8 09 ?? ?? a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be 11 83 fa 20 74 ?? a1 ?? ?? ?? ?? 0f be 08 83 f9 09 ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_2_5 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_31
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c ping 127.0.0.1 -n 2 && del \"" ascii //weight: 1
        $x_1_2 = "/install.aspx?b=basicscan&d=opsdev" ascii //weight: 1
        $x_1_3 = {52 4f 4f 54 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 00 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 00 57 51 4c 00 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74}  //weight: 1, accuracy: High
        $x_1_4 = {41 56 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 41 53 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 2d 20 6e 61 6d 65 3a 20 25 73 0a 20 20 63 6f 6d 70 61 6e 79 3a 20 25 73 0a 20 20 76 65 72 73 69 6f 6e 3a 20 25 73 0a 20 20 65 6e 61 62 6c 65 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_32
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 f8 8b 4d fc ?? ?? ?? 89 4d f4 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 50 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {73 21 8b 4d ?? 0f be 11 83 fa 20 74 0b 8b 45 ?? 0f be 08 83 f9 09 75 0b}  //weight: 1, accuracy: Low
        $x_1_3 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {f7 d9 ff 24 8d ?? ?? 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 ?? 83 e0 03 2b c8 ff 24 85 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 34 40 8d 34 ?? ?? ?? 40 00 2b d0 83 26 00 83 c6 0c 4a 75 ?? 8b 09 81 f9 8e 00 00 c0 8b ?? ?? ?? 40 00 75 ?? c7 05 ?? ?? 40 00 83 00 00 00 eb ?? 81 f9 90 00 00 c0 75 ?? c7 05 ?? ?? 40 00 81 00 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_33
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Internet Explorer\\Extensions" ascii //weight: 10
        $x_10_2 = "application/x-www-form-urlencoded" ascii //weight: 10
        $x_10_3 = "<Url type=\"text/html\" method=\"GET\" template=\"" ascii //weight: 10
        $x_1_4 = {3c 53 68 6f 72 74 4e 61 6d 65 3e 4b 77 (69|61) 6e 7a 79 3c 2f 53 68 6f 72 74 4e 61 6d 65 3e}  //weight: 1, accuracy: Low
        $x_1_5 = "<ShortName>Zwunzi</ShortName>" ascii //weight: 1
        $x_1_6 = "<ShortName>FindBasic</ShortName>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_34
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 05 a0 72 40 00 00 00 00 00 (eb|e9)}  //weight: 10, accuracy: Low
        $x_1_2 = {a1 a8 72 40 00 0f be 08 85 c9 75 0c c7 05 a8 72 40 00 00 00 00 00 eb 16}  //weight: 1, accuracy: High
        $x_1_3 = {a1 a4 72 40 00 0f be 08 85 c9 75 0c c7 05 a4 72 40 00 00 00 00 00 eb 16}  //weight: 1, accuracy: High
        $x_1_4 = {0f be 11 85 d2 75 0c c7 05 (a4|a8) 72 40 00 00 00 00 00 eb 17 0f 00 8b 0d (a4|a8) 72 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {0f be 02 85 c0 75 0c c7 05 (a4|a8) 72 40 00 00 00 00 00 eb 18 0f 00 8b 15 (a4|a8) 72 40 00}  //weight: 1, accuracy: Low
        $x_1_6 = {0f be 11 85 d2 75 1d eb 0f 06 00 8b 0d (a4|a8) 72 40 00}  //weight: 1, accuracy: Low
        $x_1_7 = {a4 72 40 00 0f be ?? 85 ?? 75 0c c7 05 a4 72 40 00 ff ff ff ff eb}  //weight: 1, accuracy: Low
        $x_1_8 = {83 3d a0 72 40 00 00 75 0a c7 05 a4 72 40 00 00 00 00 00 (eb|e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_35
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 f8 8b 4d fc 03 4d f8 89 4d f4 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 50 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 4d 18 51 8b 55 14 52 8b 45 10 50 8b 4d 0c 51 8b 55 08 52 ff 55 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {33 45 10 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 e8 8b 4d ec 03 4d e8 89 4d e4 8b 55 0c 8b 45 0c 8b 4a 28 2b 48 2c 89 4d fc}  //weight: 1, accuracy: High
        $x_1_5 = {89 45 bc 8b 4d fc 8b 55 ac 8b 01 33 42 04 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc}  //weight: 1, accuracy: High
        $x_1_6 = {8d 34 40 8d 34 ?? ?? ?? 40 00 2b d0 83 26 00 83 c6 0c 4a 75 ?? 8b 09 81 f9 8e 00 00 c0 8b ?? ?? ?? 40 00 75 ?? c7 05 ?? ?? 40 00 83 00 00 00 eb ?? 81 f9 90 00 00 c0 75 ?? c7 05 ?? ?? 40 00 81 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_7 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_36
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 19 8b 55 fc 0f be 02 0f be 4d fb 3b c1 74 0b}  //weight: 1, accuracy: High
        $x_1_2 = {74 19 8b 45 fc 0f be 08 0f be 55 fb 3b ca 74 0b}  //weight: 1, accuracy: High
        $x_1_3 = {74 19 8b 4d fc 0f be 11 0f be 45 fb 3b d0 74 0b}  //weight: 1, accuracy: High
        $x_1_4 = {c7 85 d4 fe ff ff 00 00 00 00 eb 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 bd d4 fe ff ff 04 0f 8d ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 dc 00 00 00 00 eb 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 7d dc 04 0f 8d ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 45 d8 00 00 00 00 eb 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 7d d8 04 0f 8d ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {83 bd d4 fe ff ff 03 75 (09|0c) 8b 03 01 01 01 55 45 4d f0 03 01 01 01 52 50 51 ff 55 e0}  //weight: 1, accuracy: Low
        $x_1_8 = {83 7d dc 03 75 (09|0c) 8b 03 01 01 01 55 45 4d f0 03 01 01 01 52 50 51 ff 55 e0}  //weight: 1, accuracy: Low
        $x_1_9 = {83 7d d8 03 75 (09|0c) 8b 03 01 01 01 55 45 4d f0 03 01 01 01 52 50 51 ff 55 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_37
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 f0 8b 00 8b 4d 08 8b 55 f0 03 44 8a 08}  //weight: 5, accuracy: High
        $x_5_2 = {8b 55 f0 8b 02 8b 55 f0 03 44 8a 08}  //weight: 5, accuracy: High
        $x_5_3 = {8b 55 08 8b 45 ?? 8b 4c 90 08 89 4d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8b 02 03 45}  //weight: 5, accuracy: Low
        $x_5_4 = {8b 45 fc 8b 08 33 4d 10 8b 55 fc 89 0a}  //weight: 5, accuracy: High
        $x_1_5 = {50 ff 55 08 20 00 6a (04|02) 8b 4d 0c e8 ?? ?? ?? ?? 50 6a (03|01) 8b 4d 0c e8 ?? ?? ?? ?? 50 6a (02|00) 8b 4d 0c e8}  //weight: 1, accuracy: Low
        $x_5_6 = {6b c0 61 99 b9 29 e5 0a 00 f7 f9 89 55 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8b 02 69 c0 56 05 00 00 05 73 4d 02 00}  //weight: 5, accuracy: Low
        $x_1_7 = {8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 83 c0 01 89 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_8 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 01 89 4d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_38
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Administrator\\Application DataCLIENT" ascii //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Zumie" ascii //weight: 2
        $x_2_3 = "checkupd" ascii //weight: 2
        $x_2_4 = "Copyright (c) 2007 Zumie.com" ascii //weight: 2
        $x_2_5 = "Zumie Options Panel" ascii //weight: 2
        $x_2_6 = "Blink Options Panel is already running!" ascii //weight: 2
        $x_2_7 = "blinkopt.pdb" ascii //weight: 2
        $x_2_8 = "Zumie Search Software Activated" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_39
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 81 08 2a 00 03 51 2c 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 81 08 48 00 03 51 2c 89 55}  //weight: 1, accuracy: Low
        $x_1_3 = {03 51 2c 89 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c0 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8d 04 8a}  //weight: 1, accuracy: Low
        $x_1_4 = {03 51 2c 89 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c0 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8d 04 8a}  //weight: 1, accuracy: Low
        $x_1_5 = {89 44 91 08 8b 95 ?? ?? ?? ?? 8b 42 28 11 00 2b 02}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 51 28 8b 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 90 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 42 28 3b 00 2b 02}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 51 28 8b 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 90 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 42 28 68 00 2b 02}  //weight: 1, accuracy: Low
        $x_1_8 = {c7 42 28 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 78 28 08 0f 8d 06 00 8b 95}  //weight: 1, accuracy: Low
        $x_1_9 = {c7 42 28 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 78 28 08 0f 8d 06 00 8b 95}  //weight: 1, accuracy: Low
        $x_1_10 = {33 4d 10 8b 55 ?? 89 0a 8b 45 ?? 83 c0 04 89 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_11 = {33 4d 10 8b 55 ?? 89 0a 8b 45 ?? 83 c0 04 89 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_40
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 2d 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 0f be 48 02 83 f9 72 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 0f be 42 01 83 f8 78 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 2d 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d ?? 0f be 51 02 83 fa 72 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 0f be 48 01 83 f9 78 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 78 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d ?? 0f be 51 02 83 fa 72 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f9 2d 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8a 42 01 88 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f be 8d ?? ?? ?? ?? 83 f9 72 0f 85}  //weight: 1, accuracy: Low
        $x_1_5 = {83 f9 78 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8a 42 02 88 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f be 8d ?? ?? ?? ?? 83 f9 72 0f 85}  //weight: 1, accuracy: Low
        $x_100_6 = {6b c0 61 99 b9 29 e5 0a 00 f7 f9 89 55 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8b 02 69 c0 56 05 00 00 05 73 4d 02 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_41
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 83 c0 01 89 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f be 4d ?? 85 c9 (74|75)}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 11 88 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 8b 08 83 c1 01 8b 55 ?? 89 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8a 45}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 08 88 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f be 45 ?? 85 c0 03 02 02 02 74 08 75 41 75 23}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 83 c0 01 89 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c0 01 2b 45 ?? 8b 4d ?? 2b c8 89 4d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 83 c2 01 89 55}  //weight: 1, accuracy: Low
        $x_100_6 = {6b c0 61 99 b9 29 e5 0a 00 f7 f9 89 55 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8b 02 69 c0 56 05 00 00 05 73 4d 02 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_42
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {04 e0 80 f9 61 7c 08 80 f9 7a 7f 03 80 c1 e0 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 33 d2 3a c1 0f 94 c2 8a c2 5e c3}  //weight: 100, accuracy: High
        $x_10_2 = {66 81 3e 4d 5a c6 44 24 18 01 74 0c 68 ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? 53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 0c}  //weight: 10, accuracy: Low
        $x_5_3 = {4d 5a c6 44 24 ?? ?? 74 03 00 66 81}  //weight: 5, accuracy: Low
        $x_5_4 = {57 8b 7e 3c 8b 04 37 03 fe 3d 50 45 00 00 89 7c 24 10 74 1e}  //weight: 5, accuracy: High
        $x_5_5 = {53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 1e}  //weight: 5, accuracy: High
        $x_5_6 = {55 8b 68 3c 03 e8 81 7d 00 50 45 00 00 74 1d}  //weight: 5, accuracy: High
        $x_5_7 = {57 8b 78 3c 03 f8 81 3f 50 45 00 00 75 35}  //weight: 5, accuracy: High
        $x_1_8 = {74 17 8a 46 01 80 e9 ?? 46 84 c0 74 33 2c ?? b3 ?? f6 eb 02 c8 8b 44 24 ?? 8b 5c 24 ?? 2a ca}  //weight: 1, accuracy: Low
        $x_1_9 = {0f 94 c0 84 c0 74 1d e8 ?? ?? ?? ?? 84 c0 74 14 8b 0d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 09 04 00 75 ee 3a}  //weight: 1, accuracy: Low
        $x_1_10 = {b9 09 00 00 00 33 c0 f3 a6 5f 5e 75 1f e8 ?? ?? ?? ?? 84 c0 74 16 8b 0d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_43
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 83 f8 05 75 06 b8 80 00 00 00 c3 3d}  //weight: 1, accuracy: High
        $x_1_2 = {c3 83 f8 03 1b c0 83 e0 e2 05}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 51 14 33 c4 89 44 24 04 8b 44 24 10 53 33 db 66 39 59 06 89 44 24 04 8d 44 0a 18}  //weight: 1, accuracy: High
        $x_1_4 = {33 f6 66 8b 33 8b ce 81 e1 ff 0f 00 00 03 c8 f7 c6 00 f0 00 00 74 14}  //weight: 1, accuracy: High
        $x_1_5 = {8b c8 25 ff 0f 00 00 c1 e9 0c 03 c6 85 c9 8b f0 74 2f}  //weight: 1, accuracy: High
        $x_1_6 = {03 c1 8b 4f 04 83 e9 08 33 ed f7 c1 fe ff ff ff 8d 5f 08}  //weight: 1, accuracy: High
        $x_1_7 = {8b 5e 24 55 57 8b 7e 20 03 f9 03 d9 33 ed 85 c0}  //weight: 1, accuracy: High
        $x_1_8 = {8b 4c 24 08 8b 54 24 0c 56 8b 74 24 08 8d 04 11 03 f2 3b c1 74 0d 2b f0 8a 50 ff 48 3b c1 88 14 06 75 f5}  //weight: 1, accuracy: High
        $x_1_9 = {03 d6 3b c1 74 15 8b f2 2b f0 3b c1 77 02 73 07 8a 50 ff 48 88 14 06 3b c1 75 f1}  //weight: 1, accuracy: High
        $x_1_10 = {77 02 73 0c 85 f6 7e 08 8a 50 ff 48 88 14 07 46 3b c1 75 ec}  //weight: 1, accuracy: High
        $x_1_11 = {74 13 77 02 73 0b 48 85 f6 7e 06 8a 10 4f 88 17 46 3b c1 75 ed}  //weight: 1, accuracy: High
        $x_1_12 = {74 16 77 02 73 0e 85 c9 74 0a 48 85 f6 74 05 8a 10 4e 88 16 3b c1 75 ea}  //weight: 1, accuracy: High
        $x_1_13 = {77 02 73 0b 85 c9 74 07 8a 50 ff 48 88 14 06 3b c1 75 ed}  //weight: 1, accuracy: High
        $x_1_14 = {2b d0 0f be c9 8a 89 ?? ?? ?? ?? 88 08 8a 4c 02 01 40 84 c9 75 ec c6 00 00}  //weight: 1, accuracy: Low
        $x_1_15 = {8d 64 24 00 0f be d2 8a 92 ?? ?? ?? ?? 88 11 8a 54 0e 01 41 84 d2 75 ec c6 01 00}  //weight: 1, accuracy: Low
        $x_1_16 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_44
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 03 45 08 2b 45 f0 33 45 f4 89 45 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f0 03 55 08 2b 55 f0 33 55 f4 89 55 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d f0 03 4d 08 2b 4d f0 33 4d f4 89 4d f4}  //weight: 1, accuracy: High
        $x_1_4 = {0f be 55 f3 2b 55 f4 03 55 ec 89 55 ec}  //weight: 1, accuracy: High
        $x_1_5 = {0f be 45 f3 2b 45 f4 03 45 ec 89 45 ec}  //weight: 1, accuracy: High
        $x_1_6 = {0f be 4d f3 2b 4d f4 03 4d ec 89 4d ec}  //weight: 1, accuracy: High
        $x_1_7 = {0f be 55 ef 2b 55 f0 03 55 e8 89 55 e8}  //weight: 1, accuracy: High
        $x_1_8 = {0f be 45 ef 2b 45 f0 03 45 e8 89 45 e8}  //weight: 1, accuracy: High
        $x_1_9 = {0f be 4d ef 2b 4d f0 03 4d e8 89 4d e8}  //weight: 1, accuracy: High
        $x_1_10 = {8b 45 08 8a 08 88 4d ?? 0f be 55 ?? 8b 45 08 83 c0 01 89 45 08}  //weight: 1, accuracy: Low
        $x_1_11 = {75 02 eb 10 eb e7}  //weight: 1, accuracy: High
        $x_1_12 = {75 02 eb 2a eb 19}  //weight: 1, accuracy: High
        $x_1_13 = {75 02 eb 10 eb da}  //weight: 1, accuracy: High
        $x_1_14 = {75 02 eb 04 eb e7}  //weight: 1, accuracy: High
        $x_1_15 = {eb d1 eb 4b eb 3b}  //weight: 1, accuracy: High
        $x_1_16 = {83 f9 22 75 02 eb ?? eb 04 00 0f be 4d}  //weight: 1, accuracy: Low
        $x_1_17 = {83 f8 22 75 02 eb ?? eb 04 00 0f be 45}  //weight: 1, accuracy: Low
        $x_1_18 = {83 fa 22 75 02 eb ?? eb 04 00 0f be 55}  //weight: 1, accuracy: Low
        $x_1_19 = {0f be 02 83 f8 22 75 5a eb ?? eb}  //weight: 1, accuracy: Low
        $x_1_20 = {0f be 08 83 f9 22 75 51 eb ?? eb}  //weight: 1, accuracy: Low
        $x_1_21 = {eb c7 eb bb eb 08}  //weight: 1, accuracy: High
        $x_1_22 = {75 0c c7 05 28 83 40 00 00 00 00 00 eb 09 00 28 83 40 00 0f be ?? 85}  //weight: 1, accuracy: Low
        $x_1_23 = {89 4d f4 8b 55 ?? 83 3a 00 74 22 00 89 4d 00 c7 45 fc ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? 8b 45 f8 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_45
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 16 2a c2 88 07 8a 46 01}  //weight: 1, accuracy: High
        $x_1_2 = {8a c2 2a c3 88 45 00 8a 47 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b 70 04 8b 0c 30 03 c6 85 c9 77 f4 8b 02}  //weight: 1, accuracy: High
        $x_1_4 = {8a 51 03 8a c3 32 d0 88 51 03}  //weight: 1, accuracy: High
        $x_1_5 = {74 0e 8b 4c 24 08 8a 10 88 11 41 40 3b c6 75 f6}  //weight: 1, accuracy: High
        $x_1_6 = {2b f0 8a 50 ff 48 3b c1 88 14 06 77 f5}  //weight: 1, accuracy: High
        $x_1_7 = {03 f7 8a 41 ff 49 3b ca 88 04 0e 75 f5}  //weight: 1, accuracy: High
        $x_1_8 = {8a 50 ff 48 88 14 06 3b c1 75 f1}  //weight: 1, accuracy: High
        $x_1_9 = {8a 50 ff 48 88 14 07 46 3b c1 75 ec}  //weight: 1, accuracy: High
        $x_1_10 = {8a 50 ff 48 88 14 07 3b c1 75 e9}  //weight: 1, accuracy: High
        $x_1_11 = {83 f8 05 75 07 b8 80 00 00 00 eb 11 33 c9 83 f8 06 0f 95 c1 49}  //weight: 1, accuracy: High
        $x_1_12 = {83 f8 05 75 06 b8 80 00 00 00 c3 33 c9 83 f8 06 0f 95 c1 49}  //weight: 1, accuracy: High
        $x_1_13 = {83 f8 06 75 06 b8 04 00 00 00 c3 33 c9 83 f8 07 0f 95 c1 49 83 e1 40}  //weight: 1, accuracy: High
        $x_1_14 = {83 f8 05 75 07 b8 80 00 00 00 eb 11 33 d2 83 f8 06 0f 95 c2 4a}  //weight: 1, accuracy: High
        $x_1_15 = {83 f8 05 75 06 b8 80 00 00 00 c3}  //weight: 1, accuracy: High
        $x_1_16 = {c3 83 f8 03 75 06 b8 ?? ?? ?? ?? c3 3d ?? ?? ?? ?? 75 06 b8 ?? ?? ?? ?? c3 83 f8 06}  //weight: 1, accuracy: Low
        $x_1_17 = {83 f8 06 75 07 b8 04 00 00 00 eb 26 83 f8 03 75 07}  //weight: 1, accuracy: High
        $x_1_18 = {0f b7 51 06 43 83 c5 28 3b da 0f 8c}  //weight: 1, accuracy: High
        $x_1_19 = {66 8b 47 06 0f b7 d8 8d 04 9b c1 e0 03 3d}  //weight: 1, accuracy: High
        $x_1_20 = {8d 49 00 88 44 04 20 40 3d 00 01 00 00 7c f4}  //weight: 1, accuracy: High
        $x_1_21 = {8d 64 24 00 88 44 04 24 40 3d 00 01 00 00 7c f4}  //weight: 1, accuracy: High
        $x_1_22 = {88 10 8a 11 88 10 8a 11 40 41 4e 75 f3}  //weight: 1, accuracy: High
        $x_1_23 = {85 c0 74 08 85 c9 74 04 8a 11 88 10 40 41 4e 75 ef}  //weight: 1, accuracy: High
        $x_1_24 = {85 ff 76 04 8a 11 88 10 40 41 4e 75 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_46
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "2101 Rosecrans Avenue, Suite 2000 El Segundo, CA 90245" ascii //weight: 10
        $x_1_2 = {61 6c 72 65 61 64 79 20 69 6e 73 74 61 6c 6c 65 64 2e 20 4e 6f 20 6e 65 65 64 20 74 6f 20 69 6e 73 74 61 6c 6c 2e 00 49 6e 74 65 72 6e 61 6c 20 65 72 72 6f 72}  //weight: 1, accuracy: High
        $x_1_3 = "turns your browser address bar (the place where you generally type in web site addresses) into an Internet search box." ascii //weight: 1
        $x_1_4 = {74 75 72 6e 73 20 79 6f 75 72 20 62 72 6f 77 73 65 72 20 61 64 64 72 65 73 73 20 62 61 72 20 28 74 68 65 20 70 6c 61 63 65 20 77 68 65 72 65 20 79 6f 75 20 67 65 6e 65 72 61 6c 6c 79 20 69 6e 70 75 74 20 69 6e 20 77 65 62 20 73 69 74 65 [0-2] 61 64 64 72 65 73 73 65 73 29 20 69 6e 74 6f 20 61 6e 20 49 6e 74 65 72 6e 65 74 20 73 65 61 72 63 68 20 62 6f 78 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {6f 76 65 72 72 69 64 65 73 [0-2] 6d 6f 73 74 20 70 72 65 2d 65 78 69 73 74 69 6e 67 20 65 72 72 6f 72 20 72 65 73 6f 6c 75 74 69 6f 6e 20 61 70 70 6c 69 63 61 74 69 6f 6e 73}  //weight: 1, accuracy: Low
        $x_1_6 = {46 6f 72 20 65 78 61 6d 70 6c 65 2c 20 4f 74 68 65 72 20 43 6f 6e 74 65 6e 74 20 6f 72 [0-2] 53 65 72 76 69 63 65 73 20 6d 61 79 20 69 6e 63 6c 75 64 65 20 70 61 69 64 20 73 65 61 72 63 68 20 72 65 73 75 6c 74 73}  //weight: 1, accuracy: Low
        $x_1_7 = {79 6f 75 20 6d 61 79 20 62 65 20 65 78 70 6f 73 65 64 [0-2] 74 6f 20 73 75 63 68 20 4f 74 68 65 72 20 43 6f 6e 74 65 6e 74 20 6f 72 20 53 65 72 76 69 63 65 73 20 74 68 61 74 20 6d 61 79 20 62 65 20 6f 66 66 65 6e 73 69 76 65 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_47
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 02 75 08 ff 55 e0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff 02 75 05 ff 55 e0 eb}  //weight: 1, accuracy: High
        $x_1_3 = {74 19 8b 4d fc 0f be 11 0f be 45 fb 3b d0 74 0b}  //weight: 1, accuracy: High
        $x_1_4 = {74 19 8b 55 fc 0f be 02 0f be 4d fb 3b c1 74 0b}  //weight: 1, accuracy: High
        $x_1_5 = {74 19 8b 45 fc 0f be 08 0f be 55 fb 3b ca 74 0b}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 fb 22 8b 45 fc 83 c0 01 8b 8d ?? ?? ff ff 89 44 8d e8}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 45 fb 22 8b 55 fc 83 c2 01 8b 85 ?? ?? ff ff 89 54 85 e8}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 4d fc 83 c1 01 8b 95 ?? ?? ff ff 89 4c 95 e8 eb 06 c6 45 fb 22 eb e8}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 fc 83 c0 01 8b 8d ?? ?? ff ff 89 44 8d e8 eb 06 c6 45 fb 22 eb e8}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 55 fc 83 c2 01 8b 85 ?? ?? ff ff 89 54 85 e8 eb 06 c6 45 fb 22 eb e8}  //weight: 1, accuracy: Low
        $x_1_11 = {83 f9 22 75 (16|13) c6 45 fb 22 8b 45 fc 83 c0 01}  //weight: 1, accuracy: Low
        $x_1_12 = {83 fa 22 75 (16|13) c6 45 fb 22 8b 4d fc 83 c1 01}  //weight: 1, accuracy: Low
        $x_1_13 = {83 f8 22 75 (16|13) c6 45 fb 22 8b 55 fc 83 c2 01}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 45 fc 83 c0 01 8b 4d ?? 89 44 8d ?? eb 06 c6 45 fb 22 eb eb}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 4d fc 83 c1 01 8b 55 ?? 89 4c 95 e8 eb 06 c6 45 fb 22 eb eb}  //weight: 1, accuracy: Low
        $x_1_16 = {c6 45 fb 20 8b 85 ?? ?? ff ff 8b 4d fc 89 4c 85 e8}  //weight: 1, accuracy: Low
        $x_1_17 = {c6 45 fb 20 8b 8d ?? ?? ff ff 8b 55 fc 89 54 8d e8}  //weight: 1, accuracy: Low
        $x_1_18 = {c6 45 fb 20 8b 95 ?? ?? ff ff 8b 45 fc 89 44 95 e8}  //weight: 1, accuracy: Low
        $x_1_19 = {c6 45 fb 20 eb eb 0f 00 8b 85 ?? ?? ff ff 8b 4d fc 89 4c 85 e8 eb 06}  //weight: 1, accuracy: Low
        $x_1_20 = {c6 45 fb 20 eb eb 0f 00 8b 8d ?? ?? ff ff 8b 55 fc 89 54 8d e8 eb 06}  //weight: 1, accuracy: Low
        $x_1_21 = {c6 45 fb 20 8b 4d ?? 8b 55 fc 89 54 8d e8}  //weight: 1, accuracy: Low
        $x_1_22 = {c6 45 fb 20 8b 45 ?? 8b 4d fc 89 4c 85 e8}  //weight: 1, accuracy: Low
        $x_1_23 = {c6 45 fb 20 8b 55 dc 8b 45 fc 89 44 95 e8}  //weight: 1, accuracy: High
        $x_1_24 = {c6 45 fb 20 eb ee 0c 00 8b 55 ?? 8b 45 fc 89 44 95 e8 eb 06}  //weight: 1, accuracy: Low
        $x_1_25 = {c6 45 fb 20 eb ee 0c 00 8b 45 ?? 8b 4d fc 89 4c 85 e8 eb 06}  //weight: 1, accuracy: Low
        $x_1_26 = {eb e8 eb 17 eb 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_48
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 20 80 f9 61 7c 08 80 f9 7a 7f 03 80 e9 20 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7}  //weight: 1, accuracy: High
        $x_1_2 = {3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 0f 00 04 (e0|20) 80 f9 (61|41) 7c 08 80 f9 (7a|5a) 7f 03 80 c1 (e0|20)}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 02 8a 0e 42 46 84 c0 74 23 84 c9 74 1f 3c 61 7c 06 3c 7a 7f 02 2c 20}  //weight: 1, accuracy: High
        $x_1_4 = {99 f7 fd 33 c0 8a 04 1a 33 d2 8a 11 03 d7 03 c2 25 ff 00 00 00 8b f8 8a ?? 37 8a [0-3] 88}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 14 02 33 c0 8a c3 03 c7 03 d0 81 e2 ff 00 00 00 8b fa 8a 04 0f 04 ?? 2c ?? 88 1c 0f 88 04 0e}  //weight: 1, accuracy: Low
        $x_1_6 = {c1 e6 03 83 ea 61 8d 0c 4e 03 d1 47 2a d0 88 55 00 8a 43 01}  //weight: 1, accuracy: High
        $x_1_7 = {83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 8a c2 0f b6 16 2a c2 88 07 8a 46 01}  //weight: 1, accuracy: High
        $x_1_8 = {02 ca 46 eb 02 8a ca 2a c8 88 0b 8a 47 01 43 47 84 c0}  //weight: 1, accuracy: High
        $x_1_9 = {8a c2 0f b6 16 2a c2 88 07 8a 46 01 47 46 84 c0 75 05}  //weight: 1, accuracy: High
        $x_1_10 = {8b 42 04 83 e8 08 02 01 01 43 47 d1 e8 83 02 01 01 c7 c3 02 3b 02 01 01 d8 f8 72}  //weight: 1, accuracy: Low
        $x_1_11 = {83 e8 08 45 d1 e8 83 c7 02 3b e8 72 03 00 8b (46|42) 04}  //weight: 1, accuracy: Low
        $x_1_12 = {83 c3 02 01 02 8b 46 04 83 e8 08 47 d1 e8 3b f8 72 d2}  //weight: 1, accuracy: High
        $x_1_13 = {83 c5 02 01 04 32 8b 57 04 83 ea 08 43 d1 ea 3b da 72 d6}  //weight: 1, accuracy: High
        $x_1_14 = {8b 56 04 83 ea 08 43 d1 ea 83 c7 02 3b da 72}  //weight: 1, accuracy: High
        $x_1_15 = {8b 56 04 83 ea 08 45 d1 ea 83 c7 02 3b ea 72 cb}  //weight: 1, accuracy: High
        $x_1_16 = {8b 47 04 83 e8 08 45 d1 e8 83 c3 02 3b e8 72 d7}  //weight: 1, accuracy: High
        $x_1_17 = {8b 53 04 8b 44 24 10 83 ea 08 40 d1 ea 83 c5 02 3b c2 89 44 24 10 72 a6}  //weight: 1, accuracy: High
        $x_1_18 = {74 2d 2c 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02}  //weight: 1, accuracy: High
        $x_1_19 = {74 17 8a 46 01 80 e9 61 46 84 c0 74 33 2c 61 b3 1a f6 eb 02 c8}  //weight: 1, accuracy: High
        $x_1_20 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02}  //weight: 1, accuracy: High
        $x_1_21 = {0f be cb 83 e9 61 8b f1 c1 e6 04 8d 0c 89 83 ea 61 8d 0c 4e}  //weight: 1, accuracy: High
        $x_1_22 = {0f be c9 83 e9 61 0f be d2 83 ea 61 6b c9 1a 02 ca 46}  //weight: 1, accuracy: High
        $x_1_23 = {0f be c0 83 e8 61 b3 1a f6 eb 02 c2 2c 61 41}  //weight: 1, accuracy: High
        $x_1_24 = {f7 d8 1b c0 83 e0 70 83 c0 10 eb}  //weight: 1, accuracy: High
        $x_1_25 = {80 38 2d 89 74 24 08 74 0c 8b 06 8b 48 7c 83 c0 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_49
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 15 a8 72 40 00 0f be 02 85 c0 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 15 a4 72 40 00 0f be 02 85 c0 75}  //weight: 1, accuracy: High
        $x_1_3 = {8b 0d a4 72 40 00 0f be 11 85 d2 75}  //weight: 1, accuracy: High
        $x_1_4 = {8b 0d a8 72 40 00 0f be 11 85 d2 75}  //weight: 1, accuracy: High
        $x_1_5 = {72 40 00 00 75 0c c7 05 a0 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_6 = {72 40 00 00 00 00 00 e9 ?? ?? ?? ?? c7 05 a4 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_7 = {72 40 00 00 00 00 00 eb ?? c7 05 (a4|a8) 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_8 = {72 40 00 00 00 00 00 eb ?? e9 ?? ?? ?? ?? c7 05 (a0|a4) 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_9 = {72 40 00 00 00 00 00 eb ?? eb ?? c7 05 a4 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_10 = {72 40 00 00 00 00 00 e9 ?? ?? ?? ?? c7 05 a8 72 40 00 00 00 00 00 eb e5}  //weight: 1, accuracy: Low
        $x_1_11 = {c7 05 a4 72 40 00 00 00 00 00 c7 05 a0 72 40 00 00 00 00 00 eb 05 00 e9}  //weight: 1, accuracy: Low
        $x_1_12 = {c7 05 a8 72 40 00 00 00 00 00 c7 05 a4 72 40 00 00 00 00 00 eb e5 05 00 e9}  //weight: 1, accuracy: Low
        $x_1_13 = {c7 05 a4 72 40 00 00 00 00 00 c7 05 a0 72 40 00 00 00 00 00 eb 02 00 eb}  //weight: 1, accuracy: Low
        $x_1_14 = {75 19 c7 05 a8 72 40 00 00 00 00 00 c7 05 a4 72 40 00 00 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_15 = {75 16 c7 05 a4 72 40 00 00 00 00 00 c7 05 a0 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_16 = {eb 1b c7 05 a8 72 40 00 00 00 00 00 c7 05 a4 72 40 00 00 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_17 = {83 f8 22 75 02 eb ?? eb 04 00 0f be 45}  //weight: 1, accuracy: Low
        $x_1_18 = {83 f9 22 75 02 eb ?? eb 04 00 0f be 4d}  //weight: 1, accuracy: Low
        $x_1_19 = {83 fa 22 75 02 eb ?? eb 04 00 0f be 55}  //weight: 1, accuracy: Low
        $x_1_20 = {83 f8 22 75 02 eb ?? 0f be 4d 04 00 0f be 45}  //weight: 1, accuracy: Low
        $x_1_21 = {83 f9 22 75 02 eb ?? 0f be 55 04 00 0f be 4d}  //weight: 1, accuracy: Low
        $x_1_22 = {83 fa 22 75 02 eb ?? 0f be 45 04 00 0f be 55}  //weight: 1, accuracy: Low
        $x_1_23 = {20 7d 0b 0f be ?? ?? 83 ?? 09 74 02 eb 06 00 0f be ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_24 = {20 7d 16 0f be ?? ?? 83 ?? 09 74 0d eb 06 00 0f be ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_25 = {20 74 0b 0f be ?? ?? 83 ?? 09 74 02 eb 06 00 0f be ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_26 = {20 7d 12 0f be ?? ?? 83 ?? 09 74 09 c6 06 00 0f be 55 fd 83 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Zwangi_144384_50
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "151"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {46 81 e6 ff 00 00 00 0f b6 04 0e 03 f8 81 e7 ff 00 00 00 8a 1c 0f 88 1c 0e 88 04 0f 33 db 8a 1c 0e 03 c3 8a 5d 00 25 ff 00 00 00 8a 04 08 32 c3 8b 5c 24 14 88 04 2b 45 3b ea 75 c4}  //weight: 100, accuracy: High
        $x_50_2 = {3f 70 72 6f 64 75 63 74 3d 30 26 [0-21] 76 6e 3d 30 26 [0-21] 72 65 61 3d 25 64 26 [0-21] 62 3d [0-21] 26 [0-21] 63 69 64 3d 25 73 26 [0-21] 70 74 61 67 3d [0-15] 26 [0-21] 61 76 3d 25 73 26 [0-21] 61 73 3d 25 73}  //weight: 50, accuracy: Low
        $x_50_3 = {3f 76 6e 3d 30 26 [0-21] 26 72 65 61 3d 25 64 26 [0-21] 63 69 64 3d 25 73 26 [0-21] 62 3d [0-32] 70 74 61 67 3d [0-32] 61 76 3d 25 73 26 [0-21] 70 72 6f 64 75 63 74 3d 30 26 [0-21] 61 73 3d 25 73}  //weight: 50, accuracy: Low
        $x_50_4 = {53 65 63 75 72 69 74 79 43 65 6e 74 65 72 00 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 00 57 51 4c 00 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74}  //weight: 50, accuracy: High
        $x_50_5 = {41 56 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 41 53 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 2d 20 6e 61 6d 65 3a 20 25 73 0a 20 20 63 6f 6d 70 61 6e 79 3a 20 25 73 0a 20 20 76 65 72 73 69 6f 6e 3a 20 25 73 0a 20 20 65 6e 61 62 6c 65 64}  //weight: 50, accuracy: High
        $x_50_6 = {6e 3d 25 73 26 63 3d 25 73 26 76 3d 25 73 26 65 3d 25 64 26 75 3d 25 64 00 26 6e 25 64 3d 25 73 26 63 25 64 3d 25 73 26 76 25 64 3d 25 73 26 65 25 64 3d 25 64 26 75 25 64 3d 25 64}  //weight: 50, accuracy: High
        $x_1_7 = "bardiscover" ascii //weight: 1
        $x_1_8 = "barquery" ascii //weight: 1
        $x_1_9 = "basicscan" ascii //weight: 1
        $x_1_10 = "browserdiscover" ascii //weight: 1
        $x_1_11 = "browserquery" ascii //weight: 1
        $x_1_12 = "browserquest" ascii //weight: 1
        $x_1_13 = "browserseek" ascii //weight: 1
        $x_1_14 = "browserzinc" ascii //weight: 1
        $x_1_15 = "finderquery" ascii //weight: 1
        $x_1_16 = "findxplorer" ascii //weight: 1
        $x_1_17 = "kwanzy" ascii //weight: 1
        $x_1_18 = "querybar" ascii //weight: 1
        $x_1_19 = "querybrowse" ascii //weight: 1
        $x_1_20 = "queryexplorer" ascii //weight: 1
        $x_1_21 = "queryresult" ascii //weight: 1
        $x_1_22 = "queryscan" ascii //weight: 1
        $x_1_23 = "questbasic" ascii //weight: 1
        $x_1_24 = "questbasicone" ascii //weight: 1
        $x_1_25 = "questbrowse" ascii //weight: 1
        $x_1_26 = "questbrwsearch" ascii //weight: 1
        $x_1_27 = "questdn" ascii //weight: 1
        $x_1_28 = "questresult" ascii //weight: 1
        $x_1_29 = "questscan" ascii //weight: 1
        $x_1_30 = "questscantwo" ascii //weight: 1
        $x_1_31 = "questservice" ascii //weight: 1
        $x_1_32 = "questurl" ascii //weight: 1
        $x_1_33 = "resulcmd" ascii //weight: 1
        $x_1_34 = "resultbar" ascii //weight: 1
        $x_1_35 = "resultbrowse" ascii //weight: 1
        $x_1_36 = "resultdn" ascii //weight: 1
        $x_1_37 = "resultscan" ascii //weight: 1
        $x_1_38 = "resultscanone" ascii //weight: 1
        $x_1_39 = "resulttool" ascii //weight: 1
        $x_1_40 = "resulturl" ascii //weight: 1
        $x_1_41 = "scanbasic" ascii //weight: 1
        $x_1_42 = "scanquery" ascii //weight: 1
        $x_1_43 = "seekdn" ascii //weight: 1
        $x_1_44 = "spacequery" ascii //weight: 1
        $x_1_45 = "tabdiscover" ascii //weight: 1
        $x_1_46 = "tabquery" ascii //weight: 1
        $x_1_47 = "winkzink" ascii //weight: 1
        $x_1_48 = "wyeke" ascii //weight: 1
        $x_1_49 = "ziniky" ascii //weight: 1
        $x_1_50 = "zinkseek" ascii //weight: 1
        $x_1_51 = "zinkwink" ascii //weight: 1
        $x_1_52 = "zinkzo" ascii //weight: 1
        $x_1_53 = "zopt" ascii //weight: 1
        $x_1_54 = "zumie" ascii //weight: 1
        $x_1_55 = "zwangie" ascii //weight: 1
        $x_1_56 = "zwankysearch" ascii //weight: 1
        $x_1_57 = "zwunzi" ascii //weight: 1
        $x_1_58 = "-p Qstbsc" ascii //weight: 1
        $x_1_59 = "-p Bscscn" ascii //weight: 1
        $x_1_60 = {40 23 40 26 6e 55 39 50 57 45 09 5e 59 62 57 55 40 23 40 26 40 23 40 26 57 3b 09 6d 4f 6b 4b 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 51 of ($x_1_*))) or
            ((3 of ($x_50_*) and 1 of ($x_1_*))) or
            ((4 of ($x_50_*))) or
            ((1 of ($x_100_*) and 51 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Zwangi_144384_51
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Zwangi"
        threat_id = "144384"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Zwangi"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 4d ?? 8b 10 33 51 04 8b 45 fc 89 10 8b 4d fc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 8b 8d ?? ?? ?? ?? 8b 10 33 51 04 8b 45 fc 89 10 8b 4d fc}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 fc 8b (45 ??|85 ?? ?? ?? ??) 8b 0a 33 48 04 8b 55 fc 89 0a 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d fc 8b (55 ??|95 ?? ?? ?? ??) 8b 01 33 42 04 8b 4d fc 89 01 8b 55 fc}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 4d f0 8b 55 f4 33 51 04 89 55 f4 eb 02 00 eb}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 45 f0 8b 4d f4 33 48 04 89 4d f4 eb 02 00 eb}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 55 f0 8b 45 f4 33 42 04 89 45 f4 eb 02 00 eb}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 4d fc 8b 11 89 55 f4 8b 45 f0 8b 4d f4 33 48 04 89 4d f4 eb}  //weight: 1, accuracy: High
        $x_1_9 = {8b 55 fc 8b 02 89 45 f4 8b 4d f0 8b 55 f4 33 51 04 89 55 f4 eb}  //weight: 1, accuracy: High
        $x_1_10 = {8b 45 fc 8b 08 89 4d f4 8b 55 f0 8b 45 f4 33 42 04 89 45 f4 eb}  //weight: 1, accuracy: High
        $x_1_11 = {8b 4d f0 8b 55 f4 33 51 04 89 55 f4 8b 45 fc 8b 4d f4 89 08}  //weight: 1, accuracy: High
        $x_1_12 = {8b 45 f0 8b 4d f4 33 48 04 89 4d f4 8b 55 fc 8b 45 f4 89 02}  //weight: 1, accuracy: High
        $x_1_13 = {8b 55 f0 8b 45 f4 33 42 04 89 45 f4 8b 4d fc 8b 55 f4 89 11}  //weight: 1, accuracy: High
        $x_1_14 = {8b 45 f4 33 45 08 89 45 f4 8b 4d fc 8b 55 f4 89 11}  //weight: 1, accuracy: High
        $x_1_15 = {8b 45 f4 33 45 08 89 45 f4 eb ?? 8b 4d fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 f4 89 11}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 4d f4 33 4d 08 89 4d f4 eb 0b 8b 55 fc 83 c2 04 89 55 fc eb 14 8b 45 fc 8b 4d f4 89 08}  //weight: 1, accuracy: High
        $x_1_17 = {83 c1 04 89 4d fc eb ?? 8b 55 f4 33 55 08 89 55 f4 eb ?? eb}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 4d f4 33 4d 08 89 4d f4 eb ?? eb ?? eb ?? 8b 55 0c 03 55 10 89 55 f8 eb}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 4d fc 0f be 11 83 ea 61 6b d2 1a 0f b6 85 ?? ?? ?? ?? 03 c2 88 85}  //weight: 1, accuracy: Low
        $x_1_20 = {8b 55 fc 0f be 02 83 e8 61 6b c0 1a 0f b6 8d ?? ?? ?? ?? 03 c8 88 8d}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 45 fc 0f be 08 83 e9 61 6b c9 1a 0f b6 95 ?? ?? ?? ?? 03 d1 88 95}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 4d fc 0f be 11 83 ea 61 6b d2 1a 0f b6 ?? e7 03 c2 88 45}  //weight: 1, accuracy: Low
        $x_1_23 = {8b 55 fc 0f be 02 83 e8 61 6b c0 1a 0f b6 4d ?? 03 c8 88 4d}  //weight: 1, accuracy: Low
        $x_1_24 = {8b 45 fc 0f be 08 83 e9 61 6b c9 1a 0f b6 55 ?? 03 d1 88 55}  //weight: 1, accuracy: Low
        $x_1_25 = {8b 88 24 01 00 00 8b 03 03 03 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 84 8a 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_26 = {8b 82 24 01 00 00 8b 03 03 03 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 94 81 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_27 = {8b 91 24 01 00 00 8b 03 03 03 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 8c 90 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_28 = {8b 55 f8 83 ea 30 89 55 f8}  //weight: 1, accuracy: High
        $x_1_29 = {8b 45 f8 83 e8 30 89 45 f8}  //weight: 1, accuracy: High
        $x_1_30 = {8b 4d f8 83 e9 30 89 4d f8}  //weight: 1, accuracy: High
        $x_1_31 = {8b 4d f4 83 e9 30 89 4d f4}  //weight: 1, accuracy: High
        $x_1_32 = {8b 4d fc 83 e9 30 89 4d fc}  //weight: 1, accuracy: High
        $x_1_33 = {8b 55 fc 83 ea 30 89 55 fc}  //weight: 1, accuracy: High
        $x_1_34 = {8b 45 f4 83 e8 30 89 45 f4}  //weight: 1, accuracy: High
        $x_1_35 = {8b 55 f4 83 ea 30 89 55 f4}  //weight: 1, accuracy: High
        $x_1_36 = {8b 45 fc 83 e8 30 89 45 fc}  //weight: 1, accuracy: High
        $x_1_37 = {8b 45 fc 3b 45 f8 73 16 8b 4d fc 0f be 11 83 fa 22 74 0b 8b 45 fc 83 c0 01 89 45 fc eb e2}  //weight: 1, accuracy: High
        $x_1_38 = {8b 55 fc 3b 55 f8 73 16 8b 45 fc 0f be 08 83 f9 22 74 0b 8b 55 fc 83 c2 01 89 55 fc eb e2}  //weight: 1, accuracy: High
        $x_1_39 = {8b 4d fc 3b 4d f8 73 16 8b 55 fc 0f be 02 83 f8 22 74 0b 8b 4d fc 83 c1 01 89 4d fc eb e2}  //weight: 1, accuracy: High
        $x_1_40 = {8b 45 fc 0f be 08 83 f9 22 75 39 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 89 45 f4 eb 0f}  //weight: 1, accuracy: High
        $x_1_41 = {8b 4d fc 3b 4d f8 72 02 eb 18 8b 55 fc 0f be 02 83 f8 22 75 02 eb 0b 8b 4d fc 83 c1 01 89 4d fc eb de}  //weight: 1, accuracy: High
        $x_1_42 = {8b 55 fc 0f be 02 83 f8 22 75 02 eb 15 8b 4d fc 3b 4d f8 72 02 eb 0b 8b 55 fc 83 c2 01 89 55 fc eb de}  //weight: 1, accuracy: High
        $x_1_43 = {8b 45 fc 0f be 08 83 f9 22 75 ?? eb ?? eb ?? 8b 55 fc 83 c2 01 89 55 fc eb}  //weight: 1, accuracy: Low
        $x_1_44 = {83 f8 22 75 ?? eb ?? eb ?? 8b 4d fc 83 c1 01 89 4d fc eb}  //weight: 1, accuracy: Low
        $x_1_45 = {83 fa 22 75 ?? eb ?? eb ?? 8b 45 fc 83 c0 01 89 45 fc eb}  //weight: 1, accuracy: Low
        $x_1_46 = {8b 55 fc 0f be 02 83 f8 22 75 ?? 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 89 55 f4}  //weight: 1, accuracy: Low
        $x_1_47 = {8b 45 fc 0f be 08 83 f9 22 75 ?? 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 89 45 f4}  //weight: 1, accuracy: Low
        $x_1_48 = {83 f8 22 75 ?? eb ?? eb ?? 8b 4d fc 3b 4d f8 72 ?? eb ?? 8b 55 fc 83 c2 01 89 55 fc}  //weight: 1, accuracy: Low
        $x_1_49 = {83 fa 22 75 ?? eb ?? eb ?? 8b 45 fc 3b 45 f8 72 ?? eb ?? 8b 4d fc 83 c1 01 89 4d fc}  //weight: 1, accuracy: Low
        $x_1_50 = {83 f8 22 75 ?? eb ?? eb ?? 8b 4d fc 8a 11 88 55 f3 eb ?? 8b 45 fc 83 c0 01 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_51 = {83 f9 22 75 ?? eb ?? 8b 55 fc 3b 55 f8 72 ?? eb ?? eb ?? 8b 45 fc 8a 08 88 4d f3 eb}  //weight: 1, accuracy: Low
        $x_1_52 = {83 f9 22 75 ?? eb ?? eb ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 fc 83 c2 01 89 55 fc eb ?? eb ?? 8b 45 fc 83 c0 01}  //weight: 1, accuracy: Low
        $x_1_53 = {83 fa 22 75 ?? 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 89 4d f4 eb ?? 8b 55 fc 83 c2 01}  //weight: 1, accuracy: Low
        $x_1_54 = {83 f9 22 75 ?? eb ?? eb ?? 8b 55 fc 8a 02 88 45 f3 eb ?? eb ?? eb ?? 8b 4d fc 83 c1 01}  //weight: 1, accuracy: Low
        $x_1_55 = {73 21 8b 4d ?? 0f be 11 83 fa 20 74 0b 8b 45 ?? 0f be 08 83 f9 09 75 0b}  //weight: 1, accuracy: Low
        $x_1_56 = {73 21 8b 45 ?? 0f be 08 83 f9 20 74 0b 8b 55 ?? 0f be 02 83 f8 09 75 0b}  //weight: 1, accuracy: Low
        $x_1_57 = {73 21 8b 55 ?? 0f be 02 83 f8 20 74 0b 8b 4d ?? 0f be 11 83 fa 09 75 0b}  //weight: 1, accuracy: Low
        $x_1_58 = {eb 04 eb dc eb d8 eb}  //weight: 1, accuracy: High
        $x_1_59 = {eb 04 eb e6 eb d8 eb}  //weight: 1, accuracy: High
        $x_1_60 = {eb 04 eb e5 eb d6 eb}  //weight: 1, accuracy: High
        $x_1_61 = {75 02 eb 13 eb db eb}  //weight: 1, accuracy: High
        $x_1_62 = {eb 04 eb de eb d2 eb}  //weight: 1, accuracy: High
        $x_1_63 = {eb e9 eb d0 eb 35 eb}  //weight: 1, accuracy: High
        $x_1_64 = {eb 04 eb e7 eb d0 eb}  //weight: 1, accuracy: High
        $x_1_65 = {eb 04 eb d2 eb ce eb}  //weight: 1, accuracy: High
        $x_1_66 = {8b 55 08 0f be 02 83 f8 32 74 16 8b 4d 08 0f be 11 83 fa 33 74 0b 8b 45 08 0f be 08 83 f9 2e 75}  //weight: 1, accuracy: High
        $x_1_67 = {0f be 08 83 f9 32 74 16 8b 55 ?? 0f be 02 83 f8 33 74 0b 8b 4d ?? 0f be 11 83 fa 2e 75}  //weight: 1, accuracy: Low
        $x_1_68 = {8b 45 14 2b 45 0c 89 45 f8 db 45 f8 de c9 da 45 0c}  //weight: 1, accuracy: High
        $x_1_69 = {8b 45 0c 2b 45 08 89 45 f8 db 45 f8 de c9 da 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

