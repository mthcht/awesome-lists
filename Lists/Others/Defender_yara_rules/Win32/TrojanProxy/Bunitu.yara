rule TrojanProxy_Win32_Bunitu_A_2147605014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.A"
        threat_id = "2147605014"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 73 76 63 68 33 d2 8f 05 ?? ?? ?? 10 68 6f 73 74 2e 8f 05 ?? ?? ?? 10 68 65 78 65 00 48 8f 05 ?? ?? ?? 10 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_B_2147648812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.B"
        threat_id = "2147648812"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 2c 24 57 75 17 00 8f 00 c7 40 04 69 6c 33 32}  //weight: 5, accuracy: High
        $x_5_2 = {c7 00 3a 2a 3a 45 5a}  //weight: 5, accuracy: High
        $x_5_3 = {c1 ca 08 03 d0 8b df b8 2e 00 00 00 (b9 10 00 00 00|33 c9 41 c1)}  //weight: 5, accuracy: Low
        $x_1_4 = "engine 2.51</font>" ascii //weight: 1
        $x_1_5 = "wrrr/1.0 200 OK" ascii //weight: 1
        $x_5_6 = {c7 40 04 69 6c 33 32 ff 48 04 ff 48 04 83 68 04 01 ff 48 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_C_2147649933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.C"
        threat_id = "2147649933"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 53 76 63 00}  //weight: 1, accuracy: High
        $x_1_2 = {c3 78 78 78 78 2f 31 2e 30 20 32 30 30 20 4f 4b 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {36 c6 84 28 ?? ?? ff ff 00 36 80 bc 28 ?? ?? ff ff 2f 76}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 8b 5d 0c c6 03 30 eb 0e 33 d2 f7 75 14 80 c2 30 36 88 54 2e}  //weight: 1, accuracy: High
        $x_1_5 = {83 c2 08 4e 75 ?? 83 ef 04 c6 47 24 03 c7 07 21 00 00 00 6a 25 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_D_2147651506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.D"
        threat_id = "2147651506"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 40 ba 0d 54 54 50 89 10 83 00 39 ff 00 ff 00 fe 0d}  //weight: 1, accuracy: High
        $x_1_2 = {8f 00 c7 40 04 69 6c 33 32 ff 48 04 ff 48 04 83 68 04 01 ff 48 04 68}  //weight: 1, accuracy: High
        $x_1_3 = {c7 00 3a 2a 3a 45 5a}  //weight: 1, accuracy: High
        $x_1_4 = "<big> not found <big>" ascii //weight: 1
        $x_1_5 = {2b c0 b8 02 00 00 00 c1 e0 03 8b d0 8b ff 8b d0 d1 e0 03 c2 66 83 c0 06 48 86 e0}  //weight: 1, accuracy: High
        $x_1_6 = {81 c1 7b 2c 00 00 6a 00 6a 2c 51 ff 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_E_2147669248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.E"
        threat_id = "2147669248"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 19 20 54 50 89 10 81 00 2d 34 00 00 ff 00 ff 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 41 06 4d c6 41 0f 53 41}  //weight: 1, accuracy: High
        $x_2_3 = {c7 40 04 69 6c 33 32 ff 48 04 ff 48 04 83 68 04 01 ff 48 04}  //weight: 2, accuracy: High
        $x_2_4 = {c7 00 3a 2a 3a 45}  //weight: 2, accuracy: High
        $x_2_5 = "wrrr/1.0 200 OK" ascii //weight: 2
        $x_1_6 = {c7 40 04 60 4f 3f 32 ff 48 04 ff 48 04 81 68 04 f8 e2 0b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_F_2147682906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.F"
        threat_id = "2147682906"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 2e 00 00 00 f2 ae 0b c9 0f 84 ?? ?? ?? ?? c6 47 01 00 57 b0 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {58 f2 ae 85 c9 0f 84 ?? ?? ?? ?? c6 47 01 00 57 b0 5c}  //weight: 1, accuracy: Low
        $x_1_3 = {58 f2 ae 85 c9 0f 84 ?? ?? ?? ?? 33 c0 88 47 01 57 b0 5d 48}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 2e 00 00 00 f2 ae 0b c9 0f 84 ?? ?? ?? ?? 52 2b d2 88 57 01 5a 57 [0-6] b0 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 41 06 4d [0-25] c6 41 0f 53 [0-9] c6 41 1f}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 41 06 4d [0-21] c6 (41|40) 0f 53}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 41 0f 53 8b d1 83 c1 01}  //weight: 1, accuracy: High
        $x_1_8 = {39 06 75 07 c6 05 ?? ?? ?? ?? 01 58 ac aa ?? ?? 75 fa 5e 5b b9}  //weight: 1, accuracy: Low
        $x_1_9 = {c6 40 0f 53 [0-8] c6 40 1f 53}  //weight: 1, accuracy: Low
        $x_1_10 = {68 06 00 02 00 [0-2] 51 68 02 00 00 80 ff 15 ?? ?? ?? ?? 57 bf ?? ?? ?? ?? (47|83 c7)}  //weight: 1, accuracy: Low
        $x_1_11 = {81 c3 54 32 77 00 5b 58 85 db 0f 85 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_12 = {58 85 db 0f 85 ?? ?? 00 00 e9 ?? ?? 00 00 6a 06 6a 01 6a 02 e8}  //weight: 1, accuracy: Low
        $x_1_13 = {ff 4a 84 07 [0-32] 6a 06 6a 01 6a 02 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_A_2147683443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.gen!A"
        threat_id = "2147683443"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 41 06 4d c6 41 0f 53 c6 41 1f 53}  //weight: 2, accuracy: High
        $x_5_2 = {c7 00 3a 2a 3a 45 5a}  //weight: 5, accuracy: High
        $x_5_3 = {c7 00 3b d1 39 f4}  //weight: 5, accuracy: High
        $x_5_4 = {81 3e 73 61 6d 70}  //weight: 5, accuracy: High
        $x_2_5 = {81 2c 24 61 75 17 00 8f 00 c7 40 04 ?? ?? ?? ?? ff 48 04 ff 48 04 81 68 04 5c 78 39 30 01 04 ff 48 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_G_2147683444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.G"
        threat_id = "2147683444"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ba fd 13 54 50 89 10 81 00 49 40 00 00 ff 00 ff 00}  //weight: 10, accuracy: High
        $x_10_2 = {2b d2 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 4a 83 ea 47 4a 4a}  //weight: 10, accuracy: Low
        $x_10_3 = {81 2c 24 61 75 17 00 8f 00 c7 40 04 03 34 3f 32 ff 48 04 ff 48 04 81 68 04 9b c7 0b 00 ff 48 04}  //weight: 10, accuracy: High
        $x_10_4 = {8b 34 8a 03 f5 33 ff c1 cf 13 ac 03 f8}  //weight: 10, accuracy: High
        $x_10_5 = {8b 34 8a 03 f5 33 ff c1 cf 13 ac 03 f8 85 c0 75 ?? 3b fb 75 ?? 5a 8b 5a 24 03 dd 66 8b 0c 4b 8b 5a 1c 03 dd 8b 04 8b 8b c8}  //weight: 10, accuracy: Low
        $x_10_6 = {c7 00 3a 2a 3a 45 5a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_H_2147683530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.H"
        threat_id = "2147683530"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "soft\\Vindows NU\\DurrentVersion\\Vinlogon\\Ootify" ascii //weight: 1
        $x_1_2 = "Controlxet001\\Services\\XharedAccess\\Parameters\\FirewallPolicy" ascii //weight: 1
        $x_1_3 = {ba fd 13 54 50 89 10 81 00 49 40 00 00 ff 00 ff 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 40 04 73 32 3f 32 ff 48 04 ff 48 04 81 68 04 0b c6 0b 00 ff 48 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_I_2147686131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.I"
        threat_id = "2147686131"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6e 61 62 6c 65 64 3a 00}  //weight: 1, accuracy: High
        $x_5_2 = {74 72 65 77 2f 31 2e 30 20 32 30 30 20 4f 4b 0d}  //weight: 5, accuracy: High
        $x_1_3 = {44 75 72 73 65 6e 74 57 ?? 72 73 69 6f 6e 5c ?? 69 6e 6c 6f 68 6f 6e 5c 4f 6f 74 69 66 79}  //weight: 1, accuracy: Low
        $x_5_4 = {41 33 c1 89 85 60 fe ff ff b9 35 00 00 00 86 e9 66 89 8d 5e fe ff ff 66 c7 85 5c fe ff ff 02 00 6a 10 8d 8d 5c fe ff ff 51 ff b5 30 fe ff ff ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_K_2147692301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.K"
        threat_id = "2147692301"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 01 c6 41 07 32 c6 41 06 33 fe 49 05 50}  //weight: 2, accuracy: High
        $x_1_2 = "trew/1.0 200 OK" ascii //weight: 1
        $x_1_3 = {75 72 73 65 6e 74 ?? ?? 72 73 69 6f 6e ?? ?? ?? ?? ?? ?? 68 6f 6e ?? ?? ?? 74 69 66 79 5c}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 58 68 61 72 64 64 ?? 63 63 65 73 73 5c 53 ?? 72 61 6d 65 74 65 72 73 5c 47 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_K_2147692301_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.K"
        threat_id = "2147692301"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 3c 61 7c 05 2c 10 48 2c 0f c1 cf 0d 03 f8 8b ff e2 ea 3b 7d 24 8b 5a 10 ff 32 5a 0f 85 ?? ?? ?? ?? 89 5c 24 1c 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {fc 47 47 b8 ?? ?? ?? ?? 51 c7 00 [0-14] 81 28 [0-7] fe 48 06 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_3 = {fc 47 47 b8 [0-10] 51 [0-21] 81 28 [0-8] fe 48 06 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_4 = {01 00 00 fc 47 47 [0-48] fe 48 06 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_5 = {01 00 00 fc 47 47 [0-48] 80 68 06 01 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_6 = {01 00 00 fc 83 c7 01 [0-51] 80 68 06 01 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_7 = {01 00 00 fc 8d 7f 02 [0-48] 80 68 06 01 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_8 = {01 00 00 fc ?? d2 (42|83) [0-48] 80 68 06 01 5a 53 56 8b df bf}  //weight: 1, accuracy: Low
        $x_1_9 = {80 68 06 01 5a 53 56 8b df bf ?? ?? ?? ?? 33 c0 b9 2c 01 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {28 50 06 5a 53 56 8b df bf ?? ?? ?? ?? 33 c0 b9 2c 01 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {ff 40 04 5a 53 56 8b df bf ?? ?? ?? ?? 33 c0 b9 2c 01 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = {89 85 30 fe ff ff 6a 01 68 ?? ?? ?? ?? 6a 08 68 ff ff 00 00 50 e8}  //weight: 1, accuracy: Low
        $x_1_13 = {10 fd 60 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 [0-16] 39 0d}  //weight: 1, accuracy: Low
        $x_1_14 = {10 fd 60 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? b8 [0-18] 39 0d}  //weight: 1, accuracy: Low
        $x_1_15 = {59 c6 41 01 2e 50 68 ?? ?? ?? ?? 6a 01 6a 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f7 d8 61 fc e9}  //weight: 1, accuracy: Low
        $x_1_16 = {f2 ae 83 f9 00 0f 84 ?? ?? ?? ?? c6 47 01 00 57 b0 5c}  //weight: 1, accuracy: Low
        $x_1_17 = {75 72 73 65 6e 74 ?? ?? 72 73 69 6f 6e ?? ?? ?? ?? ?? ?? 68 6f 6e ?? ?? ?? 74 69 66 79 5c}  //weight: 1, accuracy: Low
        $x_1_18 = {5c 58 68 61 72 64 64 ?? 63 63 65 73 73 5c 53 ?? 72 61 6d 65 74 65 72 73 5c 47 69 72 65 ?? 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c}  //weight: 1, accuracy: Low
        $x_1_19 = "trew/1.0 200 OK" ascii //weight: 1
        $x_1_20 = {6e 73 31 2e [0-16] 2e 03 03 03 03 78 79 7a 6e 65 74 63 6f 6d 00}  //weight: 1, accuracy: Low
        $x_1_21 = {6e 73 7a 2e [0-16] 2e 03 03 03 03 78 79 7a 6e 65 74 63 6f 6d 00}  //weight: 1, accuracy: Low
        $x_1_22 = {6e 73 79 2e [0-16] 2e 04 03 03 03 04 78 79 7a 6e 65 74 63 6f 6d 69 6e 66 6f 00}  //weight: 1, accuracy: Low
        $x_1_23 = {6e 73 35 2e [0-16] 2e 63 6f 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_L_2147697258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.L"
        threat_id = "2147697258"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 89 10 b2 6e 88 50 04 b2 65 86 d6 88 70 08 51 b9 2a 19 78 17 87 d1}  //weight: 1, accuracy: High
        $x_2_2 = "Donurolxet000\\Services\\XharddBccess" ascii //weight: 2
        $x_1_3 = {6e 73 79 2e [0-16] 2e 04 03 03 03 04 78 79 7a 6e 65 74 63 6f 6d 69 6e 66 6f 00}  //weight: 1, accuracy: Low
        $x_1_4 = "trew/1.0 200 OK" ascii //weight: 1
        $x_1_5 = {63 6c 64 33 2e [0-16] 2e 63 6f 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_L_2147697258_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.L"
        threat_id = "2147697258"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c6 41 06 6e 80 69 06 21 fe 49 2c fe 41 05 fe 49 08 fe 41 23 fe 49 2d}  //weight: 3, accuracy: High
        $x_1_2 = {40 89 10 b2 6e 88 50 04 b2 65 86 d6 88 70 08 51 b9 2a 19 78 17 87 d1}  //weight: 1, accuracy: High
        $x_2_3 = "Donurolxet000\\Services\\XharddBccess" ascii //weight: 2
        $x_1_4 = "ns1.diduit.info" ascii //weight: 1
        $x_1_5 = "trew/1.0 200 OK" ascii //weight: 1
        $x_1_6 = "brkewll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_M_2147706116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.M"
        threat_id = "2147706116"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 49 02 c6 41 0e 32 c6 41 0c 33 80 29 07}  //weight: 2, accuracy: High
        $x_1_2 = "trew/1.0 200 OK" ascii //weight: 1
        $x_1_3 = {75 72 73 65 6e 74 ?? ?? 72 73 69 6f 6e ?? ?? ?? ?? ?? ?? 68 6f 6e ?? ?? ?? 74 69 66 79 5c}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 58 68 61 72 64 64 ?? 63 63 65 73 73 5c 53 ?? 72 61 6d 65 74 65 72 73 5c 47 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_N_2147707404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.N"
        threat_id = "2147707404"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7f 10 33 75 20 33 c0 68 ?? ?? ?? ?? 50 ff 77 11 68 ?? ?? ?? ?? ff 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 ?? ?? ?? ?? 87 d1 29 10 59}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 78 83 c0 78 c1 e8 0a 56 be 3c 00 00 00 3b c6 72 10 83 e8 1e 83 e8 1e 41 3b ce 75 03}  //weight: 1, accuracy: High
        $x_1_4 = {4a 0b d2 75 11 0f 31 0f b6 c0 c1 e0 02 bf ?? ?? ?? ?? 03 f8 eb 05 83 3f 00 75 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_O_2147708586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.O"
        threat_id = "2147708586"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 41 07 32 fe 09 fe 41 01 fe 09 fe 49 05 c6 41 06}  //weight: 1, accuracy: High
        $x_1_2 = {83 c2 01 c1 e2 03 c1 e2 03 8d 04 02 ba ?? ?? ?? ?? 52 8f 00 83 28 08}  //weight: 1, accuracy: Low
        $x_1_3 = {89 10 b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08}  //weight: 1, accuracy: High
        $x_1_4 = {00 61 61 63 6c 66 64 3a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_P_2147719011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.P!bit"
        threat_id = "2147719011"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 64 76 3d 4e 65 74 77 6f 72 6b 4d 61 6e 61 67 65 72 26 73 68 6f 72 74 6e 61 6d 65 3d 4e 65 74 77 6f 72 6b 4d 61 6e 61 67 65 72 26 [0-32] 6b 65 79 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "Agent: ace4956e-736e-11e6-9584-d7165ca591df" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = {41 54 59 4e 4b 41 4a 50 33 30 5a 39 41 51 00}  //weight: 1, accuracy: High
        $x_1_5 = {79 65 55 21 48 6c 71 4d 50 43 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 56 6f 00 6d 74 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3}  //weight: 1, accuracy: High
        $x_1_8 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 ?? ?? ?? ?? 87 d1 29 10 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanProxy_Win32_Bunitu_R_2147720067_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.R!bit"
        threat_id = "2147720067"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 74 6e 76 69 61 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 61 74 6e 76 69 61}  //weight: 2, accuracy: High
        $x_1_2 = {89 4a 04 83 6a 04 ?? b8 01 00 00 00 48 b9 ?? ?? ?? ?? 41}  //weight: 1, accuracy: Low
        $x_1_3 = {fe 09 c6 41 ?? ?? fe 49 ?? c6 41 ?? ?? fe 49 ?? fe 09 51 e8 68 20 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bunitu_R_2147720067_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.R!bit"
        threat_id = "2147720067"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 78 83 c0 78 c1 e8 0a 56 be 3c 00 00 00 3b c6 72 10 83 e8 1e 83 e8 1e 41 3b ce 75 03}  //weight: 1, accuracy: High
        $x_1_3 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 ?? ?? ?? ?? 87 d1 29 10 59}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "advfirewall firewall add rule name=\"Rundll32\" dir=out action=allow protocol=any" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_RL_2147741344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.RL!MTB"
        threat_id = "2147741344"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 30 8b 45 f8 0f b6 08 03 ca 8b 55 f8 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {31 4d fc 8b 45 fc c7 45 fc ?? ?? ?? ?? 8b c8 b8 00 00 00 00 03 c1 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_G_2147741745_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.G!MTB"
        threat_id = "2147741745"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 0f b6 08 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 0f b6 02 03 c1 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 01 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 56 8b 15 ?? ?? ?? ?? 8b f6 8b ca 8b f6 ff 35 ?? ?? ?? ?? 8f 45 ?? 8b 55 ?? 33 d1 8b c2 8b c8 b8 [0-4] 03 c1 89 45 ?? ?? ?? ?? ?? ?? 8b 4d ?? 89 08 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = "488888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" wide //weight: 1
        $x_1_4 = "111QueryValueExW" ascii //weight: 1
        $x_1_5 = {8b 4d f8 c6 01 52 8b 55 f8 c6 42 01 65 8b 45 f8 c6 40 02 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_GA_2147742246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.GA!MTB"
        threat_id = "2147742246"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 8b 45 [0-4] 0f b6 08 03 ca 8b 55 [0-4] 88 0a 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 56 [0-24] 33 ?? 8b ?? 8b ?? b8 [0-4] 03 c1 [0-13] 8b 4d fc 89 08 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = "488888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" wide //weight: 1
        $x_1_4 = "111QueryValueExW" ascii //weight: 1
        $x_1_5 = {8b 4d f8 c6 01 52 8b 55 f8 c6 42 01 65 8b 45 f8 c6 40 02 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_GN_2147742604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.GN!MTB"
        threat_id = "2147742604"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 8b [0-5] 03 [0-5] 0f b6 ?? 8b [0-5] 0f b6 ?? 03 ?? 8b [0-5] 88 [0-2] 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 89 08 1c 00 31 [0-7] b8 [0-4] 03 c1}  //weight: 1, accuracy: Low
        $x_1_3 = "488888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" wide //weight: 1
        $x_1_4 = "111QueryValueExW" ascii //weight: 1
        $x_1_5 = {8b 4d f8 c6 01 52 8b 55 f8 c6 42 01 65 8b 45 f8 c6 40 02 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_GE_2147742651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.GE!MTB"
        threat_id = "2147742651"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 89 45 fc [0-25] 03 [0-13] 0f b6 [0-2] 8b [0-5] 0f b6 ?? 03 ?? 8b [0-5] 88 [0-2] 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 89 08 28 00 b8 [0-4] 03 c1}  //weight: 1, accuracy: Low
        $x_1_3 = "488888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" wide //weight: 1
        $x_1_4 = "111QueryValueExW" ascii //weight: 1
        $x_1_5 = {8b 4d f8 c6 01 52 8b 55 f8 c6 42 01 65 8b 45 f8 c6 40 02 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_GF_2147744848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.GF!MTB"
        threat_id = "2147744848"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 83 ec ?? 56 8b [0-5] ff [0-5] 8f [0-2] 8b [0-200] 03 01 01 01 32 30 33 f2 b8 [0-4] b8 [0-4] b8 [0-4] b8 [0-4] b8}  //weight: 1, accuracy: Low
        $x_1_2 = "4n8888888888888888888888881888888888888888888888888888888888888888888888888888888888888888888888888888888" wide //weight: 1
        $x_1_3 = {55 8b ec b8 31 [0-15] 64 [0-15] 30 [0-15] 2d [0-15] 39 [0-15] 33 [0-15] 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_HA_2147749791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.HA!MTB"
        threat_id = "2147749791"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 75 ?? 03 75 ?? 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 8b 55 ?? 03 55 ?? 8b 45 ?? 8b 4d ?? 8a 0c 31 88 0c 10 8b 55 ?? 83 c2 01 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bunitu_HB_2147749792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bunitu.HB!MTB"
        threat_id = "2147749792"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 0a 03 2b 85 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 e9 03 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

