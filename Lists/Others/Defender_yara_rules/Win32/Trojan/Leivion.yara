rule Trojan_Win32_Leivion_A_2147725335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.A"
        threat_id = "2147725335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 c7 44 24 04 40 42 0f 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 04 ff d0 c7 45 f4 00 00 00 00 eb 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Leivion_E_2147727845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.E"
        threat_id = "2147727845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0b 00 00 0a 11 05 16 20 bf 00 00 00 9c 11 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Leivion_G_2147728043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.G"
        threat_id = "2147728043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 48 00 68 00 6d 00 59 00 79 00 77 00 77 00 65 00 47 00 55 00 34 00 4c 00 44 00 42 00 34 00 4f 00 44 00 59 00 73 00 4d 00 48 00 67 00 77 00 4d 00 43 00 77 00 77 00 65 00 44 00 41 00 77 00 4c 00 44 00 42 00 34 00 4d 00 44 00 41 00 73 00 4d 00 48 00 67 00 32 00 4d 00 43 00 77 00 77 00 65 00 44 00 67 00 35 00 4c 00 44 00 42 00 34 00 5a 00 54 00 55 00 73 00 4d 00 48 00 67 00 7a 00 4d 00 53 00 77 00 77 00 65 00 47 00 51 00 79 00 4c 00 44 00 42 00 34 00 4e 00 6a 00 51 00 73 00 4d 00 48 00 67 00 34 00 59 00 69 00 77 00 77 00 65 00 44 00 55 00 79 00 4c 00 44 00 42 00 34 00 4d 00 7a 00 41 00 73 00 4d 00 48}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 48 00 68 00 6d 00 59 00 79 00 77 00 77 00 65 00 47 00 55 00 34 00 4c 00 44 00 42 00 34 00 4f 00 44 00 6b 00 73 00 4d 00 48 00 67 00 77 00 4d 00 43 00 77 00 77 00 65 00 44 00 41 00 77 00 4c 00 44 00 42 00 34 00 4d 00 44 00 41 00 73 00 4d 00 48 00 67 00 32 00 4d 00 43 00 77 00 77 00 65 00 44 00 67 00 35 00 4c 00 44 00 42 00 34 00 5a 00 54 00 55 00 73 00 4d 00 48 00 67 00 7a 00 4d 00 53 00 77 00 77 00 65 00 47 00 51 00 79 00 4c 00 44 00 42 00 34 00 4e 00 6a 00 51 00 73 00 4d 00 48 00 67 00 34 00 59 00 69 00 77 00 77 00 65 00 44 00 55 00 79 00 4c 00 44 00 42 00 34 00 4d 00 7a 00 41 00 73 00 4d 00 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Leivion_I_2147728052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.I"
        threat_id = "2147728052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc e8 86 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 8b 4c 10 78 e3 4a 01 d1 51 8b 59 20 01 d3 8b 49 18 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61}  //weight: 1, accuracy: High
        $x_1_2 = {fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4a 01 d0 50 8b 48 18 8b 58 20 01 d3 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Leivion_J_2147728056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.J!!Leivion.J"
        threat_id = "2147728056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        info = "Leivion: an internal category used to refer to some threats"
        info = "J: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 48 00 68 00 6d 00 59 00 79 00 77 00 77 00 65 00 47 00 55 00 34 00 4c 00 44 00 42 00 34 00 4f 00 44 00 59 00 73 00 4d 00 48 00 67 00 77 00 4d 00 43 00 77 00 77 00 65 00 44 00 41 00 77 00 4c 00 44 00 42 00 34 00 4d 00 44 00 41 00 73 00 4d 00 48 00 67 00 32 00 4d 00 43 00 77 00 77 00 65 00 44 00 67 00 35 00 4c 00 44 00 42 00 34 00 5a 00 54 00 55 00 73 00 4d 00 48 00 67 00 7a 00 4d 00 53 00 77 00 77 00 65 00 47 00 51 00 79 00 4c 00 44 00 42 00 34 00 4e 00 6a 00 51 00 73 00 4d 00 48 00 67 00 34 00 59 00 69 00 77 00 77 00 65 00 44 00 55 00 79 00 4c 00 44 00 42 00 34 00 4d 00 7a 00 41 00 73 00 4d 00 48}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 48 00 68 00 6d 00 59 00 79 00 77 00 77 00 65 00 47 00 55 00 34 00 4c 00 44 00 42 00 34 00 4f 00 44 00 6b 00 73 00 4d 00 48 00 67 00 77 00 4d 00 43 00 77 00 77 00 65 00 44 00 41 00 77 00 4c 00 44 00 42 00 34 00 4d 00 44 00 41 00 73 00 4d 00 48 00 67 00 32 00 4d 00 43 00 77 00 77 00 65 00 44 00 67 00 35 00 4c 00 44 00 42 00 34 00 5a 00 54 00 55 00 73 00 4d 00 48 00 67 00 7a 00 4d 00 53 00 77 00 77 00 65 00 47 00 51 00 79 00 4c 00 44 00 42 00 34 00 4e 00 6a 00 51 00 73 00 4d 00 48 00 67 00 34 00 59 00 69 00 77 00 77 00 65 00 44 00 55 00 79 00 4c 00 44 00 42 00 34 00 4d 00 7a 00 41 00 73 00 4d 00 48}  //weight: 1, accuracy: High
        $x_1_3 = {fc e8 86 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 8b 4c 10 78 e3 4a 01 d1 51 8b 59 20 01 d3 8b 49 18 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61}  //weight: 1, accuracy: High
        $x_1_4 = {fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4a 01 d0 50 8b 48 18 8b 58 20 01 d3 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Leivion_L_2147728117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.L"
        threat_id = "2147728117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec c6 00 bf 8b 45 ec 8d 50 01}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Leivion_O_2147728187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.O"
        threat_id = "2147728187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "len = string.len(shellcode)" ascii //weight: 1
        $x_1_2 = {76 61 20 3d 20 6b 65 72 6e 65 6c 33 32 2e 56 69 72 74 75 61 6c 41 6c 6c 6f 63 0a 76 61 3a 74 79 70 65 73 7b 20 72 65 74 20 3d 20 27 69 6e 74 27 2c 20 61 62 69 20 3d 20 27 73 74 64 63 61 6c 6c 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 20 7d 0a 70 74 72 20 3d 20 76 61 28 30 2c 20 6c 65 6e 2c 20 30 78 33 30 30 30 2c 20 30 78 34 30 29}  //weight: 1, accuracy: High
        $x_1_3 = {63 74 20 3d 20 6b 65 72 6e 65 6c 33 32 2e 43 72 65 61 74 65 54 68 72 65 61 64 0a 63 74 3a 74 79 70 65 73 7b 20 72 65 74 20 3d 20 27 69 6e 74 27 2c 20 61 62 69 20 3d 20 27 73 74 64 63 61 6c 6c 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 2c 20 27 69 6e 74 27 2c 20 27 72 65 66 20 69 6e 74 27 7d 0a 68 74 20 3d 20 63 74 28 30 2c 20 30 2c 20 70 74 72 2c 20 30 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Leivion_S_2147729339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leivion.S"
        threat_id = "2147729339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leivion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8b 5c 24 08 64 8b 0d 14 00 00 00 83 f9 00 75 03 ff d0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b a9 00 00 00 00 8b 6d 18 8b 34 24 89 b5 24 02 00 00 8b b1 00 00 00 00 89 b5 2c 02 00 00 8d 74 24 04 89 b5 28 02 00 00 8b 75 00 39 b1 00 00 00 00 75 1d ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {64 8b 0d 14 00 00 00 8b a9 00 00 00 00 8b 6d 18 c7 85 28 02 00 00 00 00 00 00 c3}  //weight: 1, accuracy: High
        $x_10_4 = {8b 44 24 70 8b 5c 24 28 89 1c 24 89 44 24 04 e8 ?? ?? ?? ?? 8b 74 24 3c 8b 5c 24 08 8b 6c 24 70 39 eb 0f 83 ad 00 00 00 8b 6c 24 6c 01 dd 0f b6 5d 00 88 5c 24 23 8b 4c 24 34 8b 44 24 38 89 c3 43 39 f3 77 54 89 df 89 5c 24 38 89 cb 01 c3 0f b6 6c 24 23 95 88 03 95 8b 44 24 24 40 89 44 24 24 8b 6c 24 68 39 e8 7c 97}  //weight: 10, accuracy: Low
        $x_10_5 = {b9 bf 00 00 00 88 0a 88 42 01 31 c0 88 42 02 31 c0 88 42 03 31 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

