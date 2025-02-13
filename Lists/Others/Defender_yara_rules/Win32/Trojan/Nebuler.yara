rule Trojan_Win32_Nebuler_F_2147606494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.F"
        threat_id = "2147606494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 45 fc 8b 4d fc 8d 5c 03 01 8b 45 08 83 c7 ?? 3b 08 72 84 5e 33 c0 85 db 7e 11 8a c8 80 e9 15 30 8c 05 fc f7 ff ff 40 3b c3 7c ef 53 8d 85 fc f7 ff ff 50 ff 75 10 8b 45 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 77 69 6e 00 8d 48 03 5e e8 ?? ?? 00 00 6a 1a 99 5f f7 ff 80 c2 61 88 11 41 4e 75 ec c7 01 33 32 00 00 41 41 5f c7 01 2e 64 6c 6c c6 41 04 00 b0 01}  //weight: 1, accuracy: Low
        $x_1_3 = "&v=%d&b=%d&id=%X&cnt=%s&q=%X" ascii //weight: 1
        $x_1_4 = "m3d5rt10" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Nebuler_B_2147609387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!B"
        threat_id = "2147609387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HookEx" ascii //weight: 1
        $x_1_2 = "CreateProcessAsUserA" ascii //weight: 1
        $x_1_3 = "RasEnumDevicesA" ascii //weight: 1
        $x_1_4 = "%d&cmdid=%d" ascii //weight: 1
        $x_1_5 = "EvtShutdown" ascii //weight: 1
        $x_1_6 = "EvtStartup" ascii //weight: 1
        $x_1_7 = "del \"%s\"" ascii //weight: 1
        $x_1_8 = "SHGetValueA" ascii //weight: 1
        $x_1_9 = "SHDeleteValueA" ascii //weight: 1
        $x_1_10 = "GetAdaptersInfo" ascii //weight: 1
        $x_1_11 = "iphlpapi.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nebuler_C_2147609388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!C"
        threat_id = "2147609388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 19 6a 00 6a 00 8d 86 ?? ?? 00 00 50 8d 46 0c 50 6a 00 ff d1 f7 d8 1a c0 fe c0 88 86 ?? ?? 00 00 f6 d8 1b c0 83 e0 eb 83 c0 15 5f 5e c2 04 00}  //weight: 2, accuracy: Low
        $x_1_2 = {74 1a 53 56 8b f7 2b f1 8a d8 80 eb ?? 32 da 88 1c 0e 40 41 8a 11 84 d2 75 ee 5e 5b c6 04 38 00}  //weight: 1, accuracy: Low
        $x_1_3 = "&v=%d&b=%d&id=%X&cnt=%s&q=%X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_D_2147609390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!D"
        threat_id = "2147609390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e4 0f b6 80 ?? ?? 40 00 8b 8d ?? ?? ff ff 81 e1 ff ff 00 00 0f b7 c9 81 e1 ff 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {74 1a 53 56 8b f7 2b f1 8a d8 80 ?? ?? 32 da 88 1c 0e 40 41 8a 11 84 d2 75 ee}  //weight: 2, accuracy: Low
        $x_2_3 = {74 14 56 8b f0 2b f1 80 f2 ?? 88 14 0e 47 41 8a 11 84 d2 75 f2}  //weight: 2, accuracy: Low
        $x_2_4 = {74 13 56 8b f7 2b f1 32 d3 88 14 0e 43 41 8a 11 84 d2 75 f3 5e c6 04 3b 00}  //weight: 2, accuracy: High
        $x_2_5 = {6a 20 58 64 8b 40 10 85 c0 0f 88 0c 00 00 00 8b 40 0c 8b 70 1c ad 8b 50 08 eb 0c 8b 40 34 33 c9 b1 b8}  //weight: 2, accuracy: High
        $x_4_6 = {5e 5b 33 c0 39 45 fc 5f 7e 12 8a c8 80 e9 15 30 8c 05 ?? ?? ff ff 40 3b 45 fc 7c ee ff 75 fc 8d 85 ?? ?? ff ff 50 8b 45 0c 6a 03}  //weight: 4, accuracy: Low
        $x_1_7 = {63 3d 52 25 64 26 63 6d 64 69 64 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 3d 4c 31 26 73 3d 25 75 26 68 3d 25 75 00}  //weight: 1, accuracy: High
        $x_1_9 = {26 76 3d 25 64 26 62 3d 25 64 26 69 64 3d 25 58 26 63 6e 74 3d 25 73 26 71 3d 25 58 00}  //weight: 1, accuracy: High
        $x_1_10 = {55 52 4c 41 6e 64 45 78 69 74 43 6f 6d 6d 61 6e 64 73 45 6e 61 62 6c 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_A_2147609391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!A"
        threat_id = "2147609391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {89 5d f8 ad 8b d8 03 da ad 85 c0 74 3f 8b c8 83 e9 08 85 c9 74 ed 66 c7 45 fe ff ff 66 ad 66 83 7d fe ff 74 04}  //weight: 50, accuracy: High
        $x_50_2 = {8b 75 fc 8b 4d 0c 0f b6 36 c1 e1 08 0b ce c1 e0 08 ff 45 fc 89 4d 0c 8b 0c 93 8b f0 c1 ee 0b 0f af f1 39 75 0c 73 15 8b c6 be 00 08 00 00 2b f1 c1 ee 05 03 f1 89 34 93 03 d2 eb 16}  //weight: 50, accuracy: High
        $x_5_3 = {00 45 76 74 53 68 75 74 64 6f 77 6e 00 45 76 74 53 74 61 72 74 75 70 00 69 6e 73 74 00 72 75 6e 00 74 65 73 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 69 6e 73 74 00 69 6e 73 74 32 00 6d 6f 75 6e 74 00 73 74 61 72 74 75 70 00 74 65 73 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_G_2147611130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.G"
        threat_id = "2147611130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 4d 0c 8a 4c 01 01 8b 55 08 80 f1 ?? 88 0c 10 40 3b c6 72 eb 8b 45 08 5f c6 04 06 00 5e 5b c9 c2 08 00}  //weight: 4, accuracy: Low
        $x_4_2 = {33 ff 85 f6 89 45 f8 76 20 8b 55 fc 8b cb 2b d3 8b de 8a 04 0a 32 87 ?? ?? ?? ?? 47 3b 7d f8 88 01 75 02 33 ff 41 4b 75 e9 33 c0 85 f6 76 15}  //weight: 4, accuracy: Low
        $x_4_3 = {8a 11 33 c0 84 d2 74 1a 53 56 8b f7 2b f1 8a d8 80 eb ?? 32 da 88 1c 0e 40 41 8a 11 84 d2 75 ee 5e 5b c6 04 38 00 8b c7 c3}  //weight: 4, accuracy: Low
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "c=I%d" ascii //weight: 1
        $x_1_6 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 00 5b 6d 6f 64 65 6d 5d 00 5b 62 72 61 6e 64 5d 00 5b 76 65 72 73 69 6f 6e 5d}  //weight: 1, accuracy: High
        $x_5_7 = {53 68 75 74 64 6f 77 6e ?? ?? ?? ?? 53 74 61 72 74 75 70 ?? ?? ?? ?? 54 65 73 74 19 00 2e 64 6c 6c ?? ?? ?? ?? 49 6e 73 74 ?? ?? ?? ?? 52 75 6e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_E_2147611729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!E"
        threat_id = "2147611729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 23 8b 85 ?? ?? ff ff 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 20 58 64 8b 40 10 85 c0 0f 88 0c 00 00 00 8b 40 0c 8b 70 1c ad 8b 50 08 eb 0c 8b 40 34 33 c9 b1 b8}  //weight: 1, accuracy: High
        $x_1_3 = {8a da 8d 0c 3a 80 c3 ?? 32 1c 08 42 3b d6 88 19 72 ee}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d f0 8b 45 08 8b 55 0c 03 c1 80 c1 ?? 32 0c 02 88 08}  //weight: 1, accuracy: Low
        $x_1_5 = {76 0e 8a 44 0e 01 34 73 88 04 ?? 41 3b ca 72 f2}  //weight: 1, accuracy: Low
        $x_1_6 = {5f 7e 12 8a c8 80 e9 ?? 30 8c 05 ?? ?? ff ff 40 3b 45 fc 7c ee ff 75 fc}  //weight: 1, accuracy: Low
        $x_1_7 = {5b 6d 6f 64 65 6d 5d 00 5b 62 72 61 6e 64 5d 00}  //weight: 1, accuracy: High
        $x_1_8 = {62 31 30 30 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {0c 52 5f 49 52 58 52 0c 72 6f 26 2f 28 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Nebuler_F_2147615333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!F"
        threat_id = "2147615333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = {4d 53 53 4d 53 47 53 00 25 73 5c 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {5b 62 72 61 6e 64 5d 00 5b 76 65 72 73 69 6f 6e 5d 00 00 00 5b 75 69 64 5d}  //weight: 1, accuracy: High
        $x_1_4 = {53 68 75 74 64 6f 77 6e [0-4] 53 74 61 72 74 75 70 [0-4] 54 65 73 74 19 2e 64 6c 6c [0-4] 49 6e 73 74 [0-4] 52 75 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nebuler_G_2147616736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!G"
        threat_id = "2147616736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1d 8b 45 08 03 45 f8 0f be 40 01 0f b6 0d ?? ?? ?? ?? 33 c1 8b 4d f4 03 4d f8 88 01 eb d4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 17 33 c9 85 d2 76 1c 8d a4 24 00 00 00 00 8a 44 0f 01 34 ?? 88 04 31 41 3b ca 72 f2 c6 04 32 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 07 32 54 0b 01 41 88 10 40 3b ce 72 f1}  //weight: 1, accuracy: High
        $x_1_4 = {8a 1c 17 32 5c 29 01 41 88 1a 42 3b ce 72 f1}  //weight: 1, accuracy: High
        $x_1_5 = {8a d0 80 ea 15 30 54 04 0c 40 3b c3 7c f2}  //weight: 1, accuracy: High
        $x_1_6 = {5b 62 72 61 6e 64 5d 00 5b 76 65 72 73 69 6f 6e 5d 00 00 00 5b 75 69 64 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Nebuler_H_2147616782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!H"
        threat_id = "2147616782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c1 8b 4d f4 03 4d f8 88 01 eb d1 8b 45 f4 03 45 fc c6 00 00 8b 45 f4}  //weight: 10, accuracy: High
        $x_10_2 = {33 c1 8b 4d e4 03 4d ec 88 81 fe 01 00 00 8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 f4 75 04 83 65 fc 00 eb b7}  //weight: 10, accuracy: High
        $x_1_3 = {81 bd 30 f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
        $x_1_4 = {81 bd 34 f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
        $x_1_5 = {81 bd 2c f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
        $x_1_6 = {81 bd 1c f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
        $x_1_7 = {81 bd 20 f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
        $x_1_8 = {81 bd 24 f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
        $x_1_9 = {81 bd 28 f4 ff ff 00 05 01 02 01 01 01 8e 90 98 9a 9c 00 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_J_2147625561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.J"
        threat_id = "2147625561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 53 53 4d 53 47 53 00 25 73 5c 25 73 00 00 00 50 49 44 00 4c 49 44 00 65 6d 70 74 79 00 00 00 5c 57 69 6e 49 6e 69 74 2e 49 6e 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nebuler_J_2147631947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.J"
        threat_id = "2147631947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 29 8b 8d ?? ?? ?? ?? 0f b6 94 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 33 ca 8b 95 ?? ?? ?? ?? 88 8a}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 68 58 4d 56 b9 14 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nebuler_K_2147632543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.K"
        threat_id = "2147632543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4d 53 53 4d 53 47 53 00}  //weight: 2, accuracy: High
        $x_2_2 = {2e 72 6f 6d [0-4] 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 00}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 44 24 08 83 e8 01 75 2d 8b 44 24 04 68 00 04 00 00 68 ?? ?? ?? 10 50 a3 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 85 c0 b8 01 00 00 00 75 0f c6 05 ?? ?? ?? 10 00 c2 0c 00 b8 01 00 00 00 c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 28 8b 4d 08 89 0d ?? ?? ?? 10 68 00 04 00 00 68 ?? ?? ?? 10 8b 55 08 52 ff 15 ?? ?? ?? 10 85 c0 75 07 c6 05 ?? ?? ?? 10 00 b8 01 00 00 00 8b e5 5d c2 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_I_2147639579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.gen!I"
        threat_id = "2147639579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 10 ff ff ff 3b 55 f4 73 37 6a 00 ff 15 ?? ?? ?? ?? 89 45 f0 8b 45 08 03 85 10 ff ff ff 0f be 48 01 8b 95 10 ff ff ff 0f be 82 c0 24 01 10 33 c8 8b 95 0c ff ff ff 03 95 10 ff ff ff 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nebuler_Q_2147642145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.Q"
        threat_id = "2147642145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 42 01 8b 8d ?? ?? ?? ?? 0f be 91 ?? ?? ?? ?? 33 c2 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 09 00 8b 55 08 03 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nebuler_R_2147651150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.R"
        threat_id = "2147651150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 10 08 00 00 50 8b 4d 08 8b 51 08 ff d2 89 45 f4 83 7d f4 00 75 ?? b8 29 00 00 00 e9 ?? ?? ?? ?? 8b 45 08 05 30 08 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 8b 45 0c 50 8b ?? ?? e8 ?? ?? ?? ?? 0f b6 c8 85 c9 74 ?? 8b ?? ?? 83 7a ?? 10 72}  //weight: 2, accuracy: Low
        $x_1_3 = "GetBkMode" ascii //weight: 1
        $x_1_4 = "Google Toolbar" ascii //weight: 1
        $x_1_5 = "&PrcArc=" ascii //weight: 1
        $x_1_6 = "&SuiMsk=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nebuler_R_2147651150_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nebuler.R"
        threat_id = "2147651150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 dc 83 7d dc 00 74 17 83 7d dc 01 74 02 eb 1b 8b 4d 08 89 0d ?? ?? ?? ?? eb 10 eb 0e eb 0c 8d 55 e0 52 e8}  //weight: 5, accuracy: Low
        $x_1_2 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 20 31 2e 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 42 6c 64 4e 75 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 43 53 44 56 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 53 79 6d 53 72 32 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {26 50 72 63 41 72 63 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 53 75 69 4d 73 6b 3d 00}  //weight: 1, accuracy: High
        $x_1_9 = {26 50 72 64 54 79 70 3d 00}  //weight: 1, accuracy: High
        $x_1_10 = {26 76 65 72 3d 74 72 75 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {73 74 6f 70 5f 66 75 6e 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

