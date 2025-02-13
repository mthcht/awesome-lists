rule Trojan_WinNT_Alureon_C_133874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.C"
        threat_id = "133874"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 38 4d 5a 0f 84 ?? ?? 00 00 48}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 00 02 00 00 8b 09}  //weight: 1, accuracy: High
        $x_1_3 = {0f 01 0c 24 ff 74 24 02}  //weight: 1, accuracy: High
        $x_1_4 = {ad 33 c2 ab}  //weight: 1, accuracy: High
        $x_1_5 = {94 c8 37 09}  //weight: 1, accuracy: High
        $x_1_6 = {a2 b3 45 5e}  //weight: 1, accuracy: High
        $x_1_7 = {bb 64 0b 73}  //weight: 1, accuracy: High
        $x_1_8 = {c4 e8 40 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_WinNT_Alureon_D_134074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.D"
        threat_id = "134074"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 56 01 00 c0 ff 15 06 00 32 d2 8b 03 01 01 01 cf ce cb c7 03 01 01 01 47 46 43}  //weight: 1, accuracy: Low
        $x_1_2 = {74 14 c7 43 18 57 01 00 c0 8b ?? 18 (50|2d|57) ff (70|2d|77) 04}  //weight: 1, accuracy: Low
        $x_1_3 = {7c 21 33 c0 8a c8 80 c1 54 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed}  //weight: 1, accuracy: Low
        $x_1_4 = {8a c8 80 c1 54 30 88 ?? ?? ?? ?? 40 3b c7 72 f0}  //weight: 1, accuracy: Low
        $x_1_5 = {8a d0 80 c2 54 30 90 ?? ?? ?? ?? 40 3b c1 72 f0}  //weight: 1, accuracy: Low
        $x_1_6 = {81 7d 08 32 4c 44 54 [0-1] 75 ?? 8b 45 ?? 2d 43 43 52 50}  //weight: 1, accuracy: Low
        $x_1_7 = {81 e9 4b 43 52 50 74 21}  //weight: 1, accuracy: High
        $x_2_8 = {b8 50 43 52 50 3b c8 77 ?? 74 ?? 8b c1 2d 44 44 41 4d}  //weight: 2, accuracy: Low
        $x_2_9 = {81 7d 08 51 4e 52 54 75 13 81 7d 0c 44 44 41 4d}  //weight: 2, accuracy: High
        $x_1_10 = {76 0d 8a d1 80 c2 54 30 14 31 41 3b c8 72 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Alureon_E_142490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.E"
        threat_id = "142490"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\?\\globalroot\\systemroot\\system32\\drivers\\" ascii //weight: 1
        $x_1_2 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 [0-16] 5c 00 69 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\FileSystem\\FltMgr" wide //weight: 1
        $x_1_4 = "\\driver\\disk" wide //weight: 1
        $x_1_5 = "\\filesystem\\fastfat" wide //weight: 1
        $x_1_6 = "\\driver\\tcpip" wide //weight: 1
        $x_1_7 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 65 00 6e 00 75 00 6d 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 6c 00 65 00 67 00 61 00 63 00 79 00 5f 00 [0-16] 2e 00 73 00 79 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_143835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon"
        threat_id = "143835"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Driver\\Beep" wide //weight: 1
        $x_1_2 = "services.exe" wide //weight: 1
        $x_1_3 = "FireFox.exe" wide //weight: 1
        $x_10_4 = {53 68 03 00 1f 00 8d 44 24 3c 50 83 ef 24 c7 44 24 38 4c 6f 64 72 c7 44 24 3c 0a 00 00 00 ff 15}  //weight: 10, accuracy: High
        $x_10_5 = {0f b6 54 98 08 8b 5c 24 18 32 54 0b 01 46 88 51 01 81 e6 ff 00 00 00 8b 54 b0 08 03 fa 81 e7 ff 00 00 00 8b 5c b8 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Alureon_B_143886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.B"
        threat_id = "143886"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 81 38 4d 5a 0f 84 ?? ?? ?? ?? 8d 44 20 ff 85 c0 81 c0 ff ff ff ff 0f 85 ?? ?? ?? ?? 6b c9 ea 81 e1 00 00 00 00 83 c9 04 03 e1 f7 d9 8b 0c 0c}  //weight: 10, accuracy: Low
        $x_5_2 = "RtlImageNtHeader" ascii //weight: 5
        $x_5_3 = "ExAllocatePool" ascii //weight: 5
        $x_1_4 = "dlfcccnzz.dll" ascii //weight: 1
        $x_1_5 = "OfdrvBri" ascii //weight: 1
        $x_1_6 = "ZuLhhauqMbrqtliGpj" ascii //weight: 1
        $x_1_7 = "HlDwsxspJxpwzGvj" ascii //weight: 1
        $x_1_8 = "OwiQuvfzcIoluaNoplKt" ascii //weight: 1
        $x_1_9 = "DxhJznqKxuytxWzckjbYn" ascii //weight: 1
        $x_1_10 = "HtkVqtkwlsTtvznvp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Alureon_F_144379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.F"
        threat_id = "144379"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 1c 24 87 4c 24 04 87 54 24 08 87 6c 24 0c 56 57 55 52 51 53 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 81 06 02 00 00 81 e9 ?? fe ff ff 81}  //weight: 1, accuracy: Low
        $x_1_3 = {25 00 f0 ff ff 66 81 38 4d 5a 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 a2 b3 45 5e ff 75 ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {68 61 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_G_144687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.G"
        threat_id = "144687"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 54 44 4c 44}  //weight: 1, accuracy: High
        $x_1_2 = {3d 54 44 4c 44 75 ?? a1 08 03 df ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 71 78 ff b1 b4 00 00 00 e8 ?? ?? ?? ?? 6a 54}  //weight: 1, accuracy: Low
        $x_1_4 = {57 01 00 c0 68 bb 64 0b 73}  //weight: 1, accuracy: High
        $x_1_5 = {8a d1 02 54 24 0c 30 14 01 41 3b 4c 24 08 72 f0}  //weight: 1, accuracy: High
        $x_1_6 = {68 96 f7 de b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Alureon_H_145930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.H"
        threat_id = "145930"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hTDLD" ascii //weight: 1
        $x_1_2 = {68 96 f7 de b5}  //weight: 1, accuracy: High
        $x_1_3 = {57 01 00 c0 8b ?? ?? 68 1b 50 8a fd}  //weight: 1, accuracy: Low
        $x_1_4 = {54 44 4c 4e a1 08 03 df ff 02 00 c7}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 54 24 0c 8b 44 24 04 03 c1 30 10 fe c2 41 3b 4c 24 08 72 ef}  //weight: 1, accuracy: High
        $x_1_6 = {39 16 74 14 8b 03 0b 43 04 75 2d 8b fe 32 c0 b9 00 04 00 00 f3 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Alureon_I_146894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.I"
        threat_id = "146894"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c [0-16] 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "?keyword=%s&uid=%s&seid=%d" ascii //weight: 1
        $x_1_4 = "*firefox*" ascii //weight: 1
        $x_1_5 = "\\filesystem\\fltmgr" wide //weight: 1
        $x_1_6 = "\\driver\\tcpip" wide //weight: 1
        $x_1_7 = "\\filesystem\\fastfat" wide //weight: 1
        $x_1_8 = "\\filesystem\\ntfs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_WinNT_Alureon_A_147611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.gen!A"
        threat_id = "147611"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 06 2b c2 33 c7 89 06 03 bb ?? ?? ?? ?? 03 93 ?? ?? ?? ?? 87 fa 83 c6 04 83 e9 04 75 e2}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 9e f8 00 00 00 0f b7 56 06 8b 73 14 8b 7b 0c}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e9 02 6a 00 e2 fc 83 c4 ?? ff e0}  //weight: 1, accuracy: Low
        $x_1_4 = {60 50 0f 01 4c 24 fe 5e 8b 5e 04 66 8b 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Alureon_B_149799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.gen!B"
        threat_id = "149799"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 50 89 47 10 8b 76 28 03 f3 57 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {68 1f 00 0f 00 8d 45 ?? 50 b8 ?? ?? ?? ?? ff d0 6a 01 6a 01}  //weight: 1, accuracy: Low
        $x_1_3 = {50 68 00 00 00 80 8d 45 ?? 50 b8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Alureon_L_153304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.L"
        threat_id = "153304"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 43 46 00 00 66 3b c8 74 ?? b8 43 44 00 00 66 3b c8 75}  //weight: 1, accuracy: Low
        $x_1_2 = {a1 14 00 df ff 68 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 43 0c 56 57 8b f8 8b 45 0c be ?? ?? ?? ?? b9 00 02 00 00 f3 a4 5f 5e 8b 0b 85 c9 74 ?? ff 73 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Alureon_P_155696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.P"
        threat_id = "155696"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 d8 08 c0 0f 85 ?? ?? 00 80 6a 00 ff 15 ?? ?? 01 00 68 ?? ?? 00 00 6a 00 ff 15 ?? ?? 01 00 a3 ?? ?? 01 00 89 c7 be ?? ?? 01 00 bb ?? ?? 00 00 a5 31 5f fc 81 c3 ?? ?? 00 00 81 fe ?? ?? 01 00 0f 85 ea ff ff ff ff 15 ?? ?? 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_S_158264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.S"
        threat_id = "158264"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 47 24 23 c3 0d 20 00 00 a8 89 47 24 8b 7d 0c 83 66 58 00}  //weight: 1, accuracy: High
        $x_1_2 = "[injects_end]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_X_164622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.X"
        threat_id = "164622"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 d2 b9 5e 68 5e 81 c2 00 09 24 31}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1c 01 88 18 8b ff 40 4a 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 0f b7 00 8b d0 81 e2 00 f0 00 00 bb 00 30 00 00 66 3b d3 75 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_Z_165679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.Z"
        threat_id = "165679"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 3b 50 ff d3 8b f0 83 c4 08 85 f6 74 03 c6 06 00}  //weight: 1, accuracy: High
        $x_1_2 = {a1 14 00 df ff c1 e1 09 68}  //weight: 1, accuracy: High
        $x_1_3 = {ba 53 46 00 00 66 3b c2 74 ?? ba 53 44 00 00 66 3b c2 75}  //weight: 1, accuracy: Low
        $x_1_4 = {75 0e 8b f8 be ?? ?? ?? ?? b9 00 02 00 00 f3 a4 5f 5e 8b 03 85 c0 74 ?? 8b 4b 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Alureon_AA_167854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.AA"
        threat_id = "167854"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 42 4b 46 53 53 c1 e0 09 50 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {89 48 08 89 48 58 89 48 34 e8}  //weight: 1, accuracy: High
        $x_1_3 = "[injects_end]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Alureon_AA_167854_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.AA"
        threat_id = "167854"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f4 50 6a 00 6a 01 53 ff 15 ?? ?? ?? ?? 85 c0 74 5c 8b 50 20 8b 70 1c 8b 78 24 8b 40 18}  //weight: 1, accuracy: Low
        $x_1_2 = "systemstartoptions" wide //weight: 1
        $x_1_3 = "%s\\ph.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_AB_172757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.AB"
        threat_id = "172757"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\??\\physicaldrive%d" wide //weight: 1
        $x_1_2 = "\\systemroot\\system32\\kdcom.dll" wide //weight: 1
        $x_1_3 = {3b 46 18 0f 82 ?? ?? ff ff 83 45 ?? 04 ff 4d ?? 0f 85 ?? ?? ff ff ff 4d ?? 0f 85 fb fe ff ff 8b 45 ?? 8b 55 08 8b 4d ?? 89 50 18 8b 71 58 89 70 40 8b 71 28 03 f2 5f 89 70 1c 8b 49 08 5e 89 48 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_FO_174008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.FO"
        threat_id = "174008"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ae 4e 00 00 66 03 01 b9 56 a1 00 00 66 33 c1 8b 4d f4 03 4d 10 0f b7 c0 66 89 01 8b 45 f8 8b 4d 0c}  //weight: 1, accuracy: High
        $x_1_2 = {04 2d 34 e3 88 01 41 42 8a 02 3c b6 75}  //weight: 1, accuracy: High
        $x_1_3 = {c7 06 84 6a 62 73 c7 46 04 5f 61 66 64 c7 46 08 59 63 63 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Alureon_DB_196399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Alureon.DB"
        threat_id = "196399"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 70 3c 03 f0 8b 46 50 89 45 ?? 6a 40 68 00 30 00 00 8d 45 ?? 50 53 8d 45 ?? 50 ff 75 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0a 03 ce 33 ff eb 0e 0f bf 19 69 ff ?? ?? ?? ?? 03 fb 41 33 db 38 19 75 ee 39 7d 0c 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

