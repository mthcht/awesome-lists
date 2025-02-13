rule Backdoor_Win32_Caphaw_A_2147649046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.A"
        threat_id = "2147649046"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 03 8d 73 08 85 f6 74 ?? 8a 0e 33 ff 32 c8 74 ?? 69 c0 4d 03 00 00 05 41 02 00 00 83 c9 ff 33 d2 f7 f1 47 8a 0c 37 8b c2 32 c8 75 e4}  //weight: 3, accuracy: Low
        $x_3_2 = {3d 78 56 34 12 74 04 0b c0 75 07 c7 45 ?? 01 00 00 00 e8 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 3, accuracy: Low
        $x_3_3 = {69 c0 4d 03 00 00 05 41 02 00 00 33 d2 83 cf ff f7 f7 46 8b c2 8a 14 0e 32 d0 75 e4}  //weight: 3, accuracy: High
        $x_2_4 = {43 50 48 57 20 6b 69 6c 6c 20 62 79 20 74 69 6d 65 6f 75 74 00}  //weight: 2, accuracy: High
        $x_2_5 = {2a 2a 2a 4c 6f 61 64 20 69 6e 6a 65 63 74 73 20 75 72 6c 3d 25 73 20 28 25 73 29 00}  //weight: 2, accuracy: High
        $x_2_6 = {2a 2a 2a 69 73 49 6e 6a 65 63 74 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {3d 00 00 50 00 0f 87 ?? ?? ?? ?? 85 d2 7c ?? 7f 07 3d 00 d0 07 00 76}  //weight: 2, accuracy: Low
        $x_1_8 = "AVCInjectsPack@@" ascii //weight: 1
        $x_1_9 = "AVFF_Hook@@" ascii //weight: 1
        $x_1_10 = "AVIE_Hook@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_C_2147655033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.C"
        threat_id = "2147655033"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 8a c2 32 45 08 83 7d 0c 01 88 01 75 04 84 c0 eb 08 83 7d 0c 00 75 04 84 d2 74 1b 8b 45 08 69 c0 4d 03 00 00 05 41 02 00 00 33 d2 83 ce ff f7 f6 41 89 55 08 eb c8}  //weight: 1, accuracy: High
        $x_1_2 = ".cc/ping.html" ascii //weight: 1
        $x_1_3 = "Botnet=" ascii //weight: 1
        $x_1_4 = "HJVer=1.3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_D_2147656484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.D"
        threat_id = "2147656484"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "botnet=%s" ascii //weight: 3
        $x_2_2 = "commands exec status=%s" ascii //weight: 2
        $x_1_3 = "%s%s%i.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_H_2147657836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.H"
        threat_id = "2147657836"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "&net=%s&cmd=log&w=cmpinfo&bt=%s&ver=" ascii //weight: 3
        $x_1_2 = {2f 70 69 6e 67 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "||Botnet=" ascii //weight: 1
        $x_1_4 = "||HJPath=" ascii //weight: 1
        $x_1_5 = "AVFF_Hook" ascii //weight: 1
        $x_1_6 = "AVIE_Hook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_N_2147678775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.N"
        threat_id = "2147678775"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 e8 03 00 00 6a 02 53 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ff ff 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 29 8b 35 ?? ?? ?? ?? eb 14}  //weight: 1, accuracy: Low
        $x_1_2 = "mspreadmutex" ascii //weight: 1
        $x_1_3 = "/hijackcfg/urls_server/url_server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Caphaw_P_2147682581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.P"
        threat_id = "2147682581"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/hijackcfg/plugins/plugin" ascii //weight: 1
        $x_1_2 = "/hijackcfg/timer_cfg" ascii //weight: 1
        $x_2_3 = {00 42 6f 74 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_4 = "<B>00000000000000000000000000<br/>OK</B></BODY></HTML>" ascii //weight: 2
        $x_2_5 = {8b 14 c6 89 94 8d ?? ?? ?? ?? ff 85 ?? ?? ?? ?? 33 c9 66 89 4c c6 06 8b 04 c6 3b 45 fc 76 03 89 45 fc 47 3b 7d 0c 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_R_2147682725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.R"
        threat_id = "2147682725"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&cmd=ping&net=" ascii //weight: 1
        $x_1_2 = "&cmd=log&w=err&net=" ascii //weight: 1
        $x_1_3 = {72 6f 6f 74 6b 69 74 [0-5] 23 54 45 58 54 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_S_2147682974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.S"
        threat_id = "2147682974"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 e6 f3 48 76 f2 54 19 e8 0a 05 ca 61 76 81 5c 3a b5 f6 0c b0 3a 80 fc 4e 72 94 f6 89 f6 bb 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_U_2147683122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.U"
        threat_id = "2147683122"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a9 00 00 f0 00 74 44 81 7d d4 47 65 6e 75 75 3b 81 7d d8 69 6e 65 49 75 32 81 7d dc 6e 74 65 6c 75 29 8b 45 e0 25 00 00 00 10 8b 4d f0 64 89 0d 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 50 6a 40 50 53 ff d7 64 a1 10 00 00 00 8b 4e 50 6a 40 68 00 10 00 00 51 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_U_2147683122_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.U"
        threat_id = "2147683122"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {99 81 e2 ff 1f 00 00 55 03 c2 8b e8 c1 fd 0d 85 ed}  //weight: 4, accuracy: High
        $x_4_2 = {0f b6 d6 33 dd 0f b6 69 0e 0f b6 49 0f c1 e3 08 33 dd 8b 68 0c c1 e3 08 33 d9}  //weight: 4, accuracy: High
        $x_2_3 = {4b 65 79 00 53 65 74 00 [0-16] 45 72 72 6f 72 20 25 69 00}  //weight: 2, accuracy: Low
        $x_1_4 = {51 2b d3 50 03 d0 ff d2}  //weight: 1, accuracy: High
        $x_1_5 = {52 2b c3 55 03 c5 ff d0}  //weight: 1, accuracy: High
        $x_1_6 = {2b d3 0f af c2 03 c6 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_W_2147683932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.W"
        threat_id = "2147683932"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d6 a8 02 ?? ?? 6a 00 ff 15 ?? ?? ?? ?? ff d6 a8 02 74 f2}  //weight: 2, accuracy: Low
        $x_1_2 = {89 45 fc 8b c8 8b 45 ?? 8b d1 c1 e9 02 8b f0 8b fb f3 a5 83 c4 10 6a 00 6a 00 8b ca 83 e1 03 6a 00 f3 a4 6a 00 89 45 e4 ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 ec 50 6a 00 8d 4d e0 51 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75 13 8b 55 fc 8b 75 ?? 52 56 56 e8 ?? ?? ff ff 83 c4 0c eb ?? 68 e8 03 00 00 56 ff d7 3d 02 01 00 00 74 ?? 6a 02 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_X_2147683978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.X"
        threat_id = "2147683978"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 8d 45 e0 50 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b f8 85 ff 74 ?? 68 e8 03 00 00 57 ff 15 ?? ?? ?? 00 3d 02 01 00 00 74 ?? 68 e8 03 00 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 55 8b 6c 24 18 56 8b 74 24 10 57 8b 7c 24 1c 8d 64 24 00 8b ca 83 e1 1f bb 01 00 00 00 d3 e3 85 dd 74 09 8a 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_X_2147683978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.X"
        threat_id = "2147683978"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 04 85 c9 89 44 24 08 db 44 24 08 d9 fa db 44 24 04 7d 06 dc 05 ?? ?? ?? ?? de c1 e8 ?? ?? 00 00 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 00 00 ?? 01 72 c4}  //weight: 2, accuracy: Low
        $x_1_2 = {85 c0 75 13 8b 45 ?? 8b 48 3c 03 c8 51 50 53 e8 ?? ?? ff ff 83 c4 0c 1c 00 8b 46 3c 8b 4c ?? 54 8b d1 c1 e9 02 8b fb f3 a5 8b ca 83 e1 03 f3 a4 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 53 3c 8b ?? ?? 28 03 ?? 83 c4 04 89 ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_Y_2147684039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.Y"
        threat_id = "2147684039"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {89 04 24 89 44 24 0c 8b 44 24 0c ba ?? ?? ?? ?? 3b c2 89 0d ?? ?? ?? ?? 73 60 56 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b c1 c1 e8 10 25 ff 7f 00 00 89 44 24 08 89 0d ?? ?? ?? ?? db 44 24 08 d9 fa d9 5c 24 08 d9 44 24 08 db 1d}  //weight: 50, accuracy: Low
        $x_50_2 = {89 44 24 08 89 44 24 04 8b 44 24 04 83 c4 04 3d ?? ?? ?? ?? 73 2c e8 ?? ?? 00 00 89 44 24 08 db 44 24 08 d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41 89 0c 24}  //weight: 50, accuracy: Low
        $x_1_3 = {8b 4b 3c 8b 74 19 28 03 f3 83 c4 04 89 75 dc ff d6 8b 5d dc 93 90 cc}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4b 3c 8b 44 0b 28 03 c3 83 c4 04 89 45 d8 ff d0 8b 5d d8 93 90 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_Z_2147684064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.Z"
        threat_id = "2147684064"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 44 24 08 89 44 24 04 8b 44 24 04 83 c4 04 3d 00 00 ?? 01 73 2c e8 ?? ?? 00 00 89 44 24 08 db 44 24 08 d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 47 3c 8b 74 38 28 03 f7 83 c4 04 89 75 d8 ff d6 8b 5d d8 93 90 cc}  //weight: 1, accuracy: High
        $x_1_3 = {8b 43 3c 8b 4c 18 28 83 c4 04 03 cb ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AA_2147684110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AA"
        threat_id = "2147684110"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {89 44 24 08 89 44 24 04 8b 44 24 04 83 c4 04 3d ?? ?? ?? ?? 73 2c e8 ?? ?? 00 00 89 44 24 08 db 44 24 08 d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41}  //weight: 100, accuracy: Low
        $x_100_2 = {89 7c 24 0c db 44 24 0c d9 fa e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_3 = {89 4c 24 0c db 44 24 0c (d9 fa|d9 fe) e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 54 24 04 42 89 54 24 04 81 7c 24 04 ?? ?? ?? ?? 72 c6}  //weight: 100, accuracy: Low
        $x_1_4 = {8b 53 3c 8b ?? ?? 28 83 c4 ?? 03 c3 ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 53 3c 8b 74 1a 28 03 f3 83 c4 ?? 89 75 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 43 3c 8b 74 ?? 28 03 f3 83 c4 ?? 89 75 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4b 3c 8b 74 19 28 03 f3 83 c4 ?? 89 75 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 4b 3c 8b 54 0b 28 83 c4 ?? 03 d3 ff d2}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 43 3c 8b 4c 03 28 83 c4 ?? 03 cb ff d1}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 53 3c 8b ?? ?? 28 83 c4 ?? 03 f3 ff d6}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 53 3c 8b ?? ?? 28 03 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_12 = {8b 53 3c 8b ?? ?? 28 03 ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 45 3c 8b ?? ?? 28 03 ?? ff d1}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 55 3c 8b ?? ?? 28 03 ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 4b 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 43 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_17 = {8b 43 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 53 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AC_2147684760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AC"
        threat_id = "2147684760"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {db 44 24 0c d9 (fa|fe) [0-47] 03 44 24 08 89 44 24 08 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_2 = {db 44 24 08 d9 03 01 01 01 fa fe ff e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_3 = {db 44 24 08 dc ?? ?? ?? ?? ?? d9 (fa|fe) e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41 89 0c 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_4 = {db 44 24 0c dc 7c 24 10 d9 ?? e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_5 = {db 44 24 0c d9 ed d9 c9 d9 f1 dc 44 24 10 e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_6 = {db 44 24 0c d9 ?? dc 44 24 10 e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? (72|0f 82)}  //weight: 100, accuracy: Low
        $x_100_7 = {db 44 24 0c d9 ?? dc 44 24 10 e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 0f 82 ?? ff ff ff}  //weight: 100, accuracy: Low
        $x_100_8 = {db 44 24 08 d9 fe d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_9 = {db 44 24 08 d9 ?? dc ?? ?? ?? ?? ?? d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 ?? ?? ?? ?? (72|0f)}  //weight: 100, accuracy: Low
        $x_100_10 = {db 44 24 08 dc ?? ?? ?? ?? ?? d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_11 = {db 44 24 0c dc ?? ?? ?? ?? ?? d9 ?? e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_12 = {db 44 24 08 d9 ?? e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_13 = {db 44 24 08 d9 fa d9 fe e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41 89 0c 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_14 = {db 44 24 0c d9 (fa|fe) dc 05 ?? ?? ?? ?? dc 7c 24 10 e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 54 24 04 42 89 54 24 04 81 7c 24 04 ?? ?? ?? ?? 0f 82}  //weight: 100, accuracy: Low
        $x_100_15 = {db 44 24 08 d9 c0 d9 (fa|fe) [0-47] 03 44 24 04 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_1_16 = {8b 43 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_17 = {8b 45 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 47 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 4b 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_20 = {8b 53 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 55 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 4d 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AD_2147684839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AD"
        threat_id = "2147684839"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 81 c4 cc 00 00 00 50 81 ec c8 00 00 00 83 c4 6c 61 83 c4 3c 58 5d ff e0 ff e1}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 10 00 00 8b 45 f4 50 6a 00 8b 4d 10 ff 51 10 89 45 e0 b8 00 00 00 00 b8 00 00 00 00 83 7d e0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_AE_2147685260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AE"
        threat_id = "2147685260"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/hijackcfg/urls_server/url_server" ascii //weight: 1
        $x_1_2 = {53 68 e8 03 00 00 6a 02 53 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ff ff 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 29 8b 35 ?? ?? ?? ?? eb 14}  //weight: 1, accuracy: Low
        $x_1_3 = "action=setStatus&bid=%s&skype_exists=%s&" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Caphaw_AF_2147685472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AF"
        threat_id = "2147685472"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {99 f7 ff 8b fa e8 [0-31] dd 05 ?? ?? ?? ?? e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_1_2 = {8b 43 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 47 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 4b 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 53 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 55 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 4d 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 46 3c 8b ?? ?? 28 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AG_2147685549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AG"
        threat_id = "2147685549"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {99 f7 ff 8b fa e8 [0-31] dd 05 ?? ?? ?? ?? e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_2 = {db 44 24 0c d9 (fa|fe) [0-47] 03 44 24 08 89 44 24 08 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? (72|0f 82)}  //weight: 100, accuracy: Low
        $x_100_3 = {db 44 24 08 d9 03 01 01 01 fa fe ff [0-79] 89 ?? 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_4 = {db 44 24 0c d9 (fa|fe) [0-63] 89 ?? 24 08 8b ?? 24 04 (40|41) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? (72|0f 82)}  //weight: 100, accuracy: Low
        $x_100_5 = {db 44 24 14 d9 (fa|fe) [0-47] (8b 44 24 10|03 44) 89 44 24 10 8b ?? 24 0c (41|42) 89 ?? 24 0c 81 7c 24 0c ?? ?? ?? ?? (72|0f 82)}  //weight: 100, accuracy: Low
        $x_100_6 = {db 44 24 08 d9 ff [0-63] 8b 54 24 04 03 d0 89 54 24 04 8b 04 24 40 89 04 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_7 = {db 44 24 08 d9 03 01 01 01 fa fe ff [0-63] 89 54 24 08 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_8 = {8b 4c 24 04 dc 3d ?? ?? ?? ?? 85 c9 db 44 24 04 7d 06 dc 05 ?? ?? ?? ?? de c1 e8 ?? ?? 00 00 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_1_9 = {8b c3 2b c5 50 83 ec 08 dd 1c 24 e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ?? 03 c3 50 e8 [0-15] 8b 8c 24 ?? ?? 00 00 8b 54 24 ?? 51 52 68 ?? ?? ?? ?? 53 ff d6}  //weight: 1, accuracy: Low
        $x_1_10 = {8b cb 2b cd 51 83 ec 08 dd 1c 24 e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ?? 03 c3 50 e8 ?? ?? ?? ?? 83 c4 08 8b 94 24 ?? ?? 00 00 8b 44 24 ?? 52 50 68 ?? ?? ?? ?? 53 ff d6}  //weight: 1, accuracy: Low
        $x_1_11 = {8b c5 2b c3 50 83 ec 08 dd 1c 24 e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ?? 03 c5 50 e8 ?? ?? ?? ?? 83 c4 08 8b 8c 24 ?? ?? 00 00 8b 54 24 ?? 51 52 68 ?? ?? ?? ?? 55 ff d6}  //weight: 1, accuracy: Low
        $x_1_12 = {03 c5 50 e8 ?? ?? ff ff 8b ?? 24 ?? ?? 00 00 8b ?? 24 ?? (51|52) (50|52) (b8|b9) ?? ?? ?? ?? 2b (c3|cb) 68 ?? ?? ?? ?? 55 03 (c5|cd) ff (d0|d1)}  //weight: 1, accuracy: Low
        $x_1_13 = {03 c5 50 e8 ?? ?? ff ff 83 c4 08 8b 94 24 ?? ?? 00 00 8b 44 24 ?? 52 50 68 ?? ?? ?? ?? 55 ff d6}  //weight: 1, accuracy: Low
        $x_1_14 = {8b cb 2b cd 51 53 e8 ?? ?? ff ff 83 c4 08 8b 94 24 ?? ?? 00 00 8b 44 24 ?? 52 50 b9 ?? ?? ?? ?? 2b cd 68 ?? ?? ?? ?? 53 03 cb ff d1}  //weight: 1, accuracy: Low
        $x_1_15 = {8b c3 2b c5 50 53 e8 ?? ?? ff ff 83 c4 08 8b 8c 24 ?? ?? 00 00 8b 54 24 ?? 51 52 b8 ?? ?? ?? ?? 2b c5 68 ?? ?? ?? ?? 53 03 c3 ff d0}  //weight: 1, accuracy: Low
        $x_1_16 = {99 f7 fd 66 8b 0e 83 c6 02 66 2b ca 4b 66 89 4c 37 fe 75}  //weight: 1, accuracy: High
        $x_1_17 = {8b 43 3c 8b 4c 18 54 8b d1}  //weight: 1, accuracy: High
        $x_1_18 = {8b 46 3c 8b 4c ?? 54 8b d1}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 4e 3c 8b 4c ?? 54 8b d1}  //weight: 1, accuracy: Low
        $x_1_20 = {8b 4b 3c 8b 4c ?? 54 [0-5] 8b d1}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 53 3c 8b 4c ?? 54 8b c1}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 55 3c 8b 4c 2a 54 8b c1}  //weight: 1, accuracy: High
        $x_1_23 = {8b 4d 3c 8b 4c 29 54 8b d1}  //weight: 1, accuracy: High
        $x_1_24 = {8b 56 3c 8b 4c 32 54 8b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AH_2147685614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AH"
        threat_id = "2147685614"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {db 04 24 85 c9 7d 06 dc 05 ?? ?? ?? ?? d9 (fe|ff) [0-111] 89 04 24 8b 44 24 0c 40 89 44 24 0c 81 7c 24 0c ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {db 44 24 1c 7d 06 dc 05 ?? ?? ?? ?? d9 ff [0-15] 8b 54 24 18 83 c7 02 2b e8 66 03 6f fe 46 3b f3 66 89 6c 3a fe 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {db 44 24 0c 85 ?? 7d 06 d8 05 ?? ?? ?? ?? 8b 44 24 0c 83 c0 02 99 [0-47] 8b 44 24 0c 40 89 44 24 0c 81 7c 24 0c ?? ?? ?? ?? (72|0f 82)}  //weight: 1, accuracy: Low
        $x_1_4 = {db 44 24 1c 8b e8 7d 06 dc 05 ?? ?? ?? ?? d9 fe dc 0d ?? ?? ?? ?? e8 [0-31] f7 d8 1b c0 40 2b e8 66 03 2f 46 66 89 2c 3a 83 c7 02 3b f3 72}  //weight: 1, accuracy: Low
        $x_1_5 = {db 44 24 1c 8b e8 7d 06 dc 05 ?? ?? ?? ?? d9 fe dc 0d ?? ?? ?? ?? e8 ?? ?? 00 00 99 b9 ?? ?? 00 00 f7 f9 03 ea e8 ?? ?? 00 00 66 8b 17 33 e8 8b 44 24 18 66 2b d5 66 89 14 38 46 83 c7 02 3b f3 72}  //weight: 1, accuracy: Low
        $x_1_6 = {db 44 24 04 d9 03 01 01 01 fa fe ff db ?? 24 [0-1] 7d 06 dc 05 [0-31] 8b ?? 24 0c 40 89 ?? 24 0c 81 7c 24 0c ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_7 = {db 44 24 04 d9 (fa|ff) dc 0d [0-47] 8b 54 24 0c 42 89 54 24 0c 81 7c 24 0c ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 44 24 0c 33 d2 be 09 03 00 00 f7 f6 85 d2 74 20 8b 44 24 0c 99 33 c2 2b c2 8d 14 85 10 00 00 00 8b 44 24 0c 33 d0 8b 44 24 04 33 d0 89 54 24 04 8b 54 24 0c 42 89 54 24 0c 39 4c 24 0c 72 c0}  //weight: 1, accuracy: High
        $x_1_9 = {db 44 24 04 d8 0d ?? ?? ?? ?? d9 ff [0-31] db 44 24 0c 85 c0 7d 06 d8 05 [0-63] 8b 4c 24 0c 41 89 4c 24 0c 81 7c 24 0c ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_10 = {db 44 24 04 7d 06 d8 05 ?? ?? ?? ?? d8 0d ?? ?? ?? ?? d9 fe [0-63] 8b 4c 24 0c 41 89 4c 24 0c 81 7c 24 0c ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_11 = {db 04 24 7d 06 dc 05 ?? ?? ?? ?? d9 fe e8 ?? ?? ?? ?? 89 04 24 8b 54 24 08 42 89 54 24 08 81 7c 24 08 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_12 = {db 44 24 04 7d 06 dc 05 [0-8] d9 (fe|ff) [0-47] 8b ?? 24 0c (40|42) 89 ?? 24 0c 81 7c 24 0c ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 14 24 de c9 85 d2 db 04 24 7d 06 dc 05 ?? ?? ?? ?? de c1 e8 ?? ?? ?? ?? 89 04 24 8b 44 24 0c 40 89 44 24 0c 81 7c 24 0c ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_14 = {db 44 24 04 d9 fa [0-47] 8b 54 24 0c 42 89 54 24 0c 81 7c 24 0c ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_15 = {db 44 24 04 7d 06 dc 05 [0-7] d9 (fa|fe) [0-63] 8b ?? 24 0c 03 01 01 01 40 41 42 89 ?? 24 0c 81 7c 24 0c ?? ?? ?? ?? (72|0f 82)}  //weight: 1, accuracy: Low
        $x_1_16 = {db 44 24 0c [0-2] 7d 06 dc 05 [0-8] d9 (fa|fe) [0-79] 8b ?? 24 0c 03 01 01 01 40 41 42 89 ?? 24 0c 81 7c 24 0c ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_17 = {db 04 24 7d 06 ?? ?? ?? ?? ?? ?? de c9 e8 ?? ?? 00 00 89 04 24 8b 54 24 0c 42 89 54 24 0c 81 7c 24 0c ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_18 = {db 44 24 10 [0-2] 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|fe) [0-47] 89 44 24 04 8b 44 24 10 40 89 44 24 10 81 7c 24 10 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_19 = {8d 49 00 8b 4c 24 08 03 0c 24 89 0c 24 8b 54 24 08 42 89 54 24 08 39 44 24 08 72 e7}  //weight: 1, accuracy: High
        $x_100_20 = {03 f1 9b 8b 03 85 c0 8d 1c 08 75 02 8b de}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AI_2147686406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AI"
        threat_id = "2147686406"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {db 44 24 08 7d 06 dc 05 ?? ?? ?? ?? d9 fe e8 ?? ?? 00 00 03 04 24 89 04 24 8b 54 24 04 42 89 54 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_2 = {db 44 24 08 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|ff) [0-79] 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? (0f 82|72)}  //weight: 100, accuracy: Low
        $x_100_3 = {8b 54 24 04 d9 fe 85 d2 db 44 24 04 7d 06 dc 05 [0-15] 89 44 24 04 8b 04 24 40 89 04 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_4 = {db 44 24 08 7d 06 dc 05 [0-8] d9 fe [0-47] 89 44 24 04 8b 04 24 40 89 04 24 81 3c 24 ?? ?? ?? ?? 0f 82}  //weight: 100, accuracy: Low
        $x_100_5 = {db 44 24 04 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|fe) [0-15] 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_6 = {db 44 24 08 d9 (fa|ff) [0-31] 89 54 24 08 8b 54 24 04 42 89 54 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_7 = {db 44 24 04 85 c9 8b f8 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|fe) [0-47] 8b 4c 24 08 dc 3d ?? ?? ?? ?? 85 c9 db 44 24 08 7d 06 dc 05 [0-31] 8b 54 24 04 42 89 54 24 04 81 7c 24 04 ?? ?? ?? ?? (72|0f 82)}  //weight: 100, accuracy: Low
        $x_100_8 = {db 44 24 04 85 [0-3] 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|fe) [0-79] 8b ?? 24 04 (41|42) 89 ?? 24 04 81 7c 24 04 ?? ?? ?? ?? 0f 82}  //weight: 100, accuracy: Low
        $x_100_9 = {db 04 24 85 c0 7d 06 d8 05 ?? ?? ?? ?? dc 0d ?? ?? ?? ?? 8b 4c 24 04 85 c9 dc 0d ?? ?? ?? ?? db 44 24 04 7d 06 dc 05 ?? ?? ?? ?? de c1 e8 ?? ?? ?? ?? 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_10 = {db 04 24 85 c0 7d 06 dc 05 ?? ?? ?? ?? d9 fe [0-47] 8b 14 24 42 89 14 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_11 = {db 44 24 04 [0-8] 85 d2 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|fe) [0-31] 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_12 = {db 44 24 08 [0-8] 85 c9 7d 06 dc 05 ?? ?? ?? ?? d9 (fa|ff) [0-79] 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_13 = {db 44 24 0c d9 ff dc 0d [0-47] 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? (72|0f 82)}  //weight: 100, accuracy: Low
        $x_100_14 = {db 44 24 14 d9 fa dc 05 ?? ?? ?? ?? dc 6c 24 08 [0-15] 8b 44 24 04 40 89 44 24 04 81 7c 24 04 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_15 = {db 44 24 08 d9 fe db 04 24 7d 06 dc 05 [0-79] 8b 04 24 40 89 04 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_16 = {db 44 24 1c 8b e8 7d 06 dc 05 ?? ?? ?? ?? d9 fe [0-47] 2b e8 66 89 2c 3a 46 83 c7 02 3b f3 72}  //weight: 100, accuracy: Low
        $x_100_17 = {db 44 24 08 d9 fa e8 ?? ?? ?? ?? 99 [0-15] 89 54 24 04 8b 04 24 40 89 04 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
        $x_100_18 = {db 44 24 18 d9 fa [0-47] 66 8b 0e 48 0b e8 6b ed 13 66 2b cd 66 89 0c 37 83 c6 02 4b 75}  //weight: 100, accuracy: Low
        $x_1_19 = {8b 43 3c 8b 4c 18 54 8b d1}  //weight: 1, accuracy: High
        $x_1_20 = {8b 46 3c 8b 4c ?? 54 8b d1}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 4e 3c 8b 4c ?? 54 8b d1}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 4b 3c 8b 4c ?? 54 [0-5] 8b d1}  //weight: 1, accuracy: Low
        $x_1_23 = {8b 53 3c 8b 4c ?? 54 8b c1}  //weight: 1, accuracy: Low
        $x_1_24 = {8b 55 3c 8b 4c 2a 54 8b c1}  //weight: 1, accuracy: High
        $x_1_25 = {8b 4d 3c 8b 4c 29 54 8b d1}  //weight: 1, accuracy: High
        $x_1_26 = {8b 45 3c 8b 4c 28 54 8b d1}  //weight: 1, accuracy: High
        $x_1_27 = {99 41 f7 f9 66 8b 06 83 c6 02 6b d2 13 66 2b c2 4b 66 89 44 37 fe 75 c6}  //weight: 1, accuracy: High
        $x_1_28 = {8b 56 3c 8b 4c ?? 54 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_A_2147686511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.A!!Caphaw"
        threat_id = "2147686511"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        info = "Caphaw: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 03 8d 73 08 85 f6 74 ?? 8a 0e 33 ff 32 c8 74 ?? 69 c0 4d 03 00 00 05 41 02 00 00 83 c9 ff 33 d2 f7 f1 47 8a 0c 37 8b c2 32 c8 75 e4}  //weight: 3, accuracy: Low
        $x_3_2 = {3d 78 56 34 12 74 04 0b c0 75 07 c7 45 ?? 01 00 00 00 e8 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 3, accuracy: Low
        $x_3_3 = {69 c0 4d 03 00 00 05 41 02 00 00 33 d2 83 cf ff f7 f7 46 8b c2 8a 14 0e 32 d0 75 e4}  //weight: 3, accuracy: High
        $x_2_4 = {43 50 48 57 20 6b 69 6c 6c 20 62 79 20 74 69 6d 65 6f 75 74 00}  //weight: 2, accuracy: High
        $x_2_5 = {2a 2a 2a 4c 6f 61 64 20 69 6e 6a 65 63 74 73 20 75 72 6c 3d 25 73 20 28 25 73 29 00}  //weight: 2, accuracy: High
        $x_2_6 = {2a 2a 2a 69 73 49 6e 6a 65 63 74 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {3d 00 00 50 00 0f 87 ?? ?? ?? ?? 85 d2 7c ?? 7f 07 3d 00 d0 07 00 76}  //weight: 2, accuracy: Low
        $x_1_8 = "AVCInjectsPack@@" ascii //weight: 1
        $x_1_9 = "AVFF_Hook@@" ascii //weight: 1
        $x_1_10 = "AVIE_Hook@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AK_2147687671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AK"
        threat_id = "2147687671"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 4d 5a 00 00 33 c0 66 39 0a 75 30 8b 4a 3c 03 ca 81 39 50 45 00 00 75 23 85 f6 74 05 8d 41 04 89 06 85 ff 74 05 8d 41 18 89 07 85 db 74 0a 0f b7 41 14 8d 44 08 18 89 03}  //weight: 2, accuracy: High
        $x_2_2 = {83 e8 08 a9 fe ff ff ff 76 39 8b 45 fc 0f b7 44 41 08 8b f8 81 e7 00 f0 00 00 bb 00 30 00 00 66 3b fb 75 0f 25 ff 0f 00 00 03 01 8b fa 2b 7e 1c 01 3c 10 8b 41 04}  //weight: 2, accuracy: High
        $x_2_3 = {8b 7e 04 8d 4f 01 3b c1 72 16 8b 06 8b 55 08 8d 3c b8 33 c0 ab 8b 46 04 8b 0e 89 14 81 ff 46 04}  //weight: 2, accuracy: High
        $x_1_4 = "AVCInjPack@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AL_2147687833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AL"
        threat_id = "2147687833"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 04 8b 41 3c 0f b7 54 08 14 03 c1 0f b7 48 06 53 03 d0 56 8d 34 89 8d 44 f2 f0 33 d2 85 c9 76}  //weight: 2, accuracy: High
        $x_2_2 = {8d 0c 89 8d 44 ca f0 c7 04 24 00 00 00 00 89 04 24 8b 04 24 59 c3}  //weight: 2, accuracy: High
        $x_2_3 = {83 c0 f8 d1 e8 85 c0 8d 72 08 76}  //weight: 2, accuracy: High
        $x_2_4 = {8b 42 38 8b 0e 8d 54 01 ff 48 f7 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Caphaw_AK_2147687835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AK!!Caphaw"
        threat_id = "2147687835"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        info = "Caphaw: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 4d 5a 00 00 33 c0 66 39 0a 75 30 8b 4a 3c 03 ca 81 39 50 45 00 00 75 23 85 f6 74 05 8d 41 04 89 06 85 ff 74 05 8d 41 18 89 07 85 db 74 0a 0f b7 41 14 8d 44 08 18 89 03}  //weight: 2, accuracy: High
        $x_2_2 = {83 e8 08 a9 fe ff ff ff 76 39 8b 45 fc 0f b7 44 41 08 8b f8 81 e7 00 f0 00 00 bb 00 30 00 00 66 3b fb 75 0f 25 ff 0f 00 00 03 01 8b fa 2b 7e 1c 01 3c 10 8b 41 04}  //weight: 2, accuracy: High
        $x_2_3 = {8b 7e 04 8d 4f 01 3b c1 72 16 8b 06 8b 55 08 8d 3c b8 33 c0 ab 8b 46 04 8b 0e 89 14 81 ff 46 04}  //weight: 2, accuracy: High
        $x_1_4 = "AVCInjPack@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AM_2147687902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AM"
        threat_id = "2147687902"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/hijackcfg/plugins/plugin" ascii //weight: 2
        $x_2_2 = "/hijackcfg/urls_server/url_server" ascii //weight: 2
        $x_1_3 = "action=setStatus&bid=%s&skype_exists=%s&policy=%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AN_2147688126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AN"
        threat_id = "2147688126"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {db 44 24 08 dc 05 ?? ?? ?? ?? e8 ?? ?? 00 00 99 [0-31] 89 ?? 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_100_2 = {8b 46 3c 8b 4c ?? 54 8b d1}  //weight: 100, accuracy: Low
        $x_100_3 = {8b 4e 3c 8b 4c ?? 54 8b d1}  //weight: 100, accuracy: Low
        $x_100_4 = {8b 43 3c 8b 4c 18 54 8b d1}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Caphaw_AP_2147718389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Caphaw.AP"
        threat_id = "2147718389"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? ?? ?? 8b f0}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b6 71 0d 33 de 0f b6 71 0e 0f b6 49 0f c1 e3 08 33 de c1 e3 08 33 d9 33 dd 8b cb c1 e9 10 0f b6 c9 8b 0c 8d}  //weight: 3, accuracy: High
        $x_1_3 = {51 2b d3 50 03 d0 ff d2}  //weight: 1, accuracy: High
        $x_1_4 = {52 2b c3 55 03 c5 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

