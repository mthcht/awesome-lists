rule Backdoor_Win32_Simda_A_2147645702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.A"
        threat_id = "2147645702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 85 d2 7c 07 42 30 08 40 4a 75 fa c3}  //weight: 1, accuracy: High
        $x_1_2 = {4b 85 db 75 ?? bb ?? ?? 00 00 b8 ?? ?? ?? ?? 8b cb ba ?? ?? 00 00 e8 ?? ?? ?? ?? 4b 85 db 75 ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Simda_A_2147645702_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.A"
        threat_id = "2147645702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 85 d2 7c 07 42 30 08 40 4a 75 fa c3}  //weight: 1, accuracy: High
        $x_1_2 = {5a 38 d9 75 10 38 fd 75 0c c1 e9 10 c1 eb 10 38 d9 75 02 38 fd 5f 5e 5b}  //weight: 1, accuracy: High
        $x_1_3 = {ff 4a f8 e8 ?? ?? ?? ?? 5a 5f 5e 5b 58 8d 24 94 ff e0 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {85 c0 7e 24 50 83 c0 0a 83 e0 fe 50 e8 ?? ?? ?? ?? 5a 66 c7 44 02 fe 00 00 83 c0 08 5a 89 50 fc c7 40 f8 01 00 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_5 = "JLgG00C000040000//y00BW000000000G000000000000000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Simda_A_2147645703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.gen!A"
        threat_id = "2147645703"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HighestAvailable" wide //weight: 1
        $x_1_2 = "/RunLevel" wide //weight: 1
        $x_1_3 = "Actions Context=\"LocalSystem" wide //weight: 1
        $x_1_4 = "wv=%s&uid=%d&lng=%s&mid=%s&res=%s&v=%08X" ascii //weight: 1
        $x_1_5 = "controller=hash&mid=" ascii //weight: 1
        $x_1_6 = "$%s&controller=sign&data=%s&mid=%s$" ascii //weight: 1
        $x_1_7 = "v=spf1 a mx ip4:%d.%d.%d.%d/%d ?all" ascii //weight: 1
        $x_1_8 = {8b 75 08 74 15 32 06 0f b6 d0 c1 e8 08}  //weight: 1, accuracy: High
        $x_2_9 = {8b 45 f8 6a 01 ff 30 6a 00 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 2, accuracy: Low
        $x_2_10 = {83 78 0c 02 50 74 0b}  //weight: 2, accuracy: High
        $x_2_11 = {50 6a ff 68 e8 03 00 00 ff 75 fc 6a 01 6a 00 ff 15}  //weight: 2, accuracy: High
        $x_2_12 = {3d ea 00 00 00}  //weight: 2, accuracy: High
        $x_4_13 = {89 04 8a c7 45 f4 74 30 30 77 b8 ff ff ff ff}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Simda_B_2147650321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.gen!B"
        threat_id = "2147650321"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<RunLevel>HighestAvailable</RunLevel>" wide //weight: 1
        $x_1_2 = "<Actions Context=\"LocalSystem\">" wide //weight: 1
        $x_1_3 = {8b 1e 81 fb 41 50 33 32 75 53 8b 5e 04 83 fb 18}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 54 30 ff 8b cf c1 e9 18 33 54 8c 28 c1 e7 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Simda_B_2147650321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.gen!B"
        threat_id = "2147650321"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 1f 85 eb 51 f7 e1 8b c2 c1 e8 03 b2 19 f6 ea 8a d1 2a d0 80 c2 61 88 96 ?? ?? ?? ?? 46 3b 75 08 0f 31}  //weight: 1, accuracy: Low
        $x_1_2 = {32 06 0f b6 d0 c1 e8 08 8b 14 95 ?? ?? ?? ?? 46 33 c2 49 75 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {74 1a ba ff df 00 00 66 21 50 16}  //weight: 1, accuracy: High
        $x_1_4 = "task%d" wide //weight: 1
        $x_1_5 = {58 2d d5 11 00 10 c3 05 00 e8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {80 3b 2e 89 45 0c 74 0a 40 80 3c 18 2e 75 f9}  //weight: 1, accuracy: High
        $x_1_7 = {68 4a 86 ff 61 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 40 68 00 30 00 00 57 6a 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Simda_C_2147650507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.gen!C"
        threat_id = "2147650507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d%evirDlacisyhP\\.\\\\" ascii //weight: 1
        $x_1_2 = "hsah=rellortnoc?/" ascii //weight: 1
        $x_1_3 = "=rellortnoc&s%=ltt&d%=diu&etadpu=epyTputes&" ascii //weight: 1
        $x_1_4 = {8b 75 08 74 15 32 06 0f b6 d0 c1 e8 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Simda_D_2147651172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.gen!D"
        threat_id = "2147651172"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "iexplore.exe|opera.exe|java.exe" ascii //weight: 5
        $x_5_2 = {5c 48 69 73 74 6f 72 79 2e 49 45 35 5c 69 6e 64 65 78 2e 64 61 74 [0-21] 5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c 74 79 70 65 64 5f 68 69 73 74 6f 72 79 2e 78 6d 6c}  //weight: 5, accuracy: Low
        $x_2_3 = {65 00 73 00 65 00 74 00 2e 00 63 00 6f 00 6d 00 [0-16] 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 [0-26] 76 00 69 00 72 00 61 00 [0-16] 76 00 69 00 72 00 75 00 73 00 74 00 6f 00 74 00 61 00 6c 00 [0-16] 76 00 69 00 72 00 75 00 73 00 69 00 6e 00 66 00 6f 00}  //weight: 2, accuracy: Low
        $x_2_4 = {65 73 65 74 2e 63 6f 6d [0-16] 61 6e 74 69 76 69 72 [0-26] 76 69 72 61 [0-16] 76 69 72 75 73 74 6f 74 61 6c [0-16] 76 69 72 75 73 69 6e 66 6f}  //weight: 2, accuracy: Low
        $x_2_5 = {6e 00 61 00 6d 00 65 00 2e 00 6b 00 65 00 79 00 [0-37] 73 00 65 00 63 00 72 00 65 00 74 00 73 00 2e 00 6b 00 65 00 79 00 [0-37] 73 00 69 00 67 00 6e 00 2e 00 6b 00 65 00 79 00}  //weight: 2, accuracy: Low
        $x_2_6 = {6e 61 6d 65 2e 6b 65 79 [0-37] 73 65 63 72 65 74 73 2e 6b 65 79 [0-37] 73 69 67 6e 2e 6b 65 79}  //weight: 2, accuracy: Low
        $x_2_7 = "command=auth_loginByPassword&back_command=&back_custom1=&" ascii //weight: 2
        $x_2_8 = "CryptoPluginId=AGAVA&Sign" ascii //weight: 2
        $x_2_9 = {00 69 64 61 67 2e 65 78 65 [0-16] 6f 6c 6c 79 64 62 67 2e 65 78 65 [0-16] 64 75 6d 70 63 61 70 2e 65 78 65 [0-16] 77 69 72 65 73 68 61 72 6b 2e 65 78 65 [0-16] 43 3a 5c 69 44 45 46 45 4e 53 45 00}  //weight: 2, accuracy: Low
        $x_2_10 = {00 47 6c 6f 62 61 6c 5c 48 69 67 68 4d 65 6d 6f 72 79 45 76 65 6e 74 5f 25 30 38 78 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Simda_K_2147653326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.K"
        threat_id = "2147653326"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Path\\File[5].txt" wide //weight: 1
        $x_1_2 = {60 00 10 8d ?? ?? d8 ff ff 3b ?? 0f 85 ?? ?? 00 00 c7 85 ?? d8 ff ff 0a 00 8d ?? ?? d8 ff ff ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Simda_AK_2147657661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.AK"
        threat_id = "2147657661"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 58 8a c3 30 90 a4 ef bc c5 c3 56 a8 3f c5 63}  //weight: 1, accuracy: High
        $x_1_2 = {44 09 97 10 a0 ee cc 2e c6 06 c0 f9 48 25 1c 3c}  //weight: 1, accuracy: High
        $x_1_3 = {fb 6e d1 03 57 4d 17 7c b4 0a 1c 7e 81 f3 a0 a5}  //weight: 1, accuracy: High
        $x_1_4 = {d6 e5 46 36 5c 5a d1 03 06 e7 8d b2 0a 35 32}  //weight: 1, accuracy: High
        $x_1_5 = {69 44 de e3 ad c5 6d 19 9a 6c ee 50 b5 43}  //weight: 1, accuracy: High
        $x_1_6 = {93 da a9 87 96 48 8c 45 17 86 c1 09 fc 3a 10}  //weight: 1, accuracy: High
        $x_1_7 = {db 77 3f dc 11 4e 71 e7 f9 6b ac 2c f9 f4 16 71 13 80 10 60 25 2e 2c ea 09 ff a5 bb b0 93 0a 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Simda_AS_2147684909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.AS"
        threat_id = "2147684909"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {77 76 3d 25 73 26 75 69 64 3d 25 64 26 6c 6e 67 3d 25 73 26 6d 69 64 3d 25 73 26 72 65 73 3d 25 73 26 76 3d 25 30 38 58 26 72 7a 3d 25 64 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 3f 61 62 62 72 3d 52 54 4b 26 73 65 74 75 70 54 79 70 65 3d 75 70 64 61 74 65 26 75 69 64 3d 25 64 26 74 74 6c 3d 25 73 26 63 6f 6e 74 72 6f 6c 6c 65 72 3d 6d 69 63 72 6f 69 6e 73 74 61 6c 6c 65 72 26 70 69 64 3d 33 00}  //weight: 2, accuracy: High
        $x_2_3 = {63 6f 6e 74 72 6f 6c 6c 65 72 3d 68 61 73 68 26 6d 69 64 3d 00}  //weight: 2, accuracy: High
        $x_1_4 = {63 3a 5c 63 67 76 69 35 72 36 69 5c 76 67 64 67 66 64 2e 37 32 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 74 70 3a 2f 2f 66 69 6e 64 67 61 6c 61 2e 63 6f 6d 2f 3f 26 75 69 64 3d 25 64 26 71 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 00 5c 5c 2e 5c 49 44 45 32 31 32 30 31 2e 56 58 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Simda_AT_2147684959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.AT"
        threat_id = "2147684959"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 72 69 76 65 72 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 63 66 67 62 69 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 75 61 63 36 34 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Classes\\SUPERAntiSpywareContextMenuExt.SASCon.1" ascii //weight: 1
        $x_1_3 = "Windows\\CurrentVersion\\Uninstall\\ERUNT_is1" ascii //weight: 1
        $x_1_4 = {6b c0 28 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 40 89 45 f8 8b 45 f8 81 38 6e 6c 73 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Simda_A_2147688203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.gen!A!!Simda.gen!A"
        threat_id = "2147688203"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Simda: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6c 6f 62 c7 45 ?? 61 6c 5c 4d c7 45 ?? 69 63 72 6f c7 45 ?? 73 6f 66 74 c7 45 ?? 53 79 73 65 c7 45 ?? 6e 74 65 72 c7 45 ?? 47 61 74 65 66 c7 ?? f4 ?? 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "&command=bc_activate&status=" ascii //weight: 1
        $x_1_3 = "dabetreswe5puphEgawrede3reswusa" ascii //weight: 1
        $x_1_4 = {63 6f 6d 6d 61 6e 64 3d 69 6e 6a 65 63 74 26 64 61 74 61 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 6f 6d 6d 61 6e 64 3d 62 63 5f 61 63 74 69 76 61 74 65 26 69 70 3d 00 26 70 6f 72 74 3d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Simda_ASI_2147921099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.ASI!MTB"
        threat_id = "2147921099"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f4 0f b6 0c 31 88 4d ff 8a 88 00 01 00 00 0f b6 f9 0f b6 14 07 03 f8 88 55 0f 8a 90 01 01 00 00 02 55 0f 89 7d f0 0f b6 fa 8a 1c 07 03 f8 89 7d ec 8b 7d f0 88 1f 8b 7d ec 88 5d 0b 0f b6 5d 0f 88 1f 0f b6 5d 0f 0f b6 7d 0b 03 fb}  //weight: 2, accuracy: High
        $x_1_2 = "DAN NLD NLB ENU ENG ENA ENC ENZ ENI FIN FRA FRB FRC FRS DEU DES DEA ISL ITA ITS NOR NON PTB PTG SVE ESP ESM ESN TRK PLK CSY SKY HUN RUS GRE ALL" ascii //weight: 1
        $x_1_3 = "EAF799BF-8249-4fe1-9A0D-922D39D22014" ascii //weight: 1
        $x_1_4 = "EAF799BF-8449-4fe1-9A0D-95CD39DC2014" ascii //weight: 1
        $x_1_5 = "EAF799BF-8989-4fe1-9A0D-95CD39DC0214" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Simda_CCJE_2147922178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Simda.CCJE!MTB"
        threat_id = "2147922178"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iexplore.exe|opera.exe|java.exe|javaw.exe|explorer.exe|isclient.exe|intpro.exe" ascii //weight: 10
        $x_10_2 = "{BotVer:" ascii //weight: 10
        $x_5_3 = "{Username:" ascii //weight: 5
        $x_5_4 = "{Processor:" ascii //weight: 5
        $x_5_5 = "{Language:" ascii //weight: 5
        $x_5_6 = "{Screen:" ascii //weight: 5
        $x_5_7 = "kaspersky" ascii //weight: 5
        $x_5_8 = "eset.com" ascii //weight: 5
        $x_5_9 = "anti-malware" ascii //weight: 5
        $x_5_10 = "software\\microsoft\\windows nt\\currentversion\\winlogon" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

