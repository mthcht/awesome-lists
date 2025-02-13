rule Worm_Win32_Dorkbot_A_160375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.A"
        threat_id = "160375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 50 68 d0 37 10 f2 68 50 40 40 00 56 ff 51 20 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = "nAndr huttaP.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_A_160375_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.A"
        threat_id = "160375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 00 00 00 00 38 00 16 00 01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 44 00 6e 00 4b 00 41 00 73 00 65 00 65 00 59 00 4f 00 55 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_A_160375_2
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.A"
        threat_id = "160375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start %%cd%%RECYCLER\\%s" ascii //weight: 1
        $x_1_2 = "ngrBot" ascii //weight: 1
        $x_1_3 = {83 c4 0c 53 8d 45 f8 50 68 00 04 00 00 8d 8d ?? ?? ff ff 51 6a 0c 8d 55 ?? 52 68 00 14 2d 00 56 c7 85 ?? ?? ff ff 00 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_A_160375_3
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.A"
        threat_id = "160375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 20 46 40 00 e8 da 45 ff ff 85 c0 75 19 ff 35 50 00 41 00 68 b4 40 40 00 e8 ba 45 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "AD:\\Cambiador.vbp" wide //weight: 1
        $x_1_3 = "dD1B20A40-59D5-101B-A3C9-08002B2F49FB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_A_160375_4
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.A"
        threat_id = "160375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You've just been protected by Penjaga Firewall" wide //weight: 1
        $x_1_2 = {8b 85 dc fe ff ff 89 85 64 fb ff ff 83 a5 dc fe ff ff 00 68 58 7b 40 00 e8 d4 57 fd ff}  //weight: 1, accuracy: High
        $x_1_3 = "t9368265E-85FE-11d1-8BE3-0000F8754DA1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_A_160411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.gen!A"
        threat_id = "160411"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 5c 9c 14 30 1c 2a 42 3b d0 72 99 5f}  //weight: 2, accuracy: High
        $x_2_2 = {7e 2f 81 3a 2e 64 61 74 74 0e 46 83 c2 28 3b f1 7c f0}  //weight: 2, accuracy: High
        $x_2_3 = {99 b9 e8 03 00 00 f7 f9 81 c2 f4 01 00 00 0f af d6 52}  //weight: 2, accuracy: High
        $x_2_4 = {f7 f9 83 c2 41 66 89 16 8b 44 24 09 25 ff 00 00 00 99 f7 f9 83 c2 61 66 89 56 02}  //weight: 2, accuracy: High
        $x_2_5 = {8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 14 80 8d 84 24 ?? ?? 00 00 c1 e2 05 03 ca 50}  //weight: 2, accuracy: Low
        $x_2_6 = {bf 64 00 00 00 8b 16 8d 44 24 14 6a 10 50 6a 00 8d 8c 24 ?? ?? 00 00 68 64 19 00 00 51}  //weight: 2, accuracy: Low
        $x_1_7 = {66 66 67 72 61 62 00}  //weight: 1, accuracy: High
        $x_1_8 = {69 65 67 72 61 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_I_162906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 6f 64 75 6c 65 33 00 50 72 6f 79 65 63 74 6f 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 a0 fd ff ff 83 00 00 00 c7 85 98 fd ff ff 02 00 00 00 8d 95 98 fd ff ff 8b 45 d8 6a 23 59 2b 48 14 c1 e1 04 8b 45 d8 8b 40 0c 03 c8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_I_162906_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 4d 5a 00 00 74 05 e9 7c 01 00 00 8b 0d ?? ?? ?? ?? 8b 55 08 03 51 3c 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 81 38 50 45 00 00 74 05}  //weight: 1, accuracy: Low
        $x_1_2 = {74 13 8b 4d fc 03 4d f8 0f be 11 f7 d2 8b 45 fc 03 45 f8 88 10 eb 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_I_162906_2
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\programdata" ascii //weight: 1
        $x_1_2 = "%s\\Recycler" ascii //weight: 1
        $x_1_3 = "%s\\*.*" ascii //weight: 1
        $x_1_4 = "\\Update\\" ascii //weight: 1
        $x_1_5 = {6a 00 6a 02 8b f8 c7 44 24 20 28 01 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_I_162906_3
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#rndbot" ascii //weight: 1
        $x_1_2 = "#rndftp" ascii //weight: 1
        $x_1_3 = "ngr.hostname" ascii //weight: 1
        $x_1_4 = "[Slowloris]:" ascii //weight: 1
        $x_5_5 = {76 4e 80 3e 53 75 18 80 7e 01 44 75 12 80 7e 02 47 75 0c 68}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_I_162906_4
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 2e 70 32 31 2d 3e 20 4d 65 73 73 61 67 65 20 68 69 6a 61 63 6b 65 64 21 00 00 6d 73 6e 6d 73 67 00 00 6d 73 6e 69 6e 74 00 00 62 61 64 64 72 00 00 00 58 2d 4d 4d 53 2d 49 4d 2d 46 6f 72 6d 61 74 3a 00 00 00 00 43 41 4c 20 25 64 20 25 32 35 36 73 00 00 00 00 6d 73 6e 75 00 00 00 00 44 6f 6e 65 20 66 72 73 74 0a 00 00 6e 67 72 2d 3e 62 6c 6f 63 6b 73 69 7a 65 3a 20 25 64 0a 00 62 6c 6f 63 6b 5f 73 69 7a 65 3a 20 25 64 0a 00 4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_I_162906_5
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "*.gonewiththewings" ascii //weight: 2
        $x_1_2 = {2f 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 54 00 4e 00 20 00 22 00 [0-32] 22 00 20 00 2f 00 54 00 52 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 43 52 45 41 54 45 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 4e 20 22 [0-32] 22 20 2f 54 52 20 22 25 73 22 20 2f 52 4c 20 48 49 47 48 45 53 54}  //weight: 1, accuracy: Low
        $x_1_4 = "/c \"%%SystemRoot%%\\explorer.exe %%cd%%%s &" ascii //weight: 1
        $x_1_5 = "attrib -s -h %%cd%%%s & xcopy /F /S /Q /H /R /Y %%cd%%%s %%temp%%\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_I_162906_6
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I"
        threat_id = "162906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ngrBot" ascii //weight: 10
        $x_2_2 = "ngr->blocksize: %d" ascii //weight: 2
        $x_1_3 = "%s.Blocked \"%s\" from removing our bot file!" ascii //weight: 1
        $x_1_4 = "start %%cd%%RECYCLER\\%s" ascii //weight: 1
        $x_1_5 = "[v=\"%s\" c=\"%s\" h=\"%s\" p=\"%S\"]" ascii //weight: 1
        $x_5_6 = {5b 53 6c 6f 77 6c 6f 72 69 73 5d 3a 20 ?? ?? ?? ?? ?? ?? ?? ?? 20 66 6c 6f 6f 64 20 6f 6e 20 22 25 73 22}  //weight: 5, accuracy: Low
        $x_1_7 = "[UDP]: Starting flood on " ascii //weight: 1
        $x_1_8 = "[SYN]: Starting flood on " ascii //weight: 1
        $x_1_9 = "[USB]: Infected %s" ascii //weight: 1
        $x_1_10 = "[MSN]: Updated MSN spread" ascii //weight: 1
        $x_1_11 = "[HTTP]: Updated HTTP spread" ascii //weight: 1
        $x_1_12 = "[HTTP]: Injected value is now %s" ascii //weight: 1
        $x_1_13 = "[usb=\"%d\" msn=\"%d\" http=\"%d\" total=\"%d\"]" ascii //weight: 1
        $x_1_14 = "[ftp=\"%d\" pop=\"%d\" http=\"%d\" total=\"%d\"]" ascii //weight: 1
        $x_1_15 = "[FTP Infect]: %s was iframed" ascii //weight: 1
        $x_1_16 = "[Ruskill]: Detected File: \"%s\"" ascii //weight: 1
        $x_1_17 = "ftpinfect" ascii //weight: 1
        $x_1_18 = "ruskill" ascii //weight: 1
        $x_1_19 = "httpspread" ascii //weight: 1
        $x_1_20 = {66 66 67 72 61 62 00}  //weight: 1, accuracy: High
        $x_1_21 = {69 65 67 72 61 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_T_167070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.T"
        threat_id = "167070"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 03 46 3c ff b4 30 08 01 00 00 8b 8c 30 0c 01 00 00 8d 84 30 f8 00 00 00 03 ce 51 8b 40 0c 03 43 34 50 ff ?? ?? ff ?? ?? 0f b7 43 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_AI_179348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AI"
        threat_id = "179348"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 8d 4d 94 51 e9 2c 6a ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {36 00 38 00 37 00 34 00 37 00 34 00 37 00 30 00 33 00 41 00 32 00 46 00 32 00 46 00 37 00 37 00 37 00 37 00 37 00 37 00 32 00 45 00 36 00 34 00 37 00 32 00 36 00 35 00 37 00 39 00 37 00 33 00 36 00 35 00 36 00 31 00 37 00 32 00 36 00 33 00 36 00 38 00 32 00 45 00 36 00 39 00 36 00 45 00 36 00 36 00 36 00 46 00 00 00 00 00 08 00 00 00 74 00 65 00 6d 00 70 00 00 00 00 00 80 00 00 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "1ocuments and Settings\\Usuario\\1scritorio\\Ex\\Ex.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_AK_180858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AK"
        threat_id = "180858"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 50 ff 51 08 8b 45 ?? 3b c3 5b 74 06 8b 08 50 ff 51 08 c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 32 ff d6 6a 00 6a 09 53 ff 75 ?? ff d7 6a 32 ff d6 6a 02 6a 10 e8 ?? ?? ?? ?? 59 59 6a 32 ff d6 6a 00 6a 0d 53 ff 75 ?? ff d7 6a 32 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_AM_181585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AM"
        threat_id = "181585"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 50 04 8b 7d ?? 0f b6 f1 8a 14 32 32 10 32 d1 fe c1 88 14 3e 3a 48 01 72 e6}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 07 68 00 08 00 00 ff d0 8d 45 ?? 50 6a ?? ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 e8 07 00 6a 04 68}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 07 68 00 08 00 00 ff d7 8d 85 ?? ?? ff ff 50 6a 08 56 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 e8 07 00 6a 04 68}  //weight: 1, accuracy: Low
        $x_2_4 = {8a 1c 06 32 1d ?? ?? ?? ?? 32 da fe c2 88 18 40 3a d1 72 ec}  //weight: 2, accuracy: Low
        $x_1_5 = {6a 07 68 00 08 00 00 ff 55 ?? 8a 0d ?? ?? ?? ?? 32 d2 84 c9 76 ?? 8b 35 07 00 6a 04 68}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 07 68 00 08 00 00 ff d7 8a 0d ?? ?? ?? ?? 32 d2 84 c9 76 ?? 8b 35 07 00 6a 04 68}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 06 89 18 47 8b c7 6b c0 14 39 98 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 04 be 6a 2d 59 66 3b 08 75 ?? 0f b7 40 02 83 f8 64 74 ?? 83 f8 75 75}  //weight: 1, accuracy: Low
        $x_1_9 = {54 68 65 72 65 20 77 65 72 65 20 6e 6f 20 66 6f 6c 64 65 72 73 20 6f 6e 20 74 68 65 20 55 53 42 20 64 72 69 76 65 20 74 6f 20 69 6e 66 65 63 74 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_AN_182693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AN"
        threat_id = "182693"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 50 ff 51 08 8b 45 ?? (3b c3|3b c7) 5b 74 06 8b 08 50 ff 51 08 c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 50 04 8b 7d ?? 0f b6 f1 8a 14 32 32 10 32 d1 fe c1 88 14 3e 3a 48 01 72 e6}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 07 68 00 08 00 00 ff d0 8d 45 ?? 50 (6a|33) [0-1] (53|56) e8 ?? ?? ?? ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_AR_196511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AR"
        threat_id = "196511"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 00 00 00 66 c7 44 24 ?? 00 c3 c7 44 24 ?? 90 90 90 90 c7 44 24 ?? 90 90 90 90 c7 44 24 ?? 90 90 90 90 c7 44 24 ?? 90 90 90 90 c7 44 24 ?? 90 90 90 90 c7 44 24 ?? e9 00 00 00 66 c7 44 24 ?? 00 c3 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 01 8d 45 ff 50 ff 75 0c c6 45 ff 00 6a ff ff 15 ?? ?? ?? ?? 85 c0 78 ?? 80 7d ff e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_AT_197341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AT"
        threat_id = "197341"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 2b f7 8a 1c 06 32 da 32 1d ?? ?? ?? ?? fe c2 88 18 40 3a d1 72 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c1 8a 14 10 32 15 ?? ?? ?? ?? 32 d1 fe c1 88 94 05 ?? ?? ff ff 3a 0d ?? ?? ?? ?? 72 db 06 00 8b 15}  //weight: 1, accuracy: Low
        $x_10_3 = {6a 00 6a 09 68 00 01 00 00 57 ff d6 6a 32 ff d3 6a 00 6a 09 68 01 01 00 00 57 ff d6 6a 32 ff d3 6a 00 6a 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_AV_200818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AV"
        threat_id = "200818"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 2b f7 8a 1c 06 32 da 32 1d ?? ?? ?? ?? fe c2 88 18 40 3a d1 72 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 39 32 0d ?? ?? ?? ?? 32 4d ff fe 45 ff 88 0f 47 38 45 ff 72 e6}  //weight: 1, accuracy: Low
        $x_1_3 = {30 14 06 41 81 f9 01 01 00 00 72 ee f6 14 06 8b c8 46 8d 79 01}  //weight: 1, accuracy: High
        $x_1_4 = "(facepalm)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Dorkbot_AY_202547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AY"
        threat_id = "202547"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 6f 6c 6c 6f 00 00 56 65 72 73 69 6f 6e 3a 20 5b 22 76}  //weight: 1, accuracy: High
        $x_1_2 = {42 6f 74 6b 69 6c 6c 65 72 00 [0-4] 00 4d 61 6c 77 61 72 65 20 44 65 74 65 63 74 65 64 2c 20 4c 6f 63 61 74 69 6f 6e 3a 20 5b 25 73 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {50 44 65 66 00 [0-4] 00 55 6e 2d 48 6f 6f 6b 65 64 20 5b 25 73 21 25 73 5d}  //weight: 1, accuracy: Low
        $x_1_4 = "Browser: [%s], Website: [%s], Username: [%s], Password: [%s]" ascii //weight: 1
        $x_1_5 = {8b 04 be 6a 2d 59 66 3b 08 75 ?? 0f b7 40 02 83 f8 64 74 ?? 83 f8 75 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Dorkbot_A_202851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.A!!Dorkbot.gen!A"
        threat_id = "202851"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        info = "Dorkbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ngrBot" ascii //weight: 1
        $x_1_2 = "ngr->blocksize: %d" ascii //weight: 1
        $x_1_3 = "[Ruskill]: Detected " ascii //weight: 1
        $x_1_4 = {5b 53 6c 6f 77 6c 6f 72 69 73 5d 3a 20 ?? ?? ?? ?? ?? ?? ?? ?? 20 66 6c 6f 6f 64 20 6f 6e 20 22 25 73 22}  //weight: 1, accuracy: Low
        $x_1_5 = "[PDef+]: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Dorkbot_I_207306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.I!!Dorkbot.gen!A"
        threat_id = "207306"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        info = "Dorkbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 2e 70 32 31 2d 3e 20 4d 65 73 73 61 67 65 20 68 69 6a 61 63 6b 65 64 21 00 00 6d 73 6e 6d 73 67 00 00 6d 73 6e 69 6e 74 00 00 62 61 64 64 72 00 00 00 58 2d 4d 4d 53 2d 49 4d 2d 46 6f 72 6d 61 74 3a 00 00 00 00 43 41 4c 20 25 64 20 25 32 35 36 73 00 00 00 00 6d 73 6e 75 00 00 00 00 44 6f 6e 65 20 66 72 73 74 0a 00 00 6e 67 72 2d 3e 62 6c 6f 63 6b 73 69 7a 65 3a 20 25 64 0a 00 62 6c 6f 63 6b 5f 73 69 7a 65 3a 20 25 64 0a 00 4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dorkbot_AZ_209562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AZ"
        threat_id = "209562"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 06 89 18 47 8b c7 6b c0 14 39 98 ?? ?? ?? ?? 75}  //weight: 3, accuracy: Low
        $x_3_2 = {8a 1c 06 32 da 32 1d ?? ?? ?? ?? fe c2 88 18 40 3a d1 72 ec}  //weight: 3, accuracy: Low
        $x_1_3 = "(facepalm)" wide //weight: 1
        $x_1_4 = "larawang ito" wide //weight: 1
        $x_1_5 = "detta foto" wide //weight: 1
        $x_1_6 = "this photo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorkbot_AM_213085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.AM!!Dorkbot.gen!B"
        threat_id = "213085"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        info = "Dorkbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 06 32 da 32 1d ?? ?? ?? ?? fe c2 88 18 40 3a d1 72 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {30 14 06 41 81 f9 01 01 00 00 72 ee f6 14 06 8b c8 46 8d 79 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b f8 2b f7 8a 1c 06 32 da 32 1d ?? ?? ?? ?? fe c2 88 18 40 3a d1 72 ec}  //weight: 1, accuracy: Low
        $x_1_4 = "(facepalm)" wide //weight: 1
        $x_1_5 = "larawang ito" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Dorkbot_BA_233601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorkbot.BA!bit"
        threat_id = "233601"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorkbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "sample string has been fucked" ascii //weight: 2
        $x_1_2 = {8b 45 e0 03 45 f0 0f b6 08 0f be 55 b3 0f af 55 dc 0f be 45 b3 8b 75 dc 2b f0 33 d6 03 ca 8b 15 ?? ?? ?? ?? 03 55 ac 88 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {8b fa 85 c0 c1 ff 02 c1 e7 02 8b f9 c0 fe 04 c0 e6 04 87 df d0 ef d0 e7 f7 d2 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

