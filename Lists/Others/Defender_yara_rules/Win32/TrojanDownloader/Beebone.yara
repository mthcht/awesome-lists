rule TrojanDownloader_Win32_Beebone_A_171880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!A"
        threat_id = "171880"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 63 00 6d 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 00 64 00 04 00 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 00 00 02 00 00 00 6d 00 00 00 04 00 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 00 00 00 00 f5 00 00 00 00 (80|f5 28 00) f5 00 00 00 00 0a ?? 00 14 00 3c}  //weight: 1, accuracy: Low
        $x_10_5 = {11 00 00 00 53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 57 [0-96] 53 68 65 6c 6c 45 78 65 63 75 74 65 57 00}  //weight: 10, accuracy: Low
        $x_10_6 = {f5 00 00 00 00 f5 ff ff ff ff 1b ?? 00 6c ?? ff 5e ?? 00 10 00 71 ?? ff 6c ?? ff 4a f5 00 00 00 00 f5 ff ff ff ff 1b ?? 00 6c ?? ff 5e ?? 00 10 00 ae fd 69 ?? ff}  //weight: 10, accuracy: Low
        $x_10_7 = {ff 94 08 00 ?? 00 5e ?? 00 04 00 71 ?? ff f5 00 00 00 00 f5 00 00 00 00 6c ?? ff 6c ?? ff f5 00 00 00 00 f5 00 00 00 00 0a ?? 00 18 00 3c 07 00 5e ?? 00 04 00 71}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Beebone_B_171924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!B"
        threat_id = "171924"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 63 00 6d 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 00 64 00 04 00 04 00 00 00}  //weight: 1, accuracy: Low
        $x_20_3 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 57 (?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) 53 68 65 6c 6c 45 78 65 63 75 74 65 57 00}  //weight: 20, accuracy: Low
        $x_10_4 = {89 45 b4 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 89 45 b0 6a 00 6a 00 8b 55 b0 52 8b 45 b4 50 6a 00 6a 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 12 00 c7 45 fc ?? 00 00 00 68 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_5 = {89 45 c8 ff 35 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 c4 6a 00 6a 00 ff 75 c4 ff 75 c8 6a 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 8d 4d dc e8 ?? ?? ff ff c7 45 fc 06 00 00 00 6a 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Beebone_AY_172829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.AY"
        threat_id = "172829"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zutugil" ascii //weight: 1
        $x_1_2 = "receivedness" ascii //weight: 1
        $x_1_3 = "cabinetwork" ascii //weight: 1
        $x_2_4 = {81 69 e2 93 09 c1 b0 40 be f7 ab 48 48 35 c4 b7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Beebone_EU_182236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.EU"
        threat_id = "182236"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 58 59 59 59 ff (75)}  //weight: 2, accuracy: Low
        $x_1_2 = {ff ff 08 00 00 00 6a 63 e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 6f e8 ?? ?? ?? ff 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 6d e8 ?? ?? ?? ff 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 3a e8 ?? ?? ?? ff 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Beebone_C_193275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!C"
        threat_id = "193275"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" ascii //weight: 1
        $x_1_2 = {2a 56 49 52 54 55 41 4c 2a [0-2] 2a 56 4d 57 41 52 45 2a [0-2] 2a 56 42 4f 58 2a [0-2] 2a 51 45 4d 55 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "/c tasklist&&del" ascii //weight: 1
        $x_1_4 = {72 75 6e 6d 65 2e 65 78 65 [0-2] 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20}  //weight: 1, accuracy: Low
        $x_1_5 = "FGD75n-bb342-VBhhjH7" ascii //weight: 1
        $x_1_6 = {3a 34 34 33 [0-2] 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 [0-2] 2f 76}  //weight: 1, accuracy: Low
        $x_1_7 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" ascii //weight: 1
        $x_1_8 = "snxhk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_Beebone_C_193275_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!C"
        threat_id = "193275"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" wide //weight: 1
        $x_1_2 = {2a 00 56 00 49 00 52 00 54 00 55 00 41 00 4c 00 2a 00 0d 00 0a 00 2a 00 56 00 4d 00 57 00 41 00 52 00 45 00 2a 00 0d 00 0a 00 2a 00 56 00 42 00 4f 00 58 00 2a 00 0d 00 0a 00 2a 00 51 00 45 00 4d 00 55 00 2a 00}  //weight: 1, accuracy: High
        $x_1_3 = "/c tasklist&&del" wide //weight: 1
        $x_1_4 = {72 00 75 00 6e 00 6d 00 65 00 2e 00 65 00 78 00 65 00 0d 00 0a 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00}  //weight: 1, accuracy: High
        $x_1_5 = "FGD75n-bb342-VBhhjH7" wide //weight: 1
        $x_1_6 = {3a 00 34 00 34 00 33 00 0d 00 0a 00 52 00 74 00 6c 00 4d 00 6f 00 76 00 65 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 0d 00 0a 00 2f 00 76 00}  //weight: 1, accuracy: High
        $x_1_7 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 1
        $x_1_8 = "snxhk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_Beebone_D_194978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!D"
        threat_id = "194978"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "-1396643362Administrator" wide //weight: 2
        $x_2_2 = {36 00 38 00 30 00 34 00 30 00 30 00 43 00 43 00 30 00 30 00 45 00 38 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00}  //weight: 2, accuracy: Low
        $x_1_3 = "/c tasklist&&del" wide //weight: 1
        $x_1_4 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Beebone_E_195665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!E"
        threat_id = "195665"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "tasklist&&del" wide //weight: 3
        $x_3_2 = "\\CurrentVersion\\AppPaths\\cmd.exe" wide //weight: 3
        $x_3_3 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" wide //weight: 3
        $x_3_4 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 3
        $x_1_5 = "x.mpeg" wide //weight: 1
        $x_1_6 = ":.dl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Beebone_F_197971_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!F"
        threat_id = "197971"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" ascii //weight: 2
        $x_2_2 = {2a 00 56 00 49 00 52 00 54 00 55 00 41 00 4c 00 2a 00 [0-16] 2a 00 56 00 4d 00 57 00 41 00 52 00 45 00 2a 00 [0-16] 2a 00 56 00 42 00 4f 00 58 00 2a 00 [0-16] 2a 00 51 00 45 00 4d 00 55 00 2a 00}  //weight: 2, accuracy: Low
        $x_2_3 = {2a 56 49 52 54 55 41 4c 2a [0-16] 2a 56 4d 57 41 52 45 2a [0-16] 2a 56 42 4f 58 2a [0-16] 2a 51 45 4d 55 2a}  //weight: 2, accuracy: Low
        $x_2_4 = "/c tasklist&&del" ascii //weight: 2
        $x_2_5 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" ascii //weight: 2
        $x_1_6 = {72 00 75 00 6e 00 6d 00 65 00 2e 00 65 00 78 00 65 00 [0-16] 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00}  //weight: 1, accuracy: Low
        $x_1_7 = {72 75 6e 6d 65 2e 65 78 65 [0-16] 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: Low
        $x_1_8 = {52 00 74 00 6c 00 4d 00 6f 00 76 00 65 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 [0-16] 2f 00 76 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_9 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 [0-16] 2f 76 2f}  //weight: 1, accuracy: Low
        $x_1_10 = {47 00 65 00 74 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 [0-16] 78 00 78 00 78 00}  //weight: 1, accuracy: Low
        $x_1_11 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e [0-16] 78 78 78}  //weight: 1, accuracy: Low
        $x_1_12 = "x.mpeg" wide //weight: 1
        $x_1_13 = ":.dl" wide //weight: 1
        $x_1_14 = "autorun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Beebone_G_198317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!G"
        threat_id = "198317"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c tasklist&&del " wide //weight: 1
        $x_1_2 = {72 00 75 00 6e 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00 ?? ?? 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/o/?" wide //weight: 1
        $x_1_4 = {2e 00 65 00 78 00 65 00 00 00 00 00 1a 00 00 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 57 00 00 00 24 00 00 00 47 00 65 00 74 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 00 65 00 74 00 55 00 73 00 65 00 72 00 4e 00 61 00 6d 00 65 00 57 00 [0-32] 2a 00 [0-2] 47 00 65 00 74 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 57 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = "/x/?" wide //weight: 1
        $x_1_7 = {72 00 75 00 6e 00 6d 00 65 00 2e 00 65 00 78 00 65 00 [0-8] 2f 00 [0-14] 2f 00 [0-8] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_8 = {73 00 62 00 69 00 65 00 64 00 6c 00 6c 00 [0-10] 64 00 62 00 67 00 68 00 65 00 6c 00 70 00 ?? ?? ?? ?? ?? ?? 73 00 6e 00 78 00 68 00 6b 00 ?? ?? ?? ?? ?? ?? 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 69 00 73 00 6b 00 5c 00 45 00 6e 00 75 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 [0-48] 2f 00 ?? ?? ?? ?? ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Beebone_H_205720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beebone.gen!H"
        threat_id = "205720"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 62 00 69 00 65 00 64 00 6c 00 6c 00 [0-6] 0e 00 00 00 64 00 62 00 67 00 68 00 65 00 6c 00 70 00 [0-6] 0a 00 00 00 73 00 6e 00 78 00 68 00 6b 00 [0-6] 4e 00 00 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 69 00 73 00 6b 00 5c 00 45 00 6e 00 75 00 6d 00 [0-6] 12 00 00 00 2a 00 56 00 49 00 52 00 54 00 55 00 41 00 4c 00 2a 00 [0-6] 10 00 00 00 2a 00 56 00 4d 00 57 00 41 00 52 00 45 00 2a 00 [0-6] 0c 00 00 00 2a 00 56 00 42 00 4f 00 58 00 2a 00 [0-6] 0c 00 00 00 2a 00 51 00 45 00 4d 00 55 00 2a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 63 00 20 00 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 26 00 26 00 64 00 65 00 6c 00 20 00 ?? ?? 02 00 00 00 5c 00 ?? ?? 02 00 00 00 3f 00 ?? ?? 02 00 00 00 7c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

