rule TrojanDownloader_Win32_Bancos_B_2147583054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.gen!B"
        threat_id = "2147583054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2200"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {8d 4d ec 8b d3 a1 ?? ?? ?? ?? 8b 30 ff 56 0c 8d 45 ec 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec b2 01 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 68 90 01 00 00 e8 ?? ?? ?? ?? 4b 83 fb ff}  //weight: 1000, accuracy: Low
        $x_1000_2 = {8d 4d ec 8b d3 a1 ?? ?? ?? ?? 8b 30 ff 56 0c 8b 45 ec b2 01 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 68 90 01 00 00 e8 ?? ?? ?? ?? 4b 83 fb ff}  //weight: 1000, accuracy: Low
        $x_1000_3 = {8b 00 8b 40 30 50 e8 ?? ?? ?? ?? eb 24 6a 05 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b 40 30 50 e8}  //weight: 1000, accuracy: Low
        $x_100_4 = {ff ff ff ff 17 00 00 00 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00}  //weight: 100, accuracy: High
        $x_100_5 = {ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 2 of ($x_100_*))) or
            ((3 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_2147598059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos"
        threat_id = "2147598059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "impressions.cz" ascii //weight: 1
        $x_1_3 = "teamocrazy.xpg.com.br/links/pharm.txt" ascii //weight: 1
        $x_1_4 = "teamocrazy.xpg.com.br/links/worm.txt" ascii //weight: 1
        $x_1_5 = "msnmsgrr.exe" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "gethostbyname" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "OpenSCManagerA" ascii //weight: 1
        $x_1_10 = "CreateServiceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_A_2147605812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.A"
        threat_id = "2147605812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 bb 01 00 e9 ?? 00 00 00 8d 45 ?? 8b 55 ?? 8a 54 3a ff 88 50 01 c6 00 01 8d 55 ?? 8d 45 ?? e8 ?? ?? ff ff 8d 45 ?? 0f b7 d3 8b 4d ?? 8a 14 11 88 50 01 c6 00 01 8d 55 ?? 8d 45 ?? b1 02 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 05 00 00 00 e8 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff 50 6a 00 e8 ?? ?? ff ff 8d 55 ?? b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 55}  //weight: 1, accuracy: Low
        $x_1_3 = "UrlDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_D_2147613100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.D"
        threat_id = "2147613100"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://clio4040.webcindario.com/game" ascii //weight: 10
        $x_5_2 = "site da Hotmail: http://www.hotmail.com/recadastramento/" ascii //weight: 5
        $x_5_3 = "\\IEXPLORE.EXE http://www.msn.com.br" ascii //weight: 5
        $x_5_4 = "msgne.scr" ascii //weight: 5
        $x_5_5 = "msgnt.exe" ascii //weight: 5
        $x_1_6 = {13 5a 4e 4e 50 50 50 61 64 65 65 69 69 69 69 69 65 65 64 61}  //weight: 1, accuracy: High
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_8 = "MAPI32.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_H_2147616603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.H"
        threat_id = "2147616603"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 50 89 45 f0 bf 01 00 00 00 8b 45 fc 8a 5c 38 ff 80 e3 0f 8b 45 f4 8a 44 30 ff 24 0f 32 d8 80 f3 0a}  //weight: 3, accuracy: High
        $x_1_2 = {4f 75 72 20 46 57 42 20 69 73 20 4c 6f 61 64 65 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 46 69 6c 65 20 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 75 6e 6e 69 6e 67 20 44 6f 77 6e 6c 6f 61 64 65 64 20 46 69 6c 65 20 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_2_5 = {66 77 62 64 6c 6c 2e 64 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_I_2147616821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.I"
        threat_id = "2147616821"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "URLDownloadToFileA" ascii //weight: 5
        $x_1_2 = "http://www.freewebtown.com/login187/TudoAqui.exe" wide //weight: 1
        $x_1_3 = "http://www.freewebtown.com/login187/process.exe" wide //weight: 1
        $x_1_4 = "http://www.freewebtown.com/login187/worm.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_M_2147617562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.M"
        threat_id = "2147617562"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 77 73 63 74 79 33 32 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_3 = {30 30 31 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {30 30 32 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_5_5 = {84 c0 74 30 6a 00 68 ?? ?? 45 00 e8 ?? ?? fb ff ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 84 c0 74 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_P_2147618652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.P"
        threat_id = "2147618652"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 95 f0 fa ff ff b9 00 04 00 00 8b 45 f0 8b 30 ff 56 0c 8b f0 85 f6 74 10 8d 95 f0 fa ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "!odipmorroC oviuqrA" ascii //weight: 1
        $x_1_3 = "//:ptth" ascii //weight: 1
        $x_1_4 = "srevird" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_U_2147618886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.U"
        threat_id = "2147618886"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c0 55 8b ec 6a 00 33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 e8 ?? ?? fb ff b8 ?? ?? 45 00 e8 ?? ?? fd ff (b8 ?? ??|68 ?? ??) e8 ?? ?? fb ff [0-10] 84 c0 74 05 e8 ?? ?? fb ff (b8|ba) ?? ?? 45 00 (b8|ba) ?? ?? 45 00 e8 ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_5_2 = "URLDownloadToFileA" ascii //weight: 5
        $x_1_3 = {4d 69 63 72 6f 73 6f 66 74 20 50 6f 77 65 72 20 50 6f 69 6e 74 20 6e e3 6f 20 63 6f 6e 73 65 67 75 69 75 20 76 69 73 75 61 6c 69 7a 61 72 20 65 73 74 65 20 61 72 71 75 69 76 6f 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 6f 72 64 50 61 64 20 6e e3 6f 20 63 6f 6e 73 65 67 75 69 75 20 76 69 73 75 61 6c 69 7a 61 72 20 65 73 74 65 20 61 72 71 75 69 76 6f 21 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 64 69 72 65 63 69 6f 6e 61 64 6f 20 70 61 72 61 20 6e 6f 73 73 6f 20 73 69 74 65 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_AC_2147622795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.AC"
        threat_id = "2147622795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 37 39 2e 31 32 35 2e 37 2e 32 32 31 2f [0-16] 2e 74 73 74}  //weight: 10, accuracy: Low
        $x_10_2 = "/c shutdown /r /t 30 /c \"Este computador" ascii //weight: 10
        $x_10_3 = "\\GbPlugin\\gbpdist.dll" ascii //weight: 10
        $x_10_4 = {41 20 66 65 72 72 61 6d 65 6e 74 61 20 64 65 20 72 65 6d 6f e7 e3 6f 20 64 65 20 73 6f 66 74 77 61 72 65 20 6d 61 6c 20 69 6e 74 65 6e 63 69 6f 6e 61 64 6f 20 64 61 20 4d 69 63 72 6f}  //weight: 10, accuracy: High
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_AK_2147624614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.AK"
        threat_id = "2147624614"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 eb 02 66 83 fb 03 76 40 8d 45 f0 50 0f b7 d3 b9 03 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f0 e8 ?? ?? ?? ?? 8b f8 66 2b 7d fa 8d 45 ec 8b d7 e8 ?? ?? ?? ?? 8b 55 ec 8b c6 e8 ?? ?? ?? ?? 66 83 eb 03 66 83 fb 03 77 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 0f 00 00 00 e8 ?? ?? fb ff 8b 85 ?? ?? ff ff e8 ?? ?? fb ff 50 6a 00 e8 ?? ?? fb ff 8d 55 f8 b8 ?? ?? 44 00 e8 ?? ?? ff ff 8d 55 f4 b8 ?? ?? 44 00 e8 ?? ?? ff ff 8d 55 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 0f 00 00 00 e8 ?? ?? fb ff 8b 85 ?? ?? ff ff e8 ?? ?? fb ff 50 6a 00 e8 ?? ?? fb ff 8b 45 ec e8 ?? ?? fb ff 84 c0 75 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Bancos_AN_2147625074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.AN"
        threat_id = "2147625074"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 32 ff 59 2a d1 f6 d2 e8 ?? ?? ?? ?? 8b 55 f0 8d 45 f4 e8 ?? ?? ?? ?? 46 4b 75 da}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 74 6c 64 6c 6c 2e 64 6c 6c 00 46 69 42 61 73 65 53 69 73 74 65 6d 61 00 46 75 6e 63 43 61 43 6c 69 65 6e 74 65 00 46 75 6e 63 52 65 6c 61 74 6f 72 69 6f 00 4d 6f 76 65 47 61 74 65 00 53 68 6f 77 46 6f 72 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_BD_2147627120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BD"
        threat_id = "2147627120"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 45 f6 d3 e8 f6 d0 30 45 eb 8d 55 eb b9 01 00 00 00 8b 45 ec 8b 38 ff 57 14 46 4b 75 cf}  //weight: 1, accuracy: High
        $x_1_2 = {7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 b8 44 00 00 00 c7 45 e4 01 00 00 00 66 c7 45 e8 00 00 8d 45 a8 50 8d 45 b8 50 6a 00 6a 00 68 90 00 00 00 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 83 f8 01}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 44 30 ff 33 d8 8d 45 d0 50 89 5d d4 c6 45 d8 00 8d 55 d4 33 c9 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 d0 8d 45 ec e8 ?? ?? ?? ?? 8b fb ff 45 e8 ff 4d e0 75 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Bancos_BE_2147627192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BE"
        threat_id = "2147627192"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 70 64 61 74 65 00 0d 01 07 00 55 70 64 61 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_3 = {3f 00 6e 00 61 00 6d 00 65 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "windir" wide //weight: 1
        $x_1_5 = {6d 49 6e 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_BM_2147627869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BM"
        threat_id = "2147627869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 2c bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b7 54 5a fe 2b d3 81 ea ?? ?? 00 00 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 d9}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 2e 00 2e 00 2e 00 2f 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 00 6f 00 6d 00 2f 00 2e 00 2e 00 2e 00 2f 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_BN_2147627977_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BN"
        threat_id = "2147627977"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 c7 45 ?? 01 00 00 00 83 f3 ?? 8d 45 ?? 50 89 5d ?? c6 45 ?? 00 8d 55 ?? 33 c9 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b f3 47 ff 4d ?? 75 a8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 ff b3 7c 03 00 00 68 ?? ?? ?? ?? ff b3 80 03 00 00 8d 45 e4 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 e4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_BQ_2147628070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BQ"
        threat_id = "2147628070"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 d0 6a 0c 50 6a 10 68 80 08 00 00 e8 ?? ?? ?? ?? 35}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 6f 76 6f 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "Loader_VB_didu.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_BR_2147628271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BR"
        threat_id = "2147628271"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 62 6f 4f 54 2e 64 6c 6c ?? ?? 57 41 42}  //weight: 1, accuracy: Low
        $x_1_2 = "$rundll32 C:\\Windows\\boOT.dll,network" ascii //weight: 1
        $x_1_3 = "REGSVR32 /s C:\\wab.dll" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\boOT.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_BV_2147628432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BV"
        threat_id = "2147628432"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 74 51 ff d6 8d ?? ?? ?? ff ff 6a 74 52 ff d6 8d ?? ?? ?? ff ff 6a 70 50 ff d6 8d ?? ?? ?? ff ff 6a 3a 51 ff d6 8d ?? ?? ?? ff ff 6a 2f}  //weight: 2, accuracy: Low
        $x_1_2 = {46 75 6e 63 5f 43 61 6d 69 6e 68 6f 5f 52 65 67 53 76 72 33 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 75 6e 63 5f 50 61 73 74 61 5f 53 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 75 6e 63 5f 50 61 73 74 61 5f 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 67 75 61 72 64 61 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "/cadastro.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_BY_2147628459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.BY"
        threat_id = "2147628459"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "feriascancun.hpg.com.br/tuto.html" ascii //weight: 1
        $x_1_2 = "attrib +r +s +h C:\\svchost.exe" ascii //weight: 1
        $x_1_3 = {89 74 24 04 8d 95 64 ff ff ff b8 64 00 00 00 89 54 24 0c 89 44 24 08 89 3c 24 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_CA_2147628557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.CA"
        threat_id = "2147628557"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_1_2 = "explorer.exe http://portalweb04.saude.gov.br/Imagens_svs/botoes/carregando.gif" wide //weight: 1
        $x_1_3 = "C:\\Arquivos de programas\\Arquivos comuns\\asoela.exe" wide //weight: 1
        $x_1_4 = {77 00 2e 00 66 00 69 00 72 00 69 00 62 00 65 00 63 00 61 00 34 00 35 00 30 00 30 00 2e 00 70 00 61 00 67 00 65 00 62 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 72 00 62 00 69 00 67 00 2f 00 [0-16] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = "C:\\Documents and Settings\\dessa\\Desktop\\vb puxador melhor no jeito\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_CL_2147628841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.CL"
        threat_id = "2147628841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 71 6d 64 61 74 30 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 73 79 73 74 65 6d 2f 63 6f 72 70 6f 2f [0-8] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 20 56 69 73 75 61 6c 69 7a 61 64 6f 72 20 64 65 20 69 6d 61 67 65 6e 73 20 65 20 66 61 78 20 64 6f 20 57 69 6e 64 6f 77 73 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_CQ_2147629102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.CQ"
        threat_id = "2147629102"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe -killfile C:\\WINDOWS\\system32\\drivers\\gbpkm.sys" ascii //weight: 1
        $x_1_2 = ".exe -killfile C:\\Arquiv~1\\GbPlugin\\gbpsv.exe" ascii //weight: 1
        $x_1_3 = ".exe -killfile C:\\Arquiv~1\\GbPlugin\\gbpdist.dll" ascii //weight: 1
        $x_1_4 = ".exe -killfile C:\\Arquiv~1\\GbPlugin\\gbieh.dll" ascii //weight: 1
        $x_2_5 = "C:\\WINDOWS\\System32\\Logsvc.bat" ascii //weight: 2
        $x_2_6 = "C:\\Arquivos de Programas\\Internet Explorer\\delon.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_DA_2147630847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.DA"
        threat_id = "2147630847"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "novidadesloucas.no-ip.info" ascii //weight: 1
        $x_1_2 = "indefinido" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "esmasmasks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_DJ_2147634004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.DJ"
        threat_id = "2147634004"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 42 52 41 20 20 45 4d 20 4f 55 54 52 4f 20 43 4f 4d 50 55 54 41 44 4f 52 21 21 00}  //weight: 3, accuracy: High
        $x_1_2 = "olhaminhafotos.hpg.com.br/" ascii //weight: 1
        $x_1_3 = "br/hotmail.jpg" ascii //weight: 1
        $x_1_4 = "comuns\\hotmail.exe" ascii //weight: 1
        $x_1_5 = "br/gdbrr.jpg" ascii //weight: 1
        $x_1_6 = "comuns\\gdbrr.exe" ascii //weight: 1
        $x_1_7 = "br/satplg.jpg" ascii //weight: 1
        $x_1_8 = "comuns\\satplg.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_DM_2147634136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.DM"
        threat_id = "2147634136"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 f8 ba 02 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 74 6f 73 76 63 75 6f 6c 6b 2e 63 6f 6d 2f 31 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 41 72 71 75 69 76 6f 73 20 63 6f 6d 75 6e 73 5c 6b 6c 73 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_DW_2147639956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.DW"
        threat_id = "2147639956"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FastMM Borland Edition" ascii //weight: 1
        $x_1_2 = "\\install_flash_player.exe" wide //weight: 1
        $x_1_3 = {77 00 77 00 77 00 2e 00 6e 00 75 00 63 00 65 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 6e 00 6f 00 76 00 6f 00 73 00 69 00 74 00 65 00 2f 00 69 00 6d 00 61 00 67 00 65 00 6e 00 73 00 2f 00 73 00 6d 00 74 00 70 00 2e 00 67 00 69 00 66 00 [0-4] 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {77 00 77 00 77 00 2e 00 6e 00 75 00 63 00 65 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 6e 00 6f 00 76 00 6f 00 73 00 69 00 74 00 65 00 2f 00 69 00 6d 00 61 00 67 00 65 00 6e 00 73 00 2f 00 77 00 61 00 62 00 2e 00 67 00 69 00 66 00 [0-4] 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "www.adobe.com/br/shockwave/welcome/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_DY_2147640693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.DY"
        threat_id = "2147640693"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 69 74 61 6d 61 72 65 73 2e 63 6f 6d 2f 73 70 61 69 6e 2f 41 44 4f 42 45 52 45 41 44 45 52 39 30 2e 65 78 65 00 ff ff ff ff 07 00 00 00 41 50 50 44 41 54 41 00 ff ff ff ff 12 00 00 00 5c 41 44 4f 42 45 52 45 41 44 45 52 39 30 2e 65 78 65 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_DZ_2147640937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.DZ"
        threat_id = "2147640937"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {63 6d 64 20 2f 6b 20 63 3a 5c [0-8] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 68 6f 6e 2d 73 61 6d 73 6f 6e 2e 62 65 2f 6a 73 2f 5f 6e 6f 74 65 73 2f [0-8] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_EE_2147642322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.EE"
        threat_id = "2147642322"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 3c 83 c9 ff 33 c0 41 83 f9 40 7e 02 33 c9 8a 91 ?? ?? ?? 00 30 90 ?? ?? ?? 00 40 3d 00 08 00 00 7c e4}  //weight: 1, accuracy: Low
        $x_1_2 = {b2 68 b1 3a 80 bc 05 ?? ?? ?? ?? 67 75 1c 80 bc 05 ?? ?? ?? ff 74 75 12 38 94 ?? ?? ?? ?? ?? 75 09 38 8c ?? ?? ?? ?? ?? 74 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_EH_2147644364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.EH"
        threat_id = "2147644364"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "systeam\\reaction\\" ascii //weight: 1
        $x_1_2 = {74 61 73 6b 6b 69 6c 6c [0-4] 20 2d 66 20 2d 69 6d 20 [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "MuTexXx2010" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_EI_2147644704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.EI"
        threat_id = "2147644704"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\sys\\alg.exe" ascii //weight: 2
        $x_3_2 = "schtasks /create /tn %s /tr %s /sc onlogon /ru \"NT AUTHORITY\\SYSTEM\"" ascii //weight: 3
        $x_2_3 = "\\BK66.log" ascii //weight: 2
        $x_1_4 = "ConsentPromptBehaviorAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_EX_2147649379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.EX"
        threat_id = "2147649379"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 23 69 25 76 ?? 6f ?? ?? ?? 63 ?? 6f ?? 72 ?? 72 ?? 6f ?? 6d ?? 70 ?? 69 ?? 64 ?? 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {63 23 73 23 73 ?? 72 ?? 73 ?? 61}  //weight: 1, accuracy: Low
        $x_1_3 = {63 2a 6f 23 6e ?? 74 ?? 61 ?? 64 ?? 6f ?? 72 ?? 2e ?? 70 ?? 68 ?? 70 ?? 3f ?? 75 ?? 72 ?? 6c ?? 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {63 23 6f 23 6e ?? 74 ?? 61 ?? 64 ?? 6f ?? 72 ?? 2e ?? 70 ?? 68 ?? 70 ?? 3f ?? 75 ?? 72 ?? 6c ?? 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 1, accuracy: High
        $x_1_6 = "C:\\programfiles\\cssrsa.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Bancos_FC_2147649752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FC"
        threat_id = "2147649752"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\iiexplorer.exe" ascii //weight: 1
        $x_1_2 = "dl.dropbox.com/u/" wide //weight: 1
        $x_1_3 = "/GetDiskSerial.dll" wide //weight: 1
        $x_1_4 = "/iiexplorer.js" wide //weight: 1
        $x_1_5 = {77 00 2e 00 66 00 75 00 6e 00 6f 00 72 00 70 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 66 00 6f 00 74 00 6f 00 73 00 2f 00 [0-24] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_FL_2147652059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FL"
        threat_id = "2147652059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/products/erro.php" ascii //weight: 1
        $x_1_2 = "Software\\Classes\\Applications\\Nicrosoft.exe" ascii //weight: 1
        $x_1_3 = "Software\\Classes\\Applications\\NatGat_.exe" ascii //weight: 1
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "DontReportInfectionInformation" ascii //weight: 1
        $x_1_6 = {41 74 75 61 6c 69 7a 61 e7 e3 6f 20 64 6f 20 57 69 6e 64 6f 77 73 20 63 6f 6d 70 6c 65 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Bancos_FM_2147652548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FM"
        threat_id = "2147652548"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 08 00 2f 61 70 73 65 74 61 2e 70 70 73}  //weight: 1, accuracy: Low
        $x_1_2 = "caballo1" ascii //weight: 1
        $x_1_3 = "sertup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_FP_2147653359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FP"
        threat_id = "2147653359"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\puta.dll" wide //weight: 1
        $x_1_2 = "/socios/datos.php" wide //weight: 1
        $x_1_3 = ":\\WINDOWS\\system32\\cdftmong.exe" wide //weight: 1
        $x_2_4 = {5c 00 47 00 65 00 6c 00 74 00 69 00 58 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 50 00 75 00 74 00 65 00 6e 00 63 00 69 00 61 00 5c 00 50 00 75 00 74 00 65 00 6e 00 63 00 69 00 61 00 5c 00 [0-16] 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_FQ_2147653383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FQ"
        threat_id = "2147653383"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6f 6d 65 72 6f 66 6f 6e 73 65 63 61 2e 30 37 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-8] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_FS_2147653933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FS"
        threat_id = "2147653933"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 [0-16] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 61 74 6c 73 79 73 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 99 f7 f9 89 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_AEW_2147655794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.AEW"
        threat_id = "2147655794"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".*p#h%p%?*c@h#a#v%e*=#x#c%h*a@v#e%&%u*r#l#=" ascii //weight: 1
        $x_1_2 = {0a 00 00 00 5c 69 64 73 79 73 2e 74 78 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_EB_2147656404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.EB"
        threat_id = "2147656404"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 74 72 4f 72 69 65 6e 74 65 00 00 55 52 4c 00 6f 75 74 46 69 6c 65 00 49 6e 70 75 74 42 75 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 72 6b 61 73 70 65 72 00 00 00 55 52 4c 00 6f 75 74 46 69 6c 65 00 49 6e 70 75 74 42 75 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_3 = {73 74 72 47 74 65 63 00 55 52 4c 00 6f 75 74 46 69 6c 65 00 49 6e 70 75 74 42 75 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_4 = {73 74 72 73 69 6d 70 6c 65 73 00 00 55 52 4c 00 6f 75 74 46 69 6c 65 00 49 6e 70 75 74 42 75 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_5 = {73 74 72 4e 65 72 76 6f 73 6f 00 00 55 52 4c 00 6f 75 74 46 69 6c 65 00 49 6e 70 75 74 42 75 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_6 = "\\kasper.vbp" wide //weight: 1
        $x_1_7 = "\\oriente.vbp" wide //weight: 1
        $x_1_8 = "\\downl.vbp" wide //weight: 1
        $x_1_9 = "2E6A7067" wide //weight: 1
        $x_1_10 = "2E676966" wide //weight: 1
        $x_1_11 = "2E657865" wide //weight: 1
        $x_1_12 = "2E736372" wide //weight: 1
        $x_1_13 = "797374656D" wide //weight: 1
        $x_1_14 = "696E646F7773" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Bancos_FU_2147659117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FU"
        threat_id = "2147659117"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "titulo=" ascii //weight: 1
        $x_1_2 = "texto=" ascii //weight: 1
        $x_1_3 = "AC79B247DD5AAE7B80" ascii //weight: 1
        $x_5_4 = "praquem=" ascii //weight: 5
        $x_10_5 = {8b c3 8b 08 ff 51 38 68 ?? ?? 47 00 8d 55 ?? 8b [0-2] e8 ?? ?? ff ff ff 75 ?? 68 ?? ?? 47 00 8d 45 ?? ba 03 00 00 00 e8 ?? ?? f8 ff 8b 55 ?? 8b c3 8b 08 ff 51 38 8d 55 ?? 8b ?? 8b 08 ff 51 ?? 8b 4d ?? 8d 45 ?? ba ?? ?? 47 00 e8 ?? ?? ?? ff 8b 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bancos_FW_2147661620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.FW"
        threat_id = "2147661620"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 72 00 75 00 7a 00 65 00 69 00 72 00 6f 00 33 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 74 00 20 00 6a 00 61 00 76 00 61 00 3d 00 70 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 20 00 6a 00 61 00 76 00 61 00 2e 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 41 00 6c 00 6c 00 50 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Super Novissimo.... Altamente Crypt." wide //weight: 1
        $x_1_4 = "REG_SZ /d C:\\WINDOWS\\system32\\ituneshelper.exe /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Bancos_GH_2147686414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.GH"
        threat_id = "2147686414"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 54 72 69 78 4e 65 74 43 6c 61 73 73 45 78 44 57 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Projetos\\Botnets\\TrixNet\\source\\TrixNet\\Release\\Flash Downloader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_GL_2147695062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.GL"
        threat_id = "2147695062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//bit.ly/" ascii //weight: 1
        $x_1_2 = "PowerShell (new-object net.webclient).DownloadString(" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WSCript.shell\")" ascii //weight: 1
        $x_1_4 = "oShell.run \"" ascii //weight: 1
        $x_1_5 = ");Start-Process regsvr32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bancos_GN_2147717106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bancos.GN"
        threat_id = "2147717106"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "536b7970652e7a6970" wide //weight: 1
        $x_1_2 = "5c536b797065" wide //weight: 1
        $x_1_3 = "687474703a2f2f6e733131362e686f73746761746f722e636f6d2e62722f7e6d61726b653132362f677569622f67726f76652e706870" wide //weight: 1
        $x_1_4 = "5c536b7970655c37343666366436353665373536333735363137363631373337342e657865" wide //weight: 1
        $x_1_5 = "687474703a2f2f6e733635382e686f73746761746f722e636f6d2e62722f7e6d61726b653735342f6e6f7661732f6469722f536b7970652e7a6970" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

