rule TrojanDownloader_Win32_Cutwail_P_2147598115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.P"
        threat_id = "2147598115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 03 6d 3d 30 26 83 c3 04 c7 03 61 3d 30 26 83 c3 04 83 3d ?? ?? ?? ?? ?? 74 09 c7 03 72 3d 31 26}  //weight: 1, accuracy: Low
        $x_1_2 = {89 5d fc 66 81 3b 4d 5a 75 1e 80 7b 50 75 74 0d ff 75 f8 ff 75 fc e8 ?? ?? 00 00 eb 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_Q_2147598322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.Q"
        threat_id = "2147598322"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5c 6c 64 72 6e 74 2e 62 69 6e 00}  //weight: 4, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 78 5f 25 75 5f 25 75 5f 25 73 5f 25 73 3f 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 78 5f 25 75 5f 25 75 5f 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 62 5f 25 75 5f 25 75 3f 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 62 5f 25 75 5f 25 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_S_2147601812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.S"
        threat_id = "2147601812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 45 08 0f be 48 50 83 f9 69 75 07 b8 01 00 00 00 eb 02 33 c0}  //weight: 6, accuracy: High
        $x_1_2 = {68 00 28 00 00 e8 ?? ?? ff ff 89 85 ?? fe ff ff 68 00 a0 0f 00 e8 ?? ?? ff ff 89 85 ?? fe ff ff a1 20 30 40 00 50}  //weight: 1, accuracy: Low
        $x_1_3 = {85 64 fe ff ff 50 8b 4d fc 51 8b 95 58 fe ff ff 52 8b 85 60 fe ff ff 8b 0c 85 24 30 40 00 51}  //weight: 1, accuracy: High
        $x_1_4 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_5 = "\\System32\\svchost.exe" wide //weight: 1
        $x_1_6 = "mutantofthefuture" ascii //weight: 1
        $x_1_7 = "GET /40" ascii //weight: 1
        $x_1_8 = "WLEventStartShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_T_2147604765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.T"
        threat_id = "2147604765"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "GET /newforum/index.php HTTP/1.1" ascii //weight: 1
        $x_1_4 = "/newforum/search.php" ascii //weight: 1
        $x_1_5 = "Glock Suite" ascii //weight: 1
        $x_1_6 = "\\glock32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_A_2147604767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.gen!A"
        threat_id = "2147604767"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 5a 74 0a ba ff ff ff ff e9 ?? ?? 00 00 83 ec ?? 8d ?? d8 fe ff ff 07 00 80 ?? 4d 75 06 80}  //weight: 1, accuracy: Low
        $x_1_2 = {74 14 83 ec 08 89 d8 29 d0 50 8d 04 16 50 e8 ?? ?? 00 00 83 c4 10 e8 ?? 00 00 00 b8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {75 7f 8a 44 3e 01 30 04 3e 8a 54 3e 02 31 d0 88 44 3e 01 8a 44 3e 03 31 c2 88 54 3e 02 40 88 44 3e 03 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_V_2147611019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.V"
        threat_id = "2147611019"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f0 00 00 00 00 8d 45 e8 8b 55 fc 8b 4d f0 8a 14 0a 8a 4d f0 41 32 d1 e8 ?? ?? ff ff 8b 55 e8 8b 45 f4 e8 ?? ?? ff ff 8b 45 f4 ff 45 f0 ff 4d ec 75 d3}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 1f 00 00 00 e8 ?? ?? ff ff 8b 45 ec e8 ?? ?? ff ff 8d 4d e8 b8 ?? ?? ?? ?? ba 22 00 00 00 e8 ?? ?? ff ff 8b 45 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {47 45 54 20 2f 66 69 6c 65 73 2f [0-10] 2e 65 78 65 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_W_2147611148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.W"
        threat_id = "2147611148"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 80 38 4d 75 0b 8b 45 08 40 80 38 5a 75 02 eb 0f}  //weight: 1, accuracy: High
        $x_2_2 = {c6 00 2f 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 72 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 69 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 6f 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 3f 8d 45 f8 ff 00}  //weight: 2, accuracy: High
        $x_1_3 = "Host: %i.%i.%i.%i%s" ascii //weight: 1
        $x_1_4 = ";%4.4hx-%4.4hx;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_Y_2147611588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.Y"
        threat_id = "2147611588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 54 5d 64 ff 35 18 00 00 00 58 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e0 b9 79 37 9e (ff|58 8b)}  //weight: 1, accuracy: Low
        $x_1_3 = {68 20 00 cc 00 68 c8 00 00 00 68 96 00 00 00 6a 00 6a 00 ff 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AA_2147611717_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AA"
        threat_id = "2147611717"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 64 ff 35 18 00 00 00 58 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e0 b9 79 37 9e (ff|58 8b)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_B_2147612115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.gen!B"
        threat_id = "2147612115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 5c 2e 5c 50 72 6f 74 33 00}  //weight: 2, accuracy: High
        $x_1_2 = {43 70 6c 33 32 76 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 73 33 32 6e 65 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_4 = {0f be 48 01 83 f9 6e 75 0a c7 05}  //weight: 2, accuracy: High
        $x_2_5 = {83 f9 4d 75 11 8b 55 fc 0f be 42 01 83 f8 5a}  //weight: 2, accuracy: High
        $x_2_6 = {74 5b c7 85 20 fd ff ff 07 00 01 00 68 c8 02 00 00 6a 00 8d 8d 24 fd ff ff}  //weight: 2, accuracy: High
        $x_2_7 = {73 37 8b 4d fc 81 c1 ?? ?? 00 08}  //weight: 2, accuracy: Low
        $x_2_8 = {c6 45 c8 56 c6 45 c9 69 c6 45 ca 72}  //weight: 2, accuracy: High
        $x_1_9 = {68 40 24 08 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_C_2147615334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.gen!C"
        threat_id = "2147615334"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 64 8b 78 01 33 c0 83 e8 02 c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {c1 eb 02 8d b7 ?? ?? ?? ?? 8b 14 1e 81 ea ?? ?? ?? ?? 2b fa c2 04 00 cc cc cc cc}  //weight: 1, accuracy: Low
        $x_1_3 = {c3 8d 47 30 8b 04 08 8b 40 0c 8b 40 1c 8b 00 8b 40 08 c3}  //weight: 1, accuracy: High
        $x_1_4 = {c1 e2 02 8d 88 ?? ?? ?? ?? 8b 1c 11 03 ca 83 eb 28 8d 95 ?? ?? ?? ?? 03 55 e4 89 1a 83 e9 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_C_2147615334_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.gen!C"
        threat_id = "2147615334"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 03 83 e9 04 7e 14 8d 3c 32 03 c7 03 45 fc}  //weight: 2, accuracy: High
        $x_1_2 = {5e ff d0 56 c3}  //weight: 1, accuracy: High
        $x_2_3 = {8b 84 0f 3c f4 ff ff 8b 40 0c 8b 40 1c 8b 00}  //weight: 2, accuracy: High
        $x_1_4 = {6c 64 72 74 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6c 64 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 6f 74 73 74 61 74 75 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {81 3a 43 6d 64 4c 75 14 8b 45 f4 81 78 04 69 6e 65 3a}  //weight: 1, accuracy: High
        $x_1_8 = {81 7d f8 45 4e 44 2e 74 14}  //weight: 1, accuracy: High
        $x_1_9 = {88 51 03 8b 45 08 03 45 fc 0f b6 48 01 83 f1}  //weight: 1, accuracy: High
        $x_1_10 = {0f be 51 01 83 fa 6e 75}  //weight: 1, accuracy: High
        $x_1_11 = {8b 48 50 51 8b 55 ?? 8b 42 34 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_2147616232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail"
        threat_id = "2147616232"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%s/" ascii //weight: 1
        $x_1_2 = "Mozilla/4.0 (compatible; MSIE 6.0" ascii //weight: 1
        $x_1_3 = {00 00 00 00 37 37 52 54}  //weight: 1, accuracy: High
        $x_1_4 = {00 2e 6b 7a 00}  //weight: 1, accuracy: High
        $x_5_5 = {88 01 0f b6 c3 33 d2 f7 f7 fe c3 8a [0-16] 88 41 01 80 79 01 65 58 75 17 f6 c3 08 74 12 0f b6 c3 6a 03 33 d2 5f f7 f7 8a}  //weight: 5, accuracy: Low
        $x_5_6 = {83 c4 04 69 c0 0d 66 19 00 8b 95 ?? ?? ?? ?? 8b 8c 95 ?? ?? ?? ?? 8d ?? ?? 5f f3 6e 3c 8b 85}  //weight: 5, accuracy: Low
        $x_5_7 = "qzlbtgrnkxsfdcmp" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_AF_2147617130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AF"
        threat_id = "2147617130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 03 83 e9 04 7e 14 8d 3c 32 03 c7 03 45 f8 8d 9b ?? ?? ?? ?? 03 de f7 da eb e5}  //weight: 2, accuracy: Low
        $x_1_2 = {f7 d9 41 6a 00 83 ca 05 51 ff 10 c9 c3}  //weight: 1, accuracy: High
        $x_1_3 = {81 c1 fa 0b 00 00 8d 45 ec 50 b8 30 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {01 03 2b ca 03 0b 51 ff 13}  //weight: 1, accuracy: High
        $x_1_5 = "ResetWriteWatch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_D_2147618078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.gen!D"
        threat_id = "2147618078"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b cf 49 3b cb 72 0a 8b c1 2b c3 8a 14 30 30 14 31}  //weight: 1, accuracy: High
        $x_1_2 = {80 38 4d 75 ?? 80 78 01 5a 75 ?? 80 78 50 69 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AJ_2147618365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AJ"
        threat_id = "2147618365"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\\\.\\ndis_ver2" ascii //weight: 10
        $x_10_2 = "netsh firewall set allowedprogram \"%s\" ENABLE" ascii //weight: 10
        $x_10_3 = {43 6f 6d 53 70 65 63 00 20 3e 3e 20 4e 55 4c 00 2f 63 20 64 65 6c 20}  //weight: 10, accuracy: High
        $x_10_4 = "GET /40" ascii //weight: 10
        $x_20_5 = {68 eb 00 00 00 50 e8 ?? ?? ff ff 6a 05 50 e8 ?? ?? ff ff 6a 05 68}  //weight: 20, accuracy: Low
        $x_20_6 = {80 78 50 69 8d 4e 0c 51 8d 4e 08 51 75 0b}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_AL_2147619811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AL"
        threat_id = "2147619811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3e 50 45 00 00 75 18 8d 4d 08 51 8d 4d fc 51 ff 75 0c 50 ff 15 ?? ?? ?? ?? 8b 45 08 89 46 58}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 75 37 a1 ?? ?? ?? ?? 56 56 56 56 56 57 56 6a 02 6a 01 53 56 ff 34 85}  //weight: 1, accuracy: Low
        $x_2_3 = "ndis_ver" ascii //weight: 2
        $x_1_4 = {b8 cc 11 00 00 ba 00 03 fe 7f ff 12}  //weight: 1, accuracy: High
        $x_1_5 = {be 3f 20 01 00 56 ff 75 fc ff d7 53 8d 45 e0}  //weight: 1, accuracy: High
        $x_1_6 = {64 a1 24 01 00 00 8b 40 44 8b f8 81 c7 c8 00 00 00 05 88 00 00 00 8b 00 bb ec 00 00 00 03 d8 8b 0b 81 f9 53 79 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_AN_2147622606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AN"
        threat_id = "2147622606"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 08 ff 30 14 08 48 75 f6 80 31}  //weight: 1, accuracy: High
        $x_1_2 = {74 1a 8d 4d e8 51 50 8b 46 04 05 ?? ?? ?? ?? 50 8b 46 fc 03 45 f8 50 ff 75 08 ff d7 8b 45 f4 0f b7 40 02 ff 45 fc 83 c6 28 39 45 fc 7c ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AO_2147624799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AO"
        threat_id = "2147624799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1b 81 f3 ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 75 09 8b 1d ?? ?? ?? ?? c6 03 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {53 83 29 05 50 6a 00 6a 00 ff 11 6a ff 50 ff 15 ?? ?? ?? ?? ff 24 24}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 08 66 33 d2 33 c0 8b ff 66 b8 01 10 66 48 66 81 3a 4d 5a 74 04 2b d0 eb f5}  //weight: 1, accuracy: High
        $x_1_4 = {05 e9 00 00 00 50 8b 45 e4 29 04 24 8f 45 f8 8d 45 fc 50 6a 04 ff 75 f4 ff 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AP_2147625119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AP"
        threat_id = "2147625119"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 38 4d 75 1f 80 78 01 5a 75 19}  //weight: 2, accuracy: High
        $x_2_2 = {6a 19 33 d2 59 f7 f1 80 c2 61 eb 13 3c 58}  //weight: 2, accuracy: High
        $x_1_3 = {66 83 7e 06 00 8d 7c 30 18 76 31 83 c7 14}  //weight: 1, accuracy: High
        $x_1_4 = {80 78 50 69}  //weight: 1, accuracy: High
        $x_1_5 = {80 78 51 7a 0f 94 c1 8b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_AP_2147625119_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AP"
        threat_id = "2147625119"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 1b 81 f3 ?? ?? ?? ?? 81 fb}  //weight: 2, accuracy: Low
        $x_1_2 = {25 00 00 ff ff 05 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b c0 ff 73 50}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 e2 fc}  //weight: 1, accuracy: High
        $x_1_5 = {31 03 83 c3 04}  //weight: 1, accuracy: High
        $x_2_6 = {66 b8 01 10 57 5f 66 48 66 81 3a 4d 5a}  //weight: 2, accuracy: High
        $x_2_7 = {be 93 a2 88 91 97 8c af 81 9d}  //weight: 2, accuracy: High
        $x_2_8 = {f2 df ee c1 c4 dc cd da fc c7 c3 cd c6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_AQ_2147626016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AQ"
        threat_id = "2147626016"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 64 a1 30 00 00 00 8f 40 08 b8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 03 8b ff 25 18 00 0f b6 1b 81 f3 ?? ?? ?? ?? 90 81 fb ?? ?? ?? ?? 75 09 8b 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AQ_2147626016_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AQ"
        threat_id = "2147626016"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 02 32 14 31 02 d1 47 3b fd 88 14 31 72 d3}  //weight: 1, accuracy: High
        $x_1_2 = {b9 19 00 00 00 f7 f1 80 c2 61 eb 1b 3c 58 75 1a}  //weight: 1, accuracy: High
        $x_1_3 = {8a 50 51 33 c9 80 fa 7a 0f 94 c1 8b c1}  //weight: 1, accuracy: High
        $x_1_4 = {74 20 80 78 50 69 75 1a}  //weight: 1, accuracy: High
        $x_1_5 = {80 38 4d 75 20 80 78 01 5a 75 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AS_2147626804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AS"
        threat_id = "2147626804"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 05 0c 30 10 09 74 00 00 00 [0-16] c7 05 ?? 30 10 09 00 40 00 00 [0-16] 64 a1 18 00 00 00 [0-10] 8b 40 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_AV_2147629138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AV"
        threat_id = "2147629138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b f1 7e 1b 8a 81 ?? ?? ?? ?? 84 c0 74 0c 3a c2 74 08 32 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {66 83 7e 06 00 0f b7 4e 14}  //weight: 1, accuracy: High
        $x_2_3 = {8a 47 01 47 84 c0 75 f8 8b 15 ?? ?? ?? ?? 8b 0b a0 ?? ?? ?? ?? 89 17 51 88 47 04 ff 15 ?? ?? ?? ?? 8b 03 6a 00 6a 00 8d 54 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_AW_2147632141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.AW"
        threat_id = "2147632141"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_2 = "\\System32\\svchost.exe" ascii //weight: 1
        $x_1_3 = "MaxUserPort" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" ascii //weight: 1
        $x_1_5 = "proxy1.ru:8080;proxy1.ru:80;proxy3.ru;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BA_2147632585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BA"
        threat_id = "2147632585"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 4d 75 05 38 50 01 74 0d 83 c1 01 83 e8 01 83 f9 64 72 e6}  //weight: 1, accuracy: High
        $x_1_2 = {3b f8 7d 09 83 c7 01 80 3c 37 3b 75 ea}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 02 32 14 31 02 d1 3b fd 88 14 31 72 cf}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 46 14 33 db 66 39 5e 06 8d 44 30 18 76}  //weight: 1, accuracy: High
        $x_1_5 = {80 7d 00 4d 0f 85 ?? ?? ?? ?? 80 7d 01 5a}  //weight: 1, accuracy: Low
        $x_1_6 = {2b f1 8a 01 84 c0 74 13 3c ?? 74 02 34 ?? 88 04 0e}  //weight: 1, accuracy: Low
        $x_1_7 = {ff d3 81 7c 24 10 5a 5a 5a 5a 74 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BB_2147632593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BB"
        threat_id = "2147632593"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a bf 68 ff cf ff ff f7 14 24 f7 54 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {88 04 31 86 c3 41 42 83 fa 04 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BC_2147634397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BC"
        threat_id = "2147634397"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 50 51 8b 55 fc 8b 42 34 50 8b 8d ?? ?? ?? ?? 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 55 fc 0f b6 02 83 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BE_2147642303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BE"
        threat_id = "2147642303"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f9 75 0f 95 c2 8b 45 0c 88 10 8b 4d 08 0f be 51 51 33 c0 83 fa 7a 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8d c0 fc ff ff 03 48 28 89 8d d8 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BE_2147642303_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BE"
        threat_id = "2147642303"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f0 05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 eb 08 00 00 00 00 00 00 00 00 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03 89 45 f0}  //weight: 1, accuracy: High
        $x_1_2 = {78 76 72 66 69 65 72 2e 64 6c 6c 00 42 65 67 69 6e 53 65 61 72 63 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BE_2147642303_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BE"
        threat_id = "2147642303"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 6a 18 ff 35 ?? ?? ?? ?? 03 01 06 02 e8 b8 ?? ?? ?? ?? ff d0 ff d7}  //weight: 10, accuracy: Low
        $x_1_2 = {81 c6 ca 01 00 00 b9 03 02 02 02 00 24 e2 25 ca 29 00 00 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {81 c6 ca 01 00 00 0e 00 b9 00 ?? ?? ?? c1 e9 02}  //weight: 1, accuracy: Low
        $x_1_4 = {ac 32 c3 aa f7 c1 01 00 00 00 74 ?? 85 c0 60}  //weight: 1, accuracy: Low
        $x_1_5 = {ad 33 85 f4 fc ff ff ab e2 db b8 00}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff ad 33 85 ?? ?? ff ff ab e2 0a 00 05 ?? ?? ?? ?? 50 8f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_BF_2147646227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BF"
        threat_id = "2147646227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 42 50 50 8b 4d fc 8b 51 34 52}  //weight: 1, accuracy: High
        $x_1_2 = {03 51 28 8b 45 14 89 10}  //weight: 1, accuracy: High
        $x_2_3 = {0f b6 42 03 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 41 03 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_BH_2147647625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BH"
        threat_id = "2147647625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff ff 00 00 81 f9 19 04 00 00 75 07 b8 01 00 00 00 eb 04 eb d1}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 42 03 83 f0 ?? 8b 4d 08 03 4d fc 88 41 03 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {81 3a 43 6d 64 4c 75 14 8b 45 ?? 81 78 04 69 6e 65 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BM_2147650461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BM"
        threat_id = "2147650461"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 ?? ?? ?? ?? 72 03 89 45 f8 e2 d5 59 8b 5d f8 ac 32 c3 aa f7 c1 01 00 00 00 74 0b 85 c0 60 6a 01 e8 e5 01 00 00 61}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 e8 bf 01 00 00 85 c0 75 15 6a 40 68 00 30 00 00 ff 76 50 6a 00 e8 aa 01 00 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BP_2147654218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BP"
        threat_id = "2147654218"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_2 = {b9 00 24 00 00 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 8b fe 51 b9 ?? ?? ?? ?? 8b 45 fc d1 c0 89 45 fc e2 f6 59 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 fc 05 01 01 01 00 05 01 01 01 01 89 45 fc 8b 5d fc ac 90 32 c3 90 aa f7 c1 01 00 00 00 74 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BS_2147659849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BS"
        threat_id = "2147659849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 ff ff 00 00 53 e8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 ?? 89 9d ?? ?? ff ff 43 e2 ?? 61 83 bd 03 00 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ff ff 00 00 53 e8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 ?? 89 5d ?? 43 e2 ?? 61 83 7d 03 00 74}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e9 02 8b 35 ?? ?? ?? ?? 81 c6 ca 01 00 00 8b fe 8b 85 ?? ?? ff ff bb ?? ?? ?? ?? 33 d2 81 c3 ?? ?? 00 00 f7 e3 05 ?? ?? ?? ?? 50 8f 85 ?? ?? ff ff ad 33 85 ?? ?? ff ff ab e2 d5}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 e9 02 8b 35 ?? ?? ?? ?? 81 c6 ca 01 00 00 8b fe 8b 45 ?? bb ?? ?? ?? ?? 33 d2 f7 e3 05 ?? ?? ?? ?? 89 45 ?? ad 33 45 ?? ab e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BT_2147659853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BT"
        threat_id = "2147659853"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 33 8b 4b 04 83 e9 08 83 c3 08 0f b7 03 a9 00 30 00 00 74 ?? 25 ff 0f 00 00 03 45 08 03 c6 29 10 83 c3 02 83 e9 02}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 fc e8 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 8b 46 28 [0-16] 03 45 fc [0-16] ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 75 08 03 76 3c (6a|eb) 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 55 f0}  //weight: 1, accuracy: Low
        $x_1_4 = "4130t5gio13485" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BV_2147664316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BV"
        threat_id = "2147664316"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 66 8b 4e 06 81 c6 f8 00 00 00 8b [0-5] 03 5e 0c 8b 45 08 03 46 14 ff 76 10 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 b9 30 00 00 00 f3 aa c7 [0-5] 30 00 00 00 c7 [0-5] 03 00 00 00 c7 [0-9] c7 [0-5] 00 00 00 00 c7 [0-5] 00 00 00 00 ff 35 ?? ?? ?? ?? 8f}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 ff 75 08 6a 00 6a 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00 68 [0-9] 68}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 7d fc 8b 77 24 03 75 f4 03 75 08 33 c0 66 8b 06 c1 e0 02 8b 75 fc 8b 76 1c 03 75 08 03 f0 8b 06 03 45 08 89 44 24 1c 61 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BW_2147669253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BW"
        threat_id = "2147669253"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 75 08 6a 00 6a 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 c6 ca 01 00 00 0e 00 b9 00 ?? ?? ?? c1 e9 02}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff ad 33 85 ?? ?? ff ff ab e2 0a 00 05 ?? ?? ?? ?? 50 8f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {04 83 e9 08 83 c3 08 0f b7 03 a9 00 30 00 00 74 ?? 25 ff 0f 00 00 03 (45|65) 08 03 c6 29 10 83 c3 02 83 e9 02}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 e3 10 b9 ff ff 00 00 53 e8 ?? 03 03 03 03 fe ff ff ff ff ff 01 00 00 (3d|97) ?? ?? ?? ?? 75 (03|06) 89 04 02 02 02 05 5d c4 5d d4 5d fc 9d 78 fe ff ff 43 e2 (ea|eb|ed) 61}  //weight: 1, accuracy: Low
        $x_1_6 = {58 bb 0d 66 19 00 33 d2 f7 e3 05 5f f3 6e 3c 89 45 ?? ad 33 45 ?? ab e2 e4 b8 00 (6a|6e) 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {33 c0 f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_BZ_2147679285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.BZ"
        threat_id = "2147679285"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 75 6e 5f 6d 65 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d f8 44 41 54 41 74 ?? 81 7d f8 43 4d 44 20 74 ?? 81 7d f8 45 4e 44 2e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_CB_2147680287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.CB"
        threat_id = "2147680287"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 8d 85 ?? ?? ff ff 50 8b 8d ?? ?? ff ff 51 ff 15 06 00 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e2 00 f0 00 00 c1 fa 0c 66 89 ?? ?? 8b 45 ?? 8b 4d ?? 0f bf 14 41 81 e2 ff 0f 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 50 ff 75 ?? c7 85 ?? ?? ff ff 07 00 01 00 ff 15 04 00 8d 85}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 54 50 08 66 83 3a 00 74 ?? 0f b7 12 8b fa c1 fa 0c 80 e2 0f 81 e7 ff 0f 00 00 80}  //weight: 1, accuracy: Low
        $x_10_5 = {66 be c5 ee 66 81 ee b6 ee 2b f1 2b fe eb e3}  //weight: 10, accuracy: High
        $x_10_6 = "\\system32\\svchost.exe" ascii //weight: 10
        $x_1_7 = {53 6a 04 5b be 00 02 00 80 39 5d ?? 75 05 be 80 33 80 80 57 57 6a 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cutwail_CC_2147681240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.CC"
        threat_id = "2147681240"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 07 c3 55 8b ec 83 c4 fc 8b 75 08 03 76 3c 6a 40 18 ec 77 db db 30 14 ff 76 50 02 34 ?? bd 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cutwail_CE_2147682617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cutwail.CE"
        threat_id = "2147682617"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c6 ca 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {89 85 9c fe ff ff b9 (80 1e|00 1f)}  //weight: 10, accuracy: Low
        $x_10_3 = {89 07 47 47 47 47 e2}  //weight: 10, accuracy: High
        $x_1_4 = "LoadImageW" ascii //weight: 1
        $x_1_5 = "GetObjectA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

