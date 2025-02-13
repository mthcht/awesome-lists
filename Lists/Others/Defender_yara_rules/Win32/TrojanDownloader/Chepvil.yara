rule TrojanDownloader_Win32_Chepvil_A_114401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.A"
        threat_id = "114401"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 fc 20 26 ce 6e e7 fa a6 b3 4e e7 b2 01 58 b1 d3 82 5d 2e 67 a9 fd 04 f3 23 5c ff 17 8b 36 57 91 73 38 f0 10 f3 24 e9 3a f0 fe 7d 85 40 72 7f e7 f9 cd b7 ce bc 23 e6 b3 02 5b 39 3d 6b 32 b8 b5 2b 3b 65 9d d6 85 b9 0a b3 08 d7 9a 91 ac 4f d1 d2 2a 6e 69 d8 fc 6c 60 1b ca fb 7f 41 51 4f 17 5a 07 26 ae 20 5c 7e c6 1d 2f e4 64 6e 3f a2 39 f1 12 d8 fd c6 c4 73 e2 78 37 1a ff 5d 2c 80 d0 c1 fd 10 0a de f1 62}  //weight: 1, accuracy: High
        $x_1_2 = {03 57 a1 bd 73 25 62 c0 b6 23 e6 f1 50 53 fc 5e 09 c1 0f 1f 3e c3 70 25 35 28 1c a5 42 76 87 a8 62 e8 a4 3c 1e 62 9a 15 51 a4 b6 ec 59 0d 45 2a 0f 92 8a 9f 0d}  //weight: 1, accuracy: High
        $x_1_3 = {d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 00 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 ff 35}  //weight: 1, accuracy: High
        $x_1_5 = {40 00 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_6 = {30 00 43 72 65 61 74 65 46 69 6c 65 41 00 46 00 43 72 65 61 74 65 54 68 72 65 61 64}  //weight: 1, accuracy: High
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "c:\\ntldr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_B_114403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.B"
        threat_id = "114403"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 eb 06 8d 3f d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 ?? ?? 83 c4 ec 53 56 57 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_A_114703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.gen!A"
        threat_id = "114703"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 af 8a 07 47 8b 0f 83 c7 04 57 51 6a 00 50 51 57 e8 ?? ?? 00 00 59 5f 0e 00 [0-2] 34 cc (68 ?? ?? ?? ??|bf ?? ?? ?? ??)}  //weight: 1, accuracy: Low
        $x_1_2 = {58 34 cc 68 ?? ?? ?? ?? 5f (68|b9) ?? ?? ?? ?? [0-1] f2 af [0-5] 8a 07 47 8b 0f 83 c7 04 57 51 6a 00 50 51 57 (e8 ?? ??|68 ?? ?? ?? ?? 68 ?? ?? ?? ??) 59 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_C_115901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.C"
        threat_id = "115901"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 59 8b 55 08 28 58 eb 07 8b ff d3 c9 90 33 c1 8a 0a 42 0a c9 75 f4 c9 c2 04 00 f9 83 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_B_127790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.gen!B"
        threat_id = "127790"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 04 00 00 00 4d 5a 50 45 8b 40 04 59 66 33 c0 8b 09 c3}  //weight: 2, accuracy: High
        $x_1_2 = {83 c0 0c a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 07 3d 68 74 74 70 75 16 ff 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Chepvil_C_139898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.gen!C"
        threat_id = "139898"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 54 8f fc 74 0f 83 c1 ff 75 f5 83 c6 04 ff 4d fc 75}  //weight: 1, accuracy: High
        $x_1_2 = {74 15 d1 87 cd 96 c0 65 0e 00 e8 ?? ?? ff ff 0b c0 0f 85 ?? ?? 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {ae 20 5c 7e c6 1d 2f e4 64 6e 3f a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_J_160693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.J"
        threat_id = "160693"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 03 0f b6 97 ?? ?? ?? ?? 31 d0 88 86}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 04 10 8b 55 ?? 0f b6 92 ?? ?? ?? ?? 31 d0 88 87}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 04 08 8b 4d ?? 0f b6 89 ?? ?? ?? ?? 31 c8 88 82}  //weight: 1, accuracy: Low
        $x_1_4 = {32 44 11 01 88 86 06 00 8a 04 10 8b 4d}  //weight: 1, accuracy: Low
        $x_4_5 = {80 3c 18 2f 75 [0-8] 8d (44|54) 18 01}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Chepvil_I_160695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.I"
        threat_id = "160695"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 db 75 25 31 db 43 80 bd f4 fb ff ff 4d 75 19 31 db 43 80 bd f5 fb ff ff 5a 75 0d}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 68 52 08 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_K_161561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.K"
        threat_id = "161561"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "/f/g.php" ascii //weight: 10
        $x_1_2 = {0f be 45 00 0f be 75 01 33 f0 b8 00 00 00 00 76 14}  //weight: 1, accuracy: High
        $x_1_3 = {0f be 40 01 8b 95 ?? fc ff ff 0f be 12 31 d0 89 85 ?? fc ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Chepvil_L_161562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.L"
        threat_id = "161562"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 db 75 25 31 db 43 80 bd d4 fb ff ff 4d 75 19 31 db 43 80 bd d5 fb ff ff 5a 75 0d c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 31 db 43 8d 04 ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {32 44 39 01 88 84 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 80 bc ?? ?? ?? ?? ?? 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chepvil_N_164532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chepvil.N"
        threat_id = "164532"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s/ftp/g.php" ascii //weight: 1
        $x_10_2 = {0f be 45 00 0f be 75 01 33 f0 b8 00 00 00 00 76 14}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

