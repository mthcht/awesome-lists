rule TrojanDownloader_Win32_Karagany_A_2147800837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.A"
        threat_id = "2147800837"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 1b 8a 55 0c 8b 45 08 02 d1 30 14 30 83 f9 03 7e 04 33 c9 eb 01 41 46 3b 75 10 7c e5 33 c0 40 5e 5d c3}  //weight: 3, accuracy: High
        $x_1_2 = "h|brxwkjs*" ascii //weight: 1
        $x_1_3 = "enbpuoatp<m`>rq" ascii //weight: 1
        $x_1_4 = {7a 7d 3f 69 75 6f 7b 75 3f 62 66 7f}  //weight: 1, accuracy: High
        $x_1_5 = {65 64 65 7f 7c 77 21 73 7e 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Karagany_I_2147800988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.I"
        threat_id = "2147800988"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "showthread.php?t=" ascii //weight: 2
        $x_1_2 = "cmd.exe /c ping -n 1 -w" ascii //weight: 1
        $x_2_3 = {80 3f 6b 74 07 80 3f 4b 74 02 eb e9 5f}  //weight: 2, accuracy: High
        $x_1_4 = {2a 00 00 00 eb 09 8b 55 ?? 83 c2 01 89 55 ?? 83 7d ?? 2f 73 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Karagany_L_2147801503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.L"
        threat_id = "2147801503"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<>.-abcdefgvwionlmkhtp" ascii //weight: 1
        $x_1_2 = {ff 45 f8 8b 4d f8 8a 09 84 c9 75 d3 83 65 f8 00 8b ce eb 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Karagany_L_2147801503_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.L"
        threat_id = "2147801503"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 8d 8e ac 04 00 00 51 6a 02 50 ff d7 6a 04 8d 86 b4 04 00 00 50 6a 06 ff b6 08 04 00 00 ff d7 6a 04}  //weight: 1, accuracy: High
        $x_1_2 = {89 48 08 c7 45 ?? b9 7b 59 42 c7 45 ?? 92 42 63 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Karagany_E_2147801535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.E"
        threat_id = "2147801535"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 d2 8d 84 50 81 5c fd ff 8a 14 0e 25 ff ff 0f 00 32 d0}  //weight: 1, accuracy: High
        $x_1_2 = {8d 04 40 8d 4c 41 45 8a 04 16 81 e1 ff ff 07 00 32 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Karagany_D_2147804108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.D"
        threat_id = "2147804108"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MlLrqtuhA3x0WmjwNM27" ascii //weight: 1
        $x_1_2 = {5c 6e 6f 72 6d 61 6c 69 7a 31 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Karagany_C_2147804149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.C"
        threat_id = "2147804149"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "M:\\flash\\other\\C++\\LiteLoader 1.1\\Release\\ftpplug" ascii //weight: 2
        $x_2_2 = {66 74 70 70 6c 75 67 32 2e 64 6c 6c 00 3f 49 6e 69 74}  //weight: 2, accuracy: High
        $x_1_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 02 00 2e 02 00 20 50 72 65 73 74 6f 2f}  //weight: 1, accuracy: Low
        $x_1_4 = "Referer: http://vkontakte.ru/login.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Karagany_H_2147804179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.H"
        threat_id = "2147804179"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 70 68 70 3f 66 3d 25 69 26 74 3d [0-4] 26 73 69 64 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = {64 8b 71 30 8b 76 0c 8b 76 1c 8b 46 08 89 45 fc 8b 7e 20 8b 36 80 3f 6b 74 07 80 3f 4b 74 02 eb e9 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Karagany_F_2147804202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.F"
        threat_id = "2147804202"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 02 00 2e 02 00 20 50 72 65 73 74 6f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {21 23 4c 44 52 ?? ?? ?? 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 e8 03 00 00 f7 f1 3d 58 02 00 00 76 ?? 68 b4 05 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Karagany_N_2147804208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.N"
        threat_id = "2147804208"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 02 03 f9 8b 77 0c 03 75 ?? 8a 0e 3a 4d ?? 75 ?? 8a 4e 03 3a 4d ?? 75 ?? 8a 4e 07}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0b 8b 75 ?? 88 0c 06 8d 48 01 8b 75 ?? 0f af 4e 04 8b 75 ?? 0f b6 34 ?? 33 ce 8b 75 ?? 88 0c 06 43 40 4a 75}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 f0 c6 45 ?? 43 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 54 c6 45 ?? 68 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 64 c6 45 ?? 00 8d 45 ?? 50 8b 45 ?? 50 ff 55}  //weight: 1, accuracy: Low
        $x_1_4 = {30 18 40 fe cb 84 db 75 02 b3 e5 e2 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Karagany_GEM_2147810540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Karagany.GEM!MTB"
        threat_id = "2147810540"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 14 01 ff 45 0c 88 10 8b 55 0c 40 3b 53 50 72 ef}  //weight: 10, accuracy: High
        $x_10_2 = {8d 7c 15 e4 0f b6 1f 33 d9 03 d8 42 88 1f 83 fa 07 72 ed}  //weight: 10, accuracy: High
        $x_10_3 = {8b 45 20 8b 80 c8 01 00 00 8b 00 33 c6 2b c7 8b 45 20 75 16 8b 4d 20 8b 89 cc 01 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

