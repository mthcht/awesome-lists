rule TrojanDownloader_Win32_Farfli_A_2147639507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.A"
        threat_id = "2147639507"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "systeminfors" ascii //weight: 1
        $x_1_2 = "gbw|{g`z:qlq" ascii //weight: 1
        $x_1_3 = {c6 45 d8 31 c6 45 d9 14 c6 45 da 59 c6 45 db 29 c6 45 dc 29 c6 45 dd 5a c6 45 de 5d}  //weight: 1, accuracy: High
        $x_1_4 = {8a 04 02 30 01 46 3b (74|75) [0-3] 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_E_2147708702_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.E"
        threat_id = "2147708702"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 2c 44 c6 44 24 2d 6c c6 44 24 2e 6c c6 44 24 2f 46 c6 44 24 30 75 c6 44 24 31 55 c6 44 24 32 70 c6 44 24 33 67 c6 44 24 34 72 c6 44 24 35 61 c6 44 24 36 64 c6 44 24 37 72 c6 44 24 38 73 88 5c 24 39 51 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ab 05 00 00 25 ff 00 00 00 99 f7 f9 8b da 80 c3 3d e8 69 0a 00 00 8b 74 24 10 85 f6 76 10 8b 44 24 0c 8a 10 32 d3 02 d3 88 10 40 4e 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_J_2147717912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.J!bit"
        threat_id = "2147717912"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 11 80 c3 7a 88 1c 11 8b 55 ?? 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 08 8b 2f 8b da 81 e3 ?? ?? ?? ?? 03 dd 03 f3 81 e6 ?? ?? ?? ?? 79 08 4e 81 ce ?? ?? ?? ?? 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d 00 01 00 00 88 14 0e 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 8a 14 01 81 e3 ?? ?? ?? ?? 03 d3 81 e2 ?? ?? ?? ?? 79 ?? 4a 81 ca ?? ?? ?? ?? 42 8a 1c 02 8b 55 ?? 30 1c 16 8b 55 ?? 46 3b f2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_L_2147718324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.L!bit"
        threat_id = "2147718324"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 08 80 c2 ?? 88 14 08 8b 4c 24 08 8a 14 08 80 f2 ?? 88 14 08 40 3b c6 7c}  //weight: 1, accuracy: Low
        $x_2_2 = {81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72}  //weight: 2, accuracy: High
        $x_1_3 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Farfli_PH_2147720059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.PH!bit"
        threat_id = "2147720059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 00 56 8b f1 8b c8 74 0c 8d 9b 00 00 00 00 41 80 39 00 75 fa 8a 16 88 11 41 46 84 d2 75 f6 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 06 8b e8 81 e5 00 f0 ff ff 81 fd 00 30 00 00 75 0d 8b 6c 24 14 25 ff 0f 00 00 03 c7 01 28 8b 41 04 83 e8 08 42 d1 e8 83 c6 02 3b d0 72 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Farfli_PI_2147721523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.PI!bit"
        threat_id = "2147721523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0a 34 ?? 88 01 41 4e 75 f5}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 0f 12 00 00 99 b9 ?? ?? ?? ?? f7 f9 80 c2 ?? 88 54 34 ?? 46 81 fe ?? ?? ?? ?? 7c e3}  //weight: 1, accuracy: Low
        $x_1_3 = "%s\\%s\\dat\\%d%d" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_PJ_2147722534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.PJ!bit"
        threat_id = "2147722534"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 50 8d 45 ?? 50 c6 45 ?? 45 c6 45 ?? 52 c6 45 ?? 4e c6 45 ?? 45 c6 45 ?? 4c c6 45 ?? 33 c6 45 ?? 32}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 66 33 33 32 32 2e 6f 72 67 3a 36 35 35 30 30 2f 43 6f 6e 73 79 73 [0-9] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {32 30 32 2e 31 30 37 2e 32 30 34 2e 32 30 39 3a 36 35 35 30 30 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "C:\\Program Files\\AppPatch\\mysqld.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Farfli_PK_2147722647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.PK!bit"
        threat_id = "2147722647"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 c2 ?? 80 f2 ?? 88 14 01 41 3b ce 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 11 8a 18 88 19 41 3b c8 88 10 74 ?? 48 3b c8 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 06 8b c8 8b d0 c1 e9 ?? c1 ea ?? 83 e1 ?? 83 e2 ?? c1 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {75 c6 44 24 ?? 72 88 5c 24 1e c6 44 24 ?? 6d c6 44 24 ?? 6f c6 44 24 ?? 6e c6 44 24 ?? 2e c6 44 24 ?? 64 88 5c 24 24 88 5c 24 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_PN_2147724811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.PN!bit"
        threat_id = "2147724811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1}  //weight: 1, accuracy: Low
        $x_1_2 = "TCPConnectFloodThread.target" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 31 31 39 2e 32 34 39 2e 35 34 2e 31 31 33 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_PO_2147726557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.PO!bit"
        threat_id = "2147726557"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 c2 7a 80 f2 19 88 14 01 41 3b ce 7c ef}  //weight: 1, accuracy: High
        $x_1_2 = {4d c6 44 24 ?? 6f c6 44 24 ?? 7a c6 44 24 ?? 69 c6 84 24 ?? ?? ?? ?? 6c c6 84 24 ?? ?? ?? ?? 6c c6 84 24 ?? ?? ?? ?? 61 c6 84 24 ?? ?? ?? ?? 2f c6 84 24 ?? ?? ?? ?? 34 c6 84 24 ?? ?? ?? ?? 2e c6 84 24 ?? ?? ?? ?? 30 c6 84 24 ?? ?? ?? ?? 20 c6 84 24 ?? ?? ?? ?? 28 c6 84 24 ?? ?? ?? ?? 63}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 1c 8d 14 90 8b 04 0a 03 c1 5e 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Farfli_ARA_2147850737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Farfli.ARA!MTB"
        threat_id = "2147850737"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\shellcode\\Release\\shellcode.pdb" ascii //weight: 2
        $x_2_2 = {0f b6 06 53 50 e8 ?? ?? ?? ?? 88 06 83 c4 08 46 3b f7 75 ec}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

