rule TrojanDownloader_Win32_Pogolcil_A_2147721509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pogolcil.A"
        threat_id = "2147721509"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pogolcil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DownloadThread done!check file" wide //weight: 2
        $x_2_2 = "everything is done!delete me now" wide //weight: 2
        $x_2_3 = "fucking" wide //weight: 2
        $x_1_4 = "\\ProxyGate\\" wide //weight: 1
        $x_1_5 = "https://107.151.152.220:5658" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Pogolcil_D_2147722502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pogolcil.D!bit"
        threat_id = "2147722502"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pogolcil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 33 d2 b9 0a 00 00 00 f7 f1 b8 cd cc cc cc 83 c3 01 80 c2 30 88 54 33 ff f7 27 c1 ea 03 85 d2 89 17 77 db 8b 45 ec 8d 4b ff 8b d1 2b d0 83 fa 01 7c 22 0f b6 14 31 30 14 30 8a 14 30 30 14 31 8a 14 31 30 14 30 83 e9 01 83 c0 01 8b d1 2b d0 83 fa 01 7d de}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d d8 7a 7e 06 83 45 ec 02 eb 1f 8a 45 0f b2 0a f6 ea 8b 55 e4 8a c8 8b 45 ec 02 4c 10 02 80 e9 30 83 c0 03 88 4d 0f}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8d 8d 94 fe ff ff 51 52 ff d0 85 c0 89 85 84 fe ff ff 0f 84 a2 01 00 00 6a 79 68 4a e7 80 06 68 0d 0c 7e 1e 33 c0 68 df ae 25 07 68 75 1a 02 06 68 15 47 7d 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 78 69 74 50 72 6f 63 65 73 73 00 4c 6f 63 61 6c 20 41 70 70 57 69 7a 61 72 64 2d 47 65 6e 65 72 61 74 65 64 20 41 70 70 6c 69 63 61 74 69 6f 6e 73 00 00 44 42 00 00 49 4e 46 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pogolcil_F_2147723216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pogolcil.F!bit"
        threat_id = "2147723216"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pogolcil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "upgradeid=f561932c-0bef-41b9-9289-b7d5c099b86b" wide //weight: 1
        $x_1_2 = "fucking" wide //weight: 1
        $x_1_3 = "https://107.151.152.220:5658" wide //weight: 1
        $x_1_4 = {63 00 6c 00 6f 00 75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 65 00 74 00 2f 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "\\ProxyGate\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pogolcil_E_2147723315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pogolcil.E!bit"
        threat_id = "2147723315"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pogolcil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 ff 15 ?? ?? ?? 00 3d ?? ?? ?? ?? 74 ?? 8b c7 8d 0c 37 99 f7 7d ?? 8a 44 15 ?? 32 04 19 88 01 47 83 ff ?? 7c db}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 39 4a 6a 08 41 5b 8b c7 33 c6 d1 ee a8 01 74 06 81 f6 20 83 b8 ed d1 ef 83 eb 01 75 e9 85 d2 75 dd 5f 5b}  //weight: 1, accuracy: High
        $x_1_3 = {74 0b 80 38 4d 75 06 80 78 01 5a 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pogolcil_G_2147724782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pogolcil.G!bit"
        threat_id = "2147724782"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pogolcil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8d 0c 37 99 f7 bd ?? ?? ?? ff 8a 44 15 ?? 32 04 19 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 39 4a 6a 08 41 5b 8b c7 33 c6 d1 ee a8 01 74 06 81 f6 20 83 b8 ed d1 ef 83 eb 01 75 e9 85 d2 75 dd 5f 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

