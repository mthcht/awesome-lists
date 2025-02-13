rule TrojanDownloader_Win32_Matcash_A_2147597867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.A"
        threat_id = "2147597867"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\open\\command" ascii //weight: 1
        $x_2_2 = "mcboo.com/retadpu.exe" ascii //weight: 2
        $x_2_3 = "mcboo.com/updater.exe" ascii //weight: 2
        $x_1_4 = "name for %s" ascii //weight: 1
        $x_1_5 = "affID" ascii //weight: 1
        $x_1_6 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Matcash_B_2147597868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.B"
        threat_id = "2147597868"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_2 = {48 6f 6c 6d 65 73 2e 63 00 00 00 00 6d 2f 31 37 50}  //weight: 1, accuracy: High
        $x_1_3 = {48 6f 6c 00 6d 2f 31 37 50 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 77 72 73 2e 6d 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_5 = {5c 31 37 50 48 6f 6c 6d 65 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 6f 6e 74 65 6e 74 00 00 00 00 00 61 66 66 49 44}  //weight: 1, accuracy: High
        $x_1_7 = {61 74 00 00 75 6e 2e 62 00}  //weight: 1, accuracy: High
        $x_1_8 = {81 ec a4 00 00 00 89 8d 5c ff ff ff c7 85 74 ff ff ff 10 00 00 00 c6 85 78 ff ff ff}  //weight: 1, accuracy: High
        $x_1_9 = {6a 05 8d 85 ?? ?? ff ff 68 ?? ?? 40 00 50 ff d7 83 c4 0c 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Matcash_D_2147600886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.D"
        threat_id = "2147600886"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 47 55 49 44 3d 00 00 26 63 6f 6e 66 69 67 76 65 72 73 69 6f 6e 3d 00 26 76 65 72 73 69 6f 6e 3d}  //weight: 2, accuracy: High
        $x_1_2 = {64 6f 75 70 64 61 74 65 3d 25 64 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 30 5c 7e 4d 68 7a 00 25 30 38 58 00}  //weight: 1, accuracy: High
        $x_4_4 = {8d 85 64 d8 ff ff 50 ff 15 ?? ?? 41 00 6a ?? ff 15 ?? ?? 41 00 68 ?? ?? 41 00 8d 8d 64 d8 ff ff 51 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Matcash_E_2147605720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.E"
        threat_id = "2147605720"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WR\\nextupdate" ascii //weight: 1
        $x_1_2 = "WR\\version" ascii //weight: 1
        $x_1_3 = "wr.mc" ascii //weight: 1
        $x_1_4 = ".exe.tmp" ascii //weight: 1
        $x_2_5 = "paid" ascii //weight: 2
        $x_10_6 = "affID" ascii //weight: 10
        $x_10_7 = "finu" ascii //weight: 10
        $x_10_8 = {26 78 3d 00 26 69 3d 00 26 70 3d 00 26 63 6d 64 3d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Matcash_F_2147606985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.F"
        threat_id = "2147606985"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d7 6a ?? ff d6 8d 85 ?? ?? ff ff 68 ?? 77 40 00 50 ff d7 6a ?? ff d6 8d 85 ?? ?? ff ff 68 ?? 77 40 00 50 ff d7 6a ?? ff d6 8d 85 ?? ?? ff ff 68 ?? 77 40 00 50 ff d7 6a ?? ff d6 8d 85 ?? ?? ff ff 68 ?? 77 40 00 50 ff d7 6a ?? ff d6 8d 85 ?? ?? ff ff 68 ?? 77 40 00 50 ff d7 6a ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 79 6d 71 2e 61 1c 00 6d 2f 31 37 50 [0-5] 2e 63 6f [0-5] 6f 6f [0-5] 63 62 [0-5] 2e 77 72 73 2e 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Matcash_G_2147607789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.G"
        threat_id = "2147607789"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 00 [0-5] 70 3a 2f [0-21] 2e 6d [0-5] 63 62 [0-5] 6f [0-5] 6f [0-5] 2e [0-5] 63 6f [0-5] 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Matcash_H_2147611452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.H"
        threat_id = "2147611452"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 6c 00 00 73 2e 00 00 2e 77 72}  //weight: 1, accuracy: High
        $x_1_2 = {42 c9 21 d3 f2 b3 12 22 02 ab 08 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Matcash_K_2147616768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.K"
        threat_id = "2147616768"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wwlax.com/get_frst.php?" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = {64 00 00 65 6c 00 00 20 22 00 00 25 73 00 00 6f 70 65 6e 00 00 00 00 68 74 00 00 74 70 00 00 63 6c 61 73 73 00 00 00 2e 00 00 00 77 77 00 00 6c 61 00 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Matcash_A_2147622492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.gen!A"
        threat_id = "2147622492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_2_2 = {56 85 c0 74 12 8d 70 02 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c6 d1 f8 3b d8 7e 02 8b d8 b8 ff ff ff 7f 2b c3 3b c5 7d 0a 68 57 00 07 80 e8}  //weight: 2, accuracy: High
        $x_1_3 = "VideoBiosDate" wide //weight: 1
        $x_1_4 = "SystemBiosDate" wide //weight: 1
        $x_1_5 = "Advertisment" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Matcash_O_2147629970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Matcash.O"
        threat_id = "2147629970"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 68 b9 79 37 9e 68 ?? ?? ?? ?? 57 e8 ?? ?? ff ff 83 c4 0c 83 c7 08 4e 75 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fe 00 00 10 00 75 ?? 57 e8 ?? ?? ff ff [0-16] 3b c7 59 74 02 ff d0 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

