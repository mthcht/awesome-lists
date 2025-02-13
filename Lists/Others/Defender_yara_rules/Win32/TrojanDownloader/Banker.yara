rule TrojanDownloader_Win32_Banker_2147628005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker"
        threat_id = "2147628005"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 56 8b f0 6a 00 a1 ?? ?? ?? ?? 8b 00 8b 40 30 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ff ff 00 00 b9 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b cb ba ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_2 = {72 61 66 61 73 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-16] 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6d 64 20 2f 6b 20 63 3a 5c 78 78 [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banker_D_2147630288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.D"
        threat_id = "2147630288"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 32 30 30 2e [0-10] 2f 2e 6d 6d 73 2f 6c 73 64 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "http://www.policiajudiciaria.pt/" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "URLMON.DLL" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banker_G_2147647569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.G"
        threat_id = "2147647569"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 c7 85 1c ff ff ff 01 00 00 00 c7 85 14 ff ff ff 02 00 00 00 ff d7 8b d0 8d 4d b8 ff d6 8d 55 84 8d 45 dc 8d 4d 94 52 50 c7 45 8c 04 00 00 00 c7 45 84 02 00 00 00 89 8d 1c ff ff ff c7 85 14 ff ff ff 08 40 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 95 54 ff ff ff 51 52 ff d7 50 8d 85 44 ff ff ff 8d 8d 34 ff ff ff 50 51 ff d7 8d 95 24 ff ff ff 50 52 ff 15 ?? ?? 40 00 8b d0 8d 4d a8 ff d6 8d 85 34 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {07 00 00 00 75 72 6c 6d 6f 6e 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banker_H_2147647875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.H"
        threat_id = "2147647875"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "dilma.gif" ascii //weight: 1
        $x_1_3 = "namorada.gif" ascii //weight: 1
        $x_1_4 = "69.64.43.129" ascii //weight: 1
        $x_1_5 = "ipadconf.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banker_J_2147649677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.J"
        threat_id = "2147649677"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 74 6f 74 61 6c 76 69 73 69 74 61 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 6f 6d 2f 70 63 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 63 6f 6e 74 61 64 6f 72 65 2f 65 6e 74 72 61 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = "208.115.238.109" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banker_J_2147649677_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.J"
        threat_id = "2147649677"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 73 74 69 2d 74 69 63 69 6e 6f 2e 63 68 2f [0-15] 2f 4f 70 65 6e 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_1_2 = "TCocaina" ascii //weight: 1
        $x_1_3 = "Foto Corrompida" ascii //weight: 1
        $x_1_4 = {72 65 67 73 76 72 33 32 20 2f 73 20 90 02 0f 5c 57 69 6e 65 74 77 6f 72 6b 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banker_K_2147649718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.K"
        threat_id = "2147649718"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 74 65 6e 64 69 6d 65 6e 74 6f 2d 70 65 73 73 6f 61 6c 2d 73 75 70 6f 72 74 65 2e 63 6f 6d 2f [0-21] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6d 64 20 2f 6b 20 63 3a 5c 57 69 6e 64 6f 77 73 5c [0-15] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = "level=\"requireAdministrator\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banker_N_2147653523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.N"
        threat_id = "2147653523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c0 b2 01 e8 ?? ?? ?? ?? 90 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8d 45 bc ba 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 bc e8 ?? ?? ?? ?? 50 8d 45 b8 b9 50 04 43 38 8b 15 ec a0 43 38 e8 ?? ?? ?? ?? 8b 45 b8}  //weight: 2, accuracy: Low
        $x_2_2 = {85 d2 0f 84 c7 00 00 00 85 c9 0f 84 30 fb ff ff 3b 10 0f 84 be 00 00 00 3b 08 74 0e 50 51 e8 ?? ?? ?? ?? 5a 58 e9}  //weight: 2, accuracy: Low
        $x_3_3 = "http://dl.dropbox.com/u/51009855/julix.xtz" ascii //weight: 3
        $x_1_4 = "3ad324.exe" ascii //weight: 1
        $x_1_5 = "8001s2.exe" ascii //weight: 1
        $x_1_6 = "ld3842.exe" ascii //weight: 1
        $x_1_7 = "text/html, */*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banker_R_2147658079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.R"
        threat_id = "2147658079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X1UN926H01979Y56FXD0" ascii //weight: 1
        $x_1_2 = "82zq8595HrzJMY0lP20" ascii //weight: 1
        $x_1_3 = "AutoMsnSecurity" ascii //weight: 1
        $x_1_4 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banker_AC_2147708177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banker.AC"
        threat_id = "2147708177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 59 76 61 52 36 6d [0-64] 2f 69 6e 69 63 69 6f [0-128] 52 75 6e 44 6c 6c 33 32 2e 65 78 65 [0-64] 2c 6f 6e 6c 69 66 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

