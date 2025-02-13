rule TrojanDownloader_Win32_Banload_2147549541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload"
        threat_id = "2147549541"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://ssl859.websiteseguro.com/downloadflash/dados/grdmody.jpg" ascii //weight: 1
        $x_1_2 = "https://ssl859.websiteseguro.com/downloadflash/dados/msnGRD.jpg" ascii //weight: 1
        $x_1_3 = "https://ssl859.websiteseguro.com/downloadflash/dados/Juliana.jpg" ascii //weight: 1
        $x_1_4 = "msnmsgasqwerts.txt" ascii //weight: 1
        $x_1_5 = "julianas.txt" ascii //weight: 1
        $x_1_6 = "armor.txt" ascii //weight: 1
        $x_1_7 = "http://br.youtube.com/watch?v=rdo7zb8xiv0&feature=related" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_2147549541_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload"
        threat_id = "2147549541"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d7 88 c1 c1 e8 08 8b 5d ?? d7 30 c1 c1 e8 08 8b 5d ?? d7 30 c1 c1 e8 08 8b 5d ?? d7}  //weight: 1, accuracy: Low
        $x_1_2 = {55 89 e5 50 8b 45 ?? c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_2147549541_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload"
        threat_id = "2147549541"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 40 ff 28 30 ff 01 00 fc f6 68 ff f4 1e 70 50 ff f3 ff 00 70 52 ff 28 10 ff 01 00 04 58 ff 80 0c 00 4a fd 69 20 ff fe 68 f0 fe 77 01 0a ?? 00 00 00 04 68 ff 28 30 ff 01 00 fb}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BH_2147576988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BH"
        threat_id = "2147576988"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = {33 c0 55 68 64 7e 40 00 64 ff 30 64 89 20 68 74 7e 40 00 6a 00 e8 10 ff ff ff 68 e8 03 00 00 e8 2a f9 ff ff b8}  //weight: 1, accuracy: High
        $x_10_4 = {ff ff 4b 75 e3 6a 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 b2 fe ff ff 6a 05 68 ?? ?? 40 00 e8 f2 c6 ff ff 33 c0 5a 59 59 64 89 10 68}  //weight: 10, accuracy: Low
        $x_1_5 = {40 00 64 ff 30 64 89 20 b8 ?? ?? 40 00 ?? ?? ?? 40 00 e8 ?? ?? ff ff 68 fe 00 00 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 8d}  //weight: 1, accuracy: Low
        $x_10_6 = {ff ff 50 6a 00 e8 f6 c6 ff ff 6a 05 8d 45 dc 8b 0d c0 a8 40 00 8b 15 ac a8 40 00 e8 f8 b8 ff ff 53 e8 fa c5 ff ff 33 c0 5a 59 59 64 89 10 68}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DC_2147593908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DC"
        threat_id = "2147593908"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 [0-32] 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-64] 5c 00 69 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 20 00 62 00 6f 00 6d 00 5c 00 50 00 72 00 6f 00 79 00 65 00 63 00 74 00 6f 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 50, accuracy: Low
        $x_10_2 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = {43 00 3a 00 5c 00 41 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 [0-16] 2e 00 63 00 6d 00 64 00}  //weight: 10, accuracy: Low
        $x_10_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-512] 2f 00 [0-32] 2e 00 6a 00 70 00 67 00}  //weight: 10, accuracy: Low
        $x_5_5 = "URLDownloadToFileA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DE_2147595972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DE"
        threat_id = "2147595972"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "windir" wide //weight: 1
        $x_1_3 = "\\msnmsgr.exe" wide //weight: 1
        $x_1_4 = ":\\Arquivos de programas\\" ascii //weight: 1
        $x_5_5 = {55 8b ec 83 ec 08 68 36 11 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 53 56 57 89 65 f8 c7 45 fc ?? 11 40 00 8b 55 0c 8b 3d 8c 10 40 00 33 f6 8d 4d e4 89 75 ec 89 75 e4 89 75 e0 89 75 dc 89 75 d8 ff d7 8b 55 10 8d 4d e0 ff d7 8b 45 e0 8b 3d a4 10 40 00 56 56 8d 4d d8 50 51 ff d7 8b 55 e4 50 8d 45 dc 52 50 ff d7 50 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DD_2147595973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DD"
        threat_id = "2147595973"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_5_2 = {64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 ?? ?? fb ff 50 8b 45 fc e8 ?? ?? fb ff 50 6a 00 e8 ?? ?? fd ff}  //weight: 5, accuracy: Low
        $x_5_3 = {83 2d b8 fb 44 00 01 73 28 b8 ?? c6 44 00 e8 ?? 75 fb ff e8 00 ff ff ff 68 ?? c6 44 00 e8 ?? 9e fb ff a3 bc fb 44 00 b8 ?? 23 44 00 e8 ?? 69 fc ff c3 00 00 54 61 73 6b 62 61 72 43 72 65 61 74 65 64 00}  //weight: 5, accuracy: Low
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DG_2147596418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DG"
        threat_id = "2147596418"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_10_2 = {55 8b ec b9 0a 00 00 00 6a 00 6a 00 49 75 f9 [0-4] 33 c0 55 68 ?? ?? 46 00 64 ff 30 64 89 20 6a 00 a1 08 88 46 00 8b 00 8b 40 30 50 e8 ?? ?? ?? ?? b8 ?? ?? 46 00 e8 ?? ?? ?? ?? 84 c0 0f 85 ?? 02 00 00 8d 45 fc ba ?? ?? 46 00 e8}  //weight: 10, accuracy: Low
        $x_10_3 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 10
        $x_5_4 = "URLDownloadToFileA" ascii //weight: 5
        $x_5_5 = "ftpTransfer" ascii //weight: 5
        $x_1_6 = "9E2AC300469A" ascii //weight: 1
        $x_1_7 = "B6043E8BD42B" ascii //weight: 1
        $x_1_8 = "D72CFB5FF9" ascii //weight: 1
        $x_1_9 = "E932FD5DFB" ascii //weight: 1
        $x_1_10 = "E025C210AE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DI_2147596461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DI"
        threat_id = "2147596461"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "ube-167.pop.com.br/repositorio/77687/meusite" ascii //weight: 1
        $x_1_3 = "201.22.164.181/mensagem" ascii //weight: 1
        $x_1_4 = "sixyahbi.exe" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BEJ_2147596576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEJ"
        threat_id = "2147596576"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6e 69 63 69 61 72 5c [0-21] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {73 74 61 72 74 75 70 5c [0-21] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 69 63 69 61 6c 69 7a 61 72 5c [0-21] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 95 e8 fe ff ff b8 ?? ?? 45 00 e8 ?? ?? ?? ?? 5a 0b d0 74 70 8d 4d fc 8b 83 08 03 00 00 8b 80 18 02 00 00 8b d6 8b 38 ff 57 0c 8d 85 f8 fe ff ff 8b 55 fc e8 ?? ?? ?? ?? 8b 83 0c 03 00 00 8b 80 18 02 00 00 8b 55 fc 8b 08 ff 51 54 40 75 35 8d 85 f8 fe ff ff e8 ?? ?? ?? ?? b8 ?? ?? 45 00 b2 01 e8 ?? ?? ?? ?? 8b 83 0c 03 00 00 8b 80 18 02 00 00 8b 55 fc 8b 08 ff 51 38 68 e8 03 00 00 e8 ?? ?? ?? ?? 46 ff 4d f8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DH_2147596608_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DH"
        threat_id = "2147596608"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "youtubevideos.notlong.com" ascii //weight: 1
        $x_1_2 = "que axei no YOU-TUBE heheh" ascii //weight: 1
        $x_1_3 = "Olha que video mais louca" ascii //weight: 1
        $x_1_4 = "Veja como ele e bom!!!" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DUN_2147596780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DUN"
        threat_id = "2147596780"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net stop SharedAccess" ascii //weight: 1
        $x_1_2 = ".txt" ascii //weight: 1
        $x_1_3 = "*.mbox" ascii //weight: 1
        $x_1_4 = "*.wab" ascii //weight: 1
        $x_1_5 = "*.mbx" ascii //weight: 1
        $x_1_6 = "*.eml" ascii //weight: 1
        $x_1_7 = "*.tbb" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = {33 ff 8d 45 e0 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc e8 ?? ?? fe ff 8b 4d e0 8d 45 e4 ba ?? ?? 41 00 e8 ?? ?? fe ff 8b 45 e4 e8 ?? ?? fe ff 89 45 f0 be 03 00 00 00 8d 45 d8 50 b9 02 00 00 00 8b d6 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DUN_2147596780_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DUN"
        threat_id = "2147596780"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 63 72 73 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 73 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 64 6f 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_10_4 = {64 ff 30 64 89 20 33 d2 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 45 e8 e8 ?? ?? ff ff ff 75 e8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ec ba 03 00 00 00 e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ff ff 84 c0 74 2c 8d 45 e0 e8 ?? ?? ff ff ff 75 e0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 e4 ba 03 00 00 00 e8 ?? ?? ff ff 8b 45 e4 33 d2 e8 ?? ?? ff ff 8d 45 d8 e8 ?? ?? ff ff ff 75 d8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 dc ba 03 00 00 00 e8 ?? ?? ff ff 8b 55 dc b8 ?? ?? ?? ?? e8 ?? ?? ff ff 84 c0 74 2c 8d 45 d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DK_2147597177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DK"
        threat_id = "2147597177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\" ascii //weight: 1
        $x_1_2 = "YouTube.com" ascii //weight: 1
        $x_1_3 = "Firewall\\DB\\" wide //weight: 1
        $x_1_4 = "NOD Protection" wide //weight: 1
        $x_10_5 = {55 8b ec 83 ec 0c 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 50 53 56 57 89 65 f4 c7 45 f8 ?? ?? ?? ?? 33 f6 89 75 fc 8b 45 08 50 8b 08 ff 51 04 68 ?? ?? ?? ?? 89 75 dc 89 75 d8 89 75 c4 89 75 c0 89 75 bc 89 75 b8 89 75 a8 e8 ?? ?? ?? ?? 66 85 c0 0f 85 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8d 55 a8 8d 4d c4 c7 45 b0 ?? ?? ?? ?? c7 45 a8 08 00 00 00 ff d7 8b 1d ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 4d d8 ff d3 ff 15 ?? ?? ?? ?? 8b 55 d8 56 56 8b 35 ?? ?? ?? ?? 8d 45 b8 52 50 ff d6 8d 4d c4 50 8d 55 c0 51 52 ff 15 ?? ?? ?? ?? 50 8d 45 bc 50 ff d6 50 6a 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4d b8 8d 55 d8 51 52}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DS_2147598267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DS"
        threat_id = "2147598267"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/install_count.html?id=svcshost&MAC=" ascii //weight: 1
        $x_1_2 = "/access_count.html?id=svcshost&MAC=" ascii //weight: 1
        $x_1_3 = "if KillProcessByFileName(%s) then" ascii //weight: 1
        $x_1_4 = "svcshost.exe" ascii //weight: 1
        $x_1_5 = "svcshost.sys" ascii //weight: 1
        $x_1_6 = "stop_agent.sys" ascii //weight: 1
        $x_10_7 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 54 66 55 70 64 61 74 65 72 2e 43 72 65 61 74 65 3b 00 00 00 ff ff ff ff 0c 00 00 00 73 76 63 73 68 6f 73 74 2e 65 78 65 00 00 00 00 ff ff ff ff 0f 00 00 00 69 66 20 25 73 20 3d 20 25 73 20 74 68 65 6e 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DT_2147598268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DT"
        threat_id = "2147598268"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/access_count.html?id=DemeterB&MAC=" ascii //weight: 1
        $x_1_2 = "/access_count.html?id=DemeterB&MAC" ascii //weight: 1
        $x_1_3 = "if KillProcessByFileName(%s) then" ascii //weight: 1
        $x_1_4 = "Demeter.sys" ascii //weight: 1
        $x_1_5 = "Demeter.exe" ascii //weight: 1
        $x_1_6 = "stop_agent.sys" ascii //weight: 1
        $x_10_7 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 54 66 55 70 64 61 74 65 72 2e 43 72 65 61 74 65 3b 00 00 00 ff ff ff ff 0b 00 00 00 44 65 6d 65 74 65 72 2e 65 78 65 00 ff ff ff ff 0f 00 00 00 69 66 20 25 73 20 3d 20 25 73 20 74 68 65 6e 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DV_2147598359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DV"
        threat_id = "2147598359"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-64] 2f [0-22] 2e (65|6a)}  //weight: 1, accuracy: Low
        $x_1_2 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
        $x_1_3 = {0f 00 00 00 63 3a 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6d 65 64 69 61 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DJ_2147598466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DJ"
        threat_id = "2147598466"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 42 41 43 4b 53 50 41 43 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {08 43 41 50 53 4c 4f 43 4b 00}  //weight: 1, accuracy: High
        $x_1_3 = {06 45 53 43 41 50 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {0a 53 43 52 4f 4c 4c 4c 4f 43 4b 00}  //weight: 1, accuracy: High
        $x_1_5 = {06 44 45 4c 45 54 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {05 45 4e 54 45 52 00}  //weight: 1, accuracy: High
        $x_1_7 = {04 48 4f 4d 45 00}  //weight: 1, accuracy: High
        $x_1_8 = {2d 20 43 6f 6e 76 65 72 73 61 00 00 ff ff ff ff 09 00 00 00 2d 20 43 65 6c 75 6c 61 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {8b 83 08 03 00 00 8b 80 18 02 00 00 8b d6 8b 38 ff 57 0c 8b ?? ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 8d 8d ?? ?? ff ff 8b 83 08 03 00 00 8b 80 18 02 00 00 8b d6 8b 38 ff 57 0c 8b ?? ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 0b d0 74 ?? 8d 4d fc 8b 83 08 03 00 00 8b 80 18 02 00 00 8b d6 8b 38 ff 57 0c 8d 85 ?? ?? ff ff 8b 55 fc e8 ?? ?? ?? ?? 8b 83 0c 03 00 00 8b 80 18 02 00 00 8b 55 fc 8b 08 ff 51 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DL_2147598467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DL"
        threat_id = "2147598467"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\regsvr32 /s" ascii //weight: 1
        $x_1_2 = "CheckExeSignatures" ascii //weight: 1
        $x_1_3 = "TaskbarCreated" ascii //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "\\Software\\Microsoft\\Internet Explorer\\Download" ascii //weight: 1
        $x_10_6 = {64 ff 30 64 89 20 ba 02 00 00 80 8b 45 fc e8 ?? ?? ?? ?? 8d 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b1 01 8b 55 f8 8b 45 fc e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? 00 00 ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? 00 00 ba 02 00 00 80 8b 45 fc e8 ?? ?? ?? ?? 8d 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b1 01 8b 55 f8 8b 45 fc e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? 00 00 ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? 00 00 8d 45 f0 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 f4 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 f4 68 ?? ?? ?? ?? 8d 45 ec ba 03 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DX_2147598484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DX"
        threat_id = "2147598484"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 30
        $x_10_2 = {e8 d2 6f fb ff 5f 5e 5b 5d c3 00 70 6c 75 67 69 6e 00 00 5c 61 2e 65 78 65 00 00 68 74 74 70 3a 2f 2f [0-64] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DY_2147598515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DY"
        threat_id = "2147598515"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 30
        $x_10_2 = {20 2d 20 43 6c 69 71 75 65 20 4f 4b 20 70 61 72 61 20 70 72 6f 73 73 65 67 75 69 72 21 [0-4] 63 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 68 74 74 70 3a 2f 2f}  //weight: 10, accuracy: Low
        $x_10_3 = {55 8b ec 83 c4 e8 33 c0 89 45 e8 89 45 ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 6a 00 b8}  //weight: 10, accuracy: Low
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_EA_2147598588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EA"
        threat_id = "2147598588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 50
        $x_50_2 = "URLDownloadToFileA" ascii //weight: 50
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\Isass.scr" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\SYSTEM32\\csrs.scr" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-32] 2f 49 73 61 73 73 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-32] 2f 63 73 72 73 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_7 = "C:\\WINDOWS\\SYSTEM32\\Update" ascii //weight: 1
        $x_1_8 = {6a 00 6a 00 8d 45 e8 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e8 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 8d 45 e4 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e4 50 8d 45 e0 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e0 5a e8 ?? ?? ?? ?? 8d 45 dc b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 dc 33 d2 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 00 8d 45 d8 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ED_2147599254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ED"
        threat_id = "2147599254"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 c4 f8 53 56 57 89 55 f8 89 45 fc 8b 45 fc e8 15 22 fb ff 8b 45 f8 e8 0d 22 fb ff 33 c0 55 68 5e 21 45 00 64 ff 30 64 89 20 33 c0 55 68 37 21 45 00 64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 f5 21 fb ff 50 8b 45 fc e8 ec 21 fb ff 50 6a 00 e8 68 40 fd ff 85 c0 0f 94 c3 33 c0 5a 59 59 64 89 10 eb 0c e9 60 14 fb ff 33 db e8 c1 17 fb ff 33 c0 5a 59 59 64 89 10 68 65 21 45 00 8d 45 f8 ba 02 00 00 00 e8 13 1d fb ff c3 e9 ed 16 fb ff eb eb 8b c3 5f 5e 5b 59 59 5d c3}  //weight: 10, accuracy: High
        $x_10_2 = {55 8b ec 81 c4 f4 f7 ff ff 89 55 f8 89 45 fc 8b 45 fc e8 75 21 fb ff 8b 45 f8 e8 6d 21 fb ff 33 c0 55 68 ef 21 45 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 f5 61 fb ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 e7 61 fb ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 0c 3f fd ff 33 c0 5a 59 59 64 89 10 68 f6 21 45 00 8d 45 f8 ba 02 00 00 00 e8 82 1c fb ff c3 e9 5c 16 fb ff eb eb 8b e5 5d c3}  //weight: 10, accuracy: High
        $x_1_3 = {16 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 70 6f 6f 6c (73|75) 76 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {18 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 00 00 00 00 ff ff ff ff ?? 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 43 6f 6e 74 61 63 74 73 4d 53 4e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 72 65 67 73 76 72 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 3a 5c 66 69 6c 65 2e 65 78 65 00 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_8 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6d 73 77 6f 72 64 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6c 6f 73 74 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_EF_2147599300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EF"
        threat_id = "2147599300"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 c4 f4 f7 ff ff 89 4d f8 89 55 fc 8b 45 fc e8 25 40 fb ff 8b 45 f8 e8 1d 40 fb ff 33 c0 55 68 3f 03 45 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 41 80 fb ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 33 80 fb ff 6a 03 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 10 5c fd ff 33 c0 5a 59 59 64 89 10 68 46 03 45 00 8d 45 f8 ba 02 00 00 00 e8 32 3b fb ff c3 e9 0c 35 fb ff eb eb 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {2e 6a 70 67 00 [0-255] 2e 6a 70 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 68 74 74 70 3a 2f 2f [0-255] 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 73 63 72 00 [0-255] 2e 73 63 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_DUR_2147599844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DUR"
        threat_id = "2147599844"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "401"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\" ascii //weight: 100
        $x_100_2 = "ShellExecuteA" ascii //weight: 100
        $x_100_3 = "URLDownloadToFileA" ascii //weight: 100
        $x_100_4 = "netsh firewall add allowedprogram" wide //weight: 100
        $x_1_5 = "executa.!!!" ascii //weight: 1
        $x_1_6 = "YouTube" ascii //weight: 1
        $x_1_7 = ".scr" wide //weight: 1
        $x_1_8 = ".pif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_EL_2147600084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EL"
        threat_id = "2147600084"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 72 71 75 69 76 6f 20 63 6f 72 72 6f 6d 70 69 64 6f 00 00 ff ff ff ff 12 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 78 70 31 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_2 = {68 74 74 70 3a 2f 2f 77 65 62 64 65 73 69 67 6e 2d 66 6f 78 2e 63 6f 6d 2f 62 6f 78 2f 50 72 69 76 38 5f 42 65 61 73 74 2e 65 78 65 00 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 78 70 31 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_3 = {55 52 4c 4d 4f 4e 2e 44 4c 4c 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_DUU_2147600196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.DUU"
        threat_id = "2147600196"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\system\\" wide //weight: 1
        $x_1_2 = "JSHNFIUY" wide //weight: 1
        $x_1_3 = "E9ING98Y" wide //weight: 1
        $x_1_4 = "30FK9884" wide //weight: 1
        $x_1_5 = "H097SH00" wide //weight: 1
        $x_1_6 = "9VHBW08H" wide //weight: 1
        $x_1_7 = "IP58454J" wide //weight: 1
        $x_1_8 = "OLPJDHUY" wide //weight: 1
        $x_1_9 = "JSIKJIK9524" wide //weight: 1
        $x_5_10 = {c7 45 fc 0c 00 00 00 8b 45 d8 50 8b 4d dc 51 ff 15 c4 10 40 00 c7 45 fc 0d 00 00 00 8d 55 d8 89 95 74 ff ff ff c7 85 6c ff ff ff 08 40 00 00 6a 02 8d 85 6c ff ff ff 50 ff 15 80 10 40 00 dd 9d 30 ff ff ff c7 45 fc 0e 00 00 00 c7 45 84 04 00 02 80 c7 85 7c ff ff ff 0a 00 00 00 c7 45 94 04 00 02 80 c7 45 8c 0a 00 00 00 c7 85 64 ff ff ff ?? ?? 40 00 c7 85 5c ff ff ff 08 00 00 00 8d 95 5c ff ff ff 8d 4d 9c ff 15 d8 10 40 00 c7 85 74 ff ff ff ?? ?? 40 00 c7 85 6c ff ff ff 08 00 00 00 8d 95 6c ff ff ff 8d 4d ac ff 15 d8 10 40 00 8d 8d 7c ff ff ff 51 8d 55 8c 52 8d 45 9c 50 6a 10 8d 4d ac 51 ff 15 4c 10 40 00 8d 95 7c ff ff ff}  //weight: 5, accuracy: Low
        $x_5_11 = {c7 85 68 ff ff ff 08 00 00 00 6a 00 8d 85 68 ff ff ff 50 ff 15 a0 10 40 00 8b d0 8d 4d d4 ff 15 e8 10 40 00 50 ff 15 30 10 40 00 8b d0 8d 4d d0 ff 15 e8 10 40 00 50 ff 15 3c 10 40 00 33 c9 85 c0 0f 9f c1 f7 d9 66 89 8d 4c ff ff ff 8d 55 d0 52 8d 45 d4 50 6a 02 ff 15 c0 10 40 00 83 c4 0c 8d 8d 68 ff ff ff ff 15 08 10 40 00 0f bf 8d 4c ff ff ff 85 c9 74 46 c7 45 fc 0c 00 00 00 8b 55 d8 52 8b 45 dc 50 ff 15 34 10 40 00 89 85 70 ff ff ff c7 85 68 ff ff ff 08 00 00 00 6a 02 8d 8d 68 ff ff ff 51 ff 15 80 10 40 00 dd 9d 50 ff ff ff 8d 8d 68 ff ff ff ff 15 08 10 40 00 9b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_EM_2147601384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EM"
        threat_id = "2147601384"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c0 ba 18 ca 44 00 b8 40 ca 44 00 e8 51 ff ff ff 84 c0 74 0c 6a 00 68 88 ca 44 00 e8 ad 95 fb ff 68 c4 09 00 00 e8 1f fa fb ff ba b0 ca 44 00 b8 d8 ca 44 00 e8 28 ff ff ff 84 c0 74 0c 6a 00 68 20 cb 44 00 e8 84 95 fb ff 6a 00 68 88 ca 44 00 e8 78 95 fb ff e8 13 73 fb ff}  //weight: 1, accuracy: High
        $x_1_2 = "http://idreamkid.com/cgi-bin/technote/board/shopkeeper2/member/k1.gif" ascii //weight: 1
        $x_1_3 = "c:\\windows\\system\\comands2.exe" ascii //weight: 1
        $x_1_4 = "http://idreamkid.com/cgi-bin/technote/board/shopkeeper2/member/k2.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KI_2147601465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KI"
        threat_id = "2147601465"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 16 3c 2b 72 46 3c 7a 77 42 33 c0 8a c3 80 7c 06 01 2b 72 37}  //weight: 5, accuracy: High
        $x_1_2 = {ff ff 0d 00 00 00 53 65 75 43 75 7a 61 6f 20 2e}  //weight: 1, accuracy: High
        $x_1_3 = {53 56 43 48 4f 53 54 00 ff ff ff ff 0b 00 00 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = ":INICIO" ascii //weight: 1
        $x_1_5 = "DELAPP ELSE GOTO DELBAT" ascii //weight: 1
        $x_1_6 = "SharedAPPs\"=-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_EN_2147601779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EN"
        threat_id = "2147601779"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "232"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MSVBVM60.DLL" ascii //weight: 100
        $x_100_2 = "BlackAgent 2.0" wide //weight: 100
        $x_10_3 = "\\blckx.exe" wide //weight: 10
        $x_10_4 = "\\server.exe" wide //weight: 10
        $x_10_5 = "\\Project1.vbp" wide //weight: 10
        $x_1_6 = "cmd /c taskkill /f /im winrar.exe " wide //weight: 1
        $x_1_7 = "cmd /c reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v msconfig /t REG_SZ /d" wide //weight: 1
        $x_1_8 = "cmd /c net stop \"SharedAccess\"" wide //weight: 1
        $x_1_9 = "cmd /c net stop \"wscsvc\"" wide //weight: 1
        $x_1_10 = "\\drivers\\svchost.exe" wide //weight: 1
        $x_1_11 = "\\drivers\\rundll32.exe" wide //weight: 1
        $x_1_12 = "\\drivers\\ctfmon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_C_2147602243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!C"
        threat_id = "2147602243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9}  //weight: 1, accuracy: High
        $x_1_2 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 1e e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 43 4e 75 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZBA_2147603275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZBA"
        threat_id = "2147603275"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 c0 74 0c 6a 00 68 ?? ?? ?? ?? e8 ad 95 fb ff 68 c4 09 00 00 e8 1f fa fb ff ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\windows\\system\\system.exe" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6b 72 65 68 65 72 2e 74 76 2f 64 68 65 73 2f 69 6d 61 67 65 73 2f 69 6d 61 67 65 73 2f [0-5] 2e 73 63 72}  //weight: 1, accuracy: Low
        $x_1_4 = "c:\\windows\\system\\comands2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ES_2147603633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ES"
        threat_id = "2147603633"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 77 77 77 2e 63 6f 72 72 65 69 6f 73 2e 63 6f 6d 2e 62 72 00 ff ff ff ff 33 00 00 00 68 74 74 70 3a 2f 2f 62 6f 78 73 74 72 2e 63 6f 6d 2f 66 69 6c 65 73 2f 31 33 39 35 39 33 39 5f 73 6a 69 67 69 2f 74 65 6c 65 67 72 61 6d 61 2e 65 78 65 00 ff ff ff ff 15 00 00 00 63 3a 5c 54 65 6d 70 5c 74 65 6c 65 67 72 61 6d 61 2e 65 78 65 00 00 00 00 00 00 00 43 3a 5c 54 65 6d 70 5c 74 65 6c 65 67 72 61 6d 61 2e 65 78 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AM_2147603635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AM"
        threat_id = "2147603635"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "type=\"multipart/alternative\";" ascii //weight: 1
        $x_1_2 = "MIME-Version" ascii //weight: 1
        $x_1_3 = "Subject" ascii //weight: 1
        $x_1_4 = "Reply-To" ascii //weight: 1
        $x_1_5 = "Newsgroups" ascii //weight: 1
        $x_1_6 = "MAIL FROM:<" ascii //weight: 1
        $x_1_7 = "RemoteMachineName" ascii //weight: 1
        $x_1_8 = "Proxy-Connection" ascii //weight: 1
        $x_1_9 = "SSLOpenSSL" ascii //weight: 1
        $x_10_10 = "http://www.mijafolu.com" ascii //weight: 10
        $x_10_11 = "TFBRADESCO" ascii //weight: 10
        $x_10_12 = "TFITAU" ascii //weight: 10
        $x_10_13 = "TFORM_AMARELO" ascii //weight: 10
        $x_10_14 = "TUBANTAB" ascii //weight: 10
        $x_10_15 = "C_A_R_T_A_OKeyPress" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_EW_2147605583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EW"
        threat_id = "2147605583"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ShellExecuteA" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_3 = {33 d2 a1 d4 0b 45 00 e8 e4 7d ff ff 33 d2 b8 ?? ?? ?? ?? e8 5c ff ff ff ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ad fe ff ff 84 c0 74 0c 33 d2 b8 ?? ?? ?? ?? e8 3d ff ff ff}  //weight: 1, accuracy: Low
        $x_10_4 = {81 c4 f4 f7 ff ff 89 55 f8 89 45 fc 8b 45 fc e8 15 67 fb ff 8b 45 f8 e8 0d 67 fb ff 33 c0 55 68 13 dc 44 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 f1 a5 fb ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 e3 a5 fb ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a}  //weight: 10, accuracy: High
        $x_1_5 = {00 6a 00 e8 b0 66 fd ff 33 c0 5a 59 59 64 89 10 68 1a dc 44 00 8d 45 f8 ba 02 00 00 00 e8 22 62 fb ff c3 e9 fc 5b fb ff eb eb 8b e5 5d c3 8b c0 33 d2 a1 d4 0b 45 00 e8}  //weight: 1, accuracy: High
        $x_10_6 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AQ_2147605819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQ"
        threat_id = "2147605819"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "RCPT TO" ascii //weight: 1
        $x_1_3 = "MAIL FROM" ascii //weight: 1
        $x_1_4 = "xoomer.alice.it" ascii //weight: 1
        $x_1_5 = "terra.com.br" ascii //weight: 1
        $x_1_6 = "login.live.com/ppsecure/sha1auth.srf" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "gethostbyname" ascii //weight: 1
        $x_1_9 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_FA_2147606504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.FA"
        threat_id = "2147606504"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "%s%s%s%s%s%s%s%s%s%s" ascii //weight: 1
        $x_1_3 = "*[+*/$SYHDUS-854231$\\*+]" ascii //weight: 1
        $x_1_4 = {89 45 bc c6 45 c0 0b 8b 45 f8 89 45 c4 c6 45 c8 0b 8b 45 f4 89 45 cc c6 45 d0 0b b8 bc 14 45 00 89 45 d4 c6 45 d8 0b 8b 45 f8 89 45 dc c6 45 e0 0b 8d 55 94 b9 09 00 00 00 b8 d8}  //weight: 1, accuracy: High
        $x_1_5 = {49 75 f9 51 53 56 57 89 55 f8 89 45 fc 8b 45 fc e8 93 24 fb ff 33 c0 55 68 84 1f 45 00 64 ff 30 64 89 20 8d 45 ec e8 cd 1f fb ff a1 88 3d 45 00 e8 83 22 fb ff 89 45 f4 33 ff 8d 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_EX_2147606662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.EX"
        threat_id = "2147606662"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = {50 6a ec a1 8c 60 45 00 53 e8 cd 21 fb ff ba c4 46 45 00 b8 e0 46 45 00 e8 f2 fe ff ff 84 c0 74 0c 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_F_2147607785_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!F"
        threat_id = "2147607785"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff ff ff ff 13 00 00 00 41 72 71 75 69 76 6f 20 63 6f 72 72 6f 6d 70 69 64 6f 2e 00 ff ff ff ff 1e 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 69 6d 67 6c 6f 67 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_2 = {68 74 74 70 3a 2f 2f [0-64] 2f [0-22] 2e (65|6a)}  //weight: 10, accuracy: Low
        $x_10_3 = {64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 e1 e8 f9 ff 50 8b 45 fc e8 d8 e8 f9 ff 50 6a 00 e8 9c 0b fc ff 85 c0 0f 94 c3 33 c0 5a 59 59 64 89 10}  //weight: 10, accuracy: High
        $x_1_4 = "Adobe Flash Player" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZBM_2147607865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZBM"
        threat_id = "2147607865"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 8b c3 e8 ?? ?? 00 00 3c 01 75 53 33 d2 8b 83 f0 02 00 00 e8 ?? ?? ?? ff b8 ?? ?? 45 00 e8 ?? ?? ?? ff 84 c0 75 38 ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 6a 01 68 ?? ?? 45 00 e8 ?? ?? ?? ff 68 dc 05 00 00 e8 ?? ?? ?? ff a1 ?? ?? 45 00 8b 00 e8 ?? ?? ff ff eb 05}  //weight: 1, accuracy: Low
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e [0-16] 52 75 6e [0-16] 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 [0-32] 2e 65 78 65 [0-16] 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e [0-37] 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 66 69 72 65 77 61 6c 6c 2e 63 70 6c [0-35] 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 5c [0-16] 2e 65 78 65 [0-16] 43 3a 5c 57 69 6e 64 6f 77 73 5c [0-16] 2e 65 78 65 [0-18] 2a 3a 45 6e 61 62 6c 65 64 3a [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AV_2147608454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AV"
        threat_id = "2147608454"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "URLDownloadtoFileA" ascii //weight: 10
        $x_10_3 = "ShellExecuteA" ascii //weight: 10
        $x_10_4 = {80 e3 0f b8 ?? ?? ?? ?? 0f b6 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc}  //weight: 10, accuracy: Low
        $x_10_5 = {8b 55 fc 0f b6 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 83 fe 0d 7e 05 be 01 00 00 00 47 ff 4d f4 75 ba}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_FI_2147610065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.FI"
        threat_id = "2147610065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 61 00 20 00 53 00 6f 00 20 00 61 00 73 00 20 00 69 00 70 00 61 00 6e 00 65 00 6d 00 61 00 20 00 74 00 65 00 6d 00 5c 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 61 00 70 00 61 00 72 00 69 00 7a 00 7a 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 6d 00 65 00 6e 00 73 00 61 00 67 00 65 00 6e 00 73 00 2e 00 68 00 74 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 69 00 6e 00 64 00 69 00 63 00 61 00 74 00 6f 00 65 00 73 00 63 00 6f 00 6c 00 61 00 61 00 6c 00 66 00 72 00 65 00 64 00 6f 00 70 00 68 00 64 00 2e 00 6b 00 69 00 74 00 2e 00 6e 00 65 00 74 00 2f 00 70 00 65 00 63 00 32 00 67 00 75 00 69 00 2e 00 6a 00 70 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_G_2147610131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!G"
        threat_id = "2147610131"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 6f 6e 66 69 67 65 78 2e 64 6c 6c 00 [0-3] 68 74 74 70 3a 2f 2f [0-48] 2f 63 6f 6e 66 69 67 [0-2] 2e 74 78 74 00}  //weight: 10, accuracy: Low
        $x_4_2 = {47 65 72 61 6c 00}  //weight: 4, accuracy: High
        $x_1_3 = {61 75 74 6f 6d 73 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 75 74 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 65 6e 73 61 67 65 6d 48 6f 74 6d 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 75 74 65 6e 74 69 63 61 63 61 6f 48 6f 74 6d 61 69 6c 00}  //weight: 1, accuracy: High
        $x_10_7 = {6a 00 6a 00 8d 85 ?? ?? ff ff e8 ?? ?? ?? ?? ff b5 ?? ?? ff ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_FL_2147610137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.FL"
        threat_id = "2147610137"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 70 72 65 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 72 65 65 77 65 62 74 6f 77 6e 2e 63 6f 6d 2f 77 65 6e 76 76 63 72 2f 69 70 6e 65 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {0d 80 00 00 00 50 6a ec a1 ?? ?? ?? 00 53 e8 ?? ?? ?? ?? ba 64 01 45 00 b8 88 01 45 00 e8 ?? ?? ?? ?? 84 c0 74 0c 6a 00 68 b8 01 45 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_J_2147611002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!J"
        threat_id = "2147611002"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 54 1a ff 2b d3 83 ea 3f e8 ?? ?? ff ff 8b 55 f4 8d 45 f8 e8 ?? ?? ff ff 43 4e 75 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "imglog.xml" ascii //weight: 1
        $x_1_3 = "orkutkut.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_FR_2147611016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.FR"
        threat_id = "2147611016"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 ?? ?? ?? ff 8b 55 f0 8d 45 f4 e8 ?? ?? ?? ff 46 4b 75 da}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 65 73 73 6f 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 77 77 2e 74 6e 77 6e 65 70 61 6c 2e 6f 72 67 2f 69 6d 61 67 65 73 2f 66 6c 6f 77 65 72 2e 6a 70 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_FW_2147611230_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.FW"
        threat_id = "2147611230"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|_we=23|_f=/" ascii //weight: 1
        $x_1_2 = "*:Enabled:Outlooks.exe" ascii //weight: 1
        $x_1_3 = "*:Enabled:xcom.exe" ascii //weight: 1
        $x_1_4 = "\\out\\Outlooks.exe" ascii //weight: 1
        $x_1_5 = "\\com\\wlcom.exe" ascii //weight: 1
        $x_1_6 = "\\com\\down.txt" ascii //weight: 1
        $x_1_7 = "urlterra_OnClick" ascii //weight: 1
        $x_1_8 = "senha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_FZ_2147611531_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.FZ"
        threat_id = "2147611531"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "benckyl.com/acesso.php" ascii //weight: 10
        $x_10_3 = "www.dinamicaltda.com.br/windows_installer.exe" ascii //weight: 10
        $x_10_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e [0-16] 53 74 61 72 74 20 50 61 67 65}  //weight: 10, accuracy: Low
        $x_10_5 = "UuidCreateSequential" ascii //weight: 10
        $x_1_6 = "computador=" ascii //weight: 1
        $x_1_7 = "usuario=" ascii //weight: 1
        $x_1_8 = "shd_fisico=" ascii //weight: 1
        $x_1_9 = "shd_firmware=" ascii //weight: 1
        $x_1_10 = "windir=" ascii //weight: 1
        $x_1_11 = "mac=" ascii //weight: 1
        $x_1_12 = "pag_inic=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZBV_2147611779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZBV"
        threat_id = "2147611779"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 65 74 75 70 2e 69 6e 69 [0-5] 68 74 74 70 3a 2f 2f 77 77 77 2e 77 65 62 66 6c 6f 72 61 2e 63 6f 2e 6b 72 2f 73 6c 6f 67 2f 73 6b 69 6e 2f 73 65 74 75 70 2e 69 6e 69}  //weight: 2, accuracy: Low
        $x_2_2 = "Documents and Settings\\All Users\\start menu\\programs\\startup\\winsys3.exe" ascii //weight: 2
        $x_2_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 77 69 6e 73 79 73 33 2e 65 78 65 00 00 57 69 6e 64 6f 77 73 20 58 50 00 00 57 69 6e 64 6f 77 73 20 32 30 30 30}  //weight: 2, accuracy: High
        $x_1_4 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_GI_2147614087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.GI"
        threat_id = "2147614087"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\WindowsDefender.exe" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 74 77 6f 78 69 73 2e 77 65 62 2e 63 65 64 61 6e 74 2e 63 6f 6d 2f [0-8] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_3 = "Visualizador de imagens e fax do Windows." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_GJ_2147614439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.GJ"
        threat_id = "2147614439"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 9f 47 fa ff 6a 05 68 ?? ?? ?? ?? e8 93 47 fa ff 6a 05 68 ?? ?? ?? ?? e8 87 47 fa ff 6a 05 68 ?? ?? ?? ?? e8 7b 47 fa ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 51 51 51 51 51 51 51 51 53 8b d8 33 c0}  //weight: 1, accuracy: High
        $x_1_3 = "http://discovirtual.terra.com.br/vdmain.shtml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_K_2147618056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!K"
        threat_id = "2147618056"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 03 47 eb 05 bf 01 00 00 00 a1 ?? ?? ?? ?? 33 db 8a 5c 38 ff 33 5d e8 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_GY_2147618458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.GY"
        threat_id = "2147618458"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff ff 10 00 00 00 39 38 33 34 39 32 42 38 44 32 36 46 45 35 30 37 00 00 00 00 ff ff ff ff 01 00 00 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 70 70 33 2e 67 69 66 [0-8] 6f 70 65 6e 00 00 00 00 ff ff ff ff ?? 00 00 00 [0-9] 2e 73 63 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_HH_2147621657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.HH"
        threat_id = "2147621657"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 3f 7b 73 6b 7d 74 ?? 8a 07 30 c8 28 e8 aa 4a 75}  //weight: 4, accuracy: Low
        $x_3_2 = {8b 45 fc 81 38 78 78 78 78 75 05 e9 ?? ?? 00 00}  //weight: 3, accuracy: Low
        $x_2_3 = {6a 00 6a 00 6a 06 e8 ?? ?? ?? ?? 50 68 ff 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 00 6a 07 e8 ?? ?? ?? ?? 50 68 ff 00 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = "%windir%\\Downloaded Program Files\\gb" ascii //weight: 1
        $x_1_5 = "%programfiles%\\GbPlugin" ascii //weight: 1
        $x_1_6 = "Folders to delete:" ascii //weight: 1
        $x_1_7 = "Files to delete:" ascii //weight: 1
        $x_1_8 = "svchost.scr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_HL_2147623050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.HL"
        threat_id = "2147623050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = {ff ff ff ff 07 00 00 00 5c 55 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_1_4 = {8d 85 f7 fb ff ff 8b 55 fc e8 ?? ?? ?? ?? 8d 85 f6 f7 ff ff 8b 55 f8 e8 ?? ?? ?? ?? 6a 03 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {68 fe 00 00 00 8d 85 ?? fe ff ff 50 e8 ?? ?? ?? ?? 8d 55 fc 8d 85 ?? fe ff ff e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 01 00 00 00 8d 45 [0-6] e8 ?? ?? ?? ?? 6a 00 6a 00 8d 85 ?? fe ff ff b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? ?? ?? 8b 85 ?? fe ff ff e8 ?? ?? ?? ?? 50 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 8d 85 ?? fe ff ff b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? ?? ?? 8b 85 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_N_2147623075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!N"
        threat_id = "2147623075"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "=_NextPart_2rfkindysadvnqw3nerasdf" ascii //weight: 1
        $x_1_3 = "Niste poze interesante cu tine in arhiva asta" ascii //weight: 1
        $n_10_4 = "EtiNet Windows Version " ascii //weight: -10
        $n_10_5 = "\\ANR Sistemas\\" ascii //weight: -10
        $n_10_6 = "Sistema - Everest" ascii //weight: -10
        $n_10_7 = "AC - Sistema de acessoria" ascii //weight: -10
        $n_10_8 = "SisPaf - Gerenciamento" ascii //weight: -10
        $n_10_9 = "TMotoBoySis00" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_HM_2147623448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.HM"
        threat_id = "2147623448"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 24 04 50 e8 ?? ?? ?? ?? 8b d3 8b c4 e8 ?? ?? ?? ?? 81 c4 94 00 00 00 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 e8 ?? ?? ff ff ff 75 f8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 fc ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 3f 33 d2 8b 83 f8 02 00 00 e8 ?? ?? ?? ?? 6a 01 8d 45 f0 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 f4 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_HP_2147624182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.HP"
        threat_id = "2147624182"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7c 2e 43 33 ff 8d 45 f8 50 8b 45 fc e8 ?? ?? ?? ff 8b d0 2b d7 b9 01 00 00 00 8b 45 fc e8 ?? ?? ?? ff 8b 55 f8 8b c6 e8 ?? ?? ?? ff 47 4b 75 d5}  //weight: 4, accuracy: Low
        $x_1_2 = "//:ptth" ascii //weight: 1
        $x_1_3 = "srevird" ascii //weight: 1
        $x_1_4 = "oviuqrA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZCD_2147624985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZCD"
        threat_id = "2147624985"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Security Center\" /v \"AntiVirusDisableNotify\" /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_2 = "/c REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Security Center\" /v \"FirewallDisableNotify\" /t REG_DWORD /d 0x00000001 /f" ascii //weight: 1
        $x_1_3 = {5c 6d 61 73 74 65 72 78 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f 38 37 2e 32 33 39 2e 32 32 2e 33 39 2f 77 75 78 70 2e 74 73 74 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/c REG ADD \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Update SP8\" /t REG_EXPAND_SZ /d \"%systemdir%\\Windows UpdateSP8.exe\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_HR_2147625221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.HR"
        threat_id = "2147625221"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 55 52 4c 4d 4f 4e 2e 44 4c 4c 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {84 c0 74 0c 33 d2 b8 ?? ?? 44 00 e8 3d ff ff ff ba ?? ?? 44 00 b8 ?? ?? 44 00 e8 ?? ?? ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 44 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZDB_2147626428_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZDB"
        threat_id = "2147626428"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be ff ff ff ff 0f bf c8 80 84 32 ?? ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 81 d9 ?? ?? ?? ?? 4d 80 cd ff bb ?? ?? ?? ?? b9 ?? ?? ?? ?? 81 ea 01 00 00 00 81 f7 ?? ?? ?? ?? be ?? ?? ?? ?? 8b dd 0f bf fb 81 fb ?? ?? ?? ?? 0f ?? ?? ff ff ff e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_IK_2147627133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.IK"
        threat_id = "2147627133"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "CreateProcess(nil,pchar(" ascii //weight: 1
        $x_1_3 = "$+r+$\\bin\\dcc32.exe\"" ascii //weight: 1
        $x_1_4 = "gethostbyname" ascii //weight: 1
        $x_1_5 = "Mozilla/3.0 (compatible; Indy Library)" ascii //weight: 1
        $x_1_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-32] 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f [0-16] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KJ_2147627936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KJ"
        threat_id = "2147627936"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 00 0a 00 6a 00 6a 00 68 ?? 00 00 00 6a ?? 6a 00 6a 00 ?? 6a 00 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? (6a 00|68 ?? ?? ?? ??) (6a 64|68 ?? ??) 6a 00 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb 0c}  //weight: 10, accuracy: Low
        $x_2_2 = {75 72 8b 16 8b c2 89 45 ec 8b 45 ec 85 c0 74 05 83 e8 04 8b 00 83 f8 03 7e 4e}  //weight: 2, accuracy: High
        $x_2_3 = {74 50 6a 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? ff 75 fc b8 ?? ?? ?? ?? 8d 55 ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? ba 03 00 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {7e 4f bf 01 00 00 00 8b 45 fc 0f b6 5c 38 ff 80 fb 5c 75 24 ff 75 f8 8d 45 ?? 8b d3 e8}  //weight: 2, accuracy: Low
        $x_2_5 = {50 68 00 04 00 00 8d 85 ?? ?? ff ff 50 56 e8 ?? ?? ?? ?? 6a 00 8d 95 ?? ?? ff ff 8b 4d ?? 8d 85 ?? ?? ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 7d ?? 00 75 c9}  //weight: 2, accuracy: Low
        $x_2_6 = "Z:\\Dropbox\\My Dropbox\\Projetos\\Javan" ascii //weight: 2
        $x_1_7 = ":INICIO" ascii //weight: 1
        $x_1_8 = "DELAPP ELSE GOTO DELBAT" ascii //weight: 1
        $x_1_9 = ":DELAPP" ascii //weight: 1
        $x_1_10 = ":DELBAT" ascii //weight: 1
        $x_1_11 = "SharedAPPs\"=-" ascii //weight: 1
        $x_1_12 = {4e 45 54 20 53 54 41 52 54 20 57 6d 69 41 70 73 72 76 33 32 00}  //weight: 1, accuracy: High
        $x_1_13 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_14 = {32 33 38 37 37 34 39 31 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_JD_2147628031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JD"
        threat_id = "2147628031"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isvchost.exe" ascii //weight: 1
        $x_1_2 = ":81/svc.php" ascii //weight: 1
        $x_1_3 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_JG_2147628118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JG"
        threat_id = "2147628118"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lllsss.info/cute.html" ascii //weight: 1
        $x_1_2 = "fifa.html" ascii //weight: 1
        $x_1_3 = "girl.html" ascii //weight: 1
        $x_1_4 = "kate.html" ascii //weight: 1
        $x_1_5 = "ieframe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_JN_2147628304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JN"
        threat_id = "2147628304"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "explorer.exe http://www.uol.com.br," wide //weight: 1
        $x_1_2 = {43 00 3a 00 5c 00 41 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 41 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 63 00 6f 00 6d 00 75 00 6e 00 73 00 5c 00 [0-10] 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 01 6a ff 6a 08 ff 15 ?? ?? 40 00 ba ?? ?? 40 00 8d 4d e8 ff 15 ?? ?? 40 00 8d 4d e8 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_JO_2147628313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JO"
        threat_id = "2147628313"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\CAIXA\\ZELEZIN\\Downloader\\Classes.pas" ascii //weight: 1
        $x_1_2 = {2f 70 6f 69 6e 74 2e ?? 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_3 = {48 6f 73 74 3a 20 6e 69 6b 6f 6c 79 [0-4] 2e 69 66 72 61 6e 63 65 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_JS_2147628374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JS"
        threat_id = "2147628374"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_2 = "mozilla/3.0 (compatible; indy library)" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 73 69 74 65 68 6f 73 74 74 2e 63 6f 6d 2f [0-8] 2e 72 61 72}  //weight: 1, accuracy: Low
        $x_1_4 = "C:\\windows\\inicialization.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_JT_2147628437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JT"
        threat_id = "2147628437"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xiexplorerr.exe" ascii //weight: 1
        $x_1_2 = "Enviador X\\Logar BB\\Puxador 2\\puxador.exe" ascii //weight: 1
        $x_1_3 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KE_2147628446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KE"
        threat_id = "2147628446"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 20 22 00 00 ff ff ff ff 04 00 00 00 22 20 2f 73 00 00 00 00 ff ff ff ff 11 00 00 00 20 2f 73 69 6c 65 6e 74 20 2f 69 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff 6a 00 6a 00 6a 00 6a 00 8d 95 dc fb ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 85 dc fb ff ff e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b f8 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 5d f4}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff ff ff 08 00 00 00 5c 6d 6b 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_4 = {ff ff ff ff 0e 00 00 00 49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00}  //weight: 2, accuracy: High
        $x_10_5 = "DeleteUrlCacheEntry" ascii //weight: 10
        $x_1_6 = "INFECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_JV_2147628768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.JV"
        threat_id = "2147628768"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Erro 404!" ascii //weight: 1
        $x_1_2 = "system32\\iexplorer.exe" ascii //weight: 1
        $x_1_3 = {45 78 70 6c 6f 72 65 72 00 68 74 74 70 3a 2f 2f 6e 61 72 75 74 6f 32 30 30 39 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KK_2147629012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KK"
        threat_id = "2147629012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&pi=LOAD_" ascii //weight: 1
        $x_1_2 = "attrib +R -A +S +H" ascii //weight: 1
        $x_1_3 = " | find \" 0 bytes\" > NUL" ascii //weight: 1
        $x_1_4 = "goto finalizar" ascii //weight: 1
        $x_1_5 = "C:\\pagefile.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KM_2147629034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KM"
        threat_id = "2147629034"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_2relrfksadv" ascii //weight: 1
        $x_1_2 = "Mensagens de erro" ascii //weight: 1
        $x_1_3 = "arquivobol" ascii //weight: 1
        $x_1_4 = "GbPlugin.exe" ascii //weight: 1
        $x_1_5 = "/Explorer.js" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KN_2147629036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KN"
        threat_id = "2147629036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 80 00 03 00 00 8b 80 20 02 00 00 ba ?? ?? 46 00 8b 08 ff 51 74 8b 45 fc 8b 80 04 03 00 00 8b 80 20 02 00 00 ba ?? ?? 46 00 8b 08 ff 51 74 6a 05 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KO_2147629094_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KO"
        threat_id = "2147629094"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERROR 10X020" ascii //weight: 1
        $x_1_2 = "problema persistir, contacte" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\Help\\csrsss.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_KV_2147629495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.KV"
        threat_id = "2147629495"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 45 59 3a 06 28 68 74 74 70 3a 2f 2f 77 77 77 2e 76 65 72 63 61 72 74 61 6f 2e 63 6f 6d 2f 49 6e 73 74 61 6c 6c 2f 25 41 30 2e 64 6c 6c 06 14 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 68 6f 6f 74 2e 64 6c 6c 06 04 57 41 42 3a}  //weight: 1, accuracy: High
        $x_1_2 = {72 75 6e 64 6c 6c 33 32 20 53 68 6f 6f 74 2e 64 6c 6c 2c 6e 65 74 77 6f 72 6b 00 00 07 54 49 64 48 54 54 50 0e 6f 70 65 6e 5f 79 6f 75 72 5f 6d 69 6e 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_LC_2147629841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.LC"
        threat_id = "2147629841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 83 f8 02 00 00 e8 ?? ?? ?? ?? 8b c6 e8 ?? ?? ?? ?? 68 f4 01 00 00 e8 ?? ?? ?? ?? 6a 00 8d 55 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 73 79 73 74 65 6d 33 32 5c 6d 64 6c 70 6c 69 74 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 79 73 74 65 6d 33 32 5c 6d 64 6c 78 6c 69 66 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 65 74 5f 77 61 62 73 2e 6a 70 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_LD_2147629842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.LD"
        threat_id = "2147629842"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 33 c0 8a c3 66 05 e7 00 0f 80 ?? ?? ?? ?? 0f bf c8 81 f9 ff 00 00 00 7e 0c 81 e9 ff 00 00 00 0f 80}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 91 f8 06 00 00 89 85 d8 fd ff ff 83 bd d8 fd ff ff 00 7d 23 68 f8 06 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5a 75 63 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_LE_2147629844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.LE"
        threat_id = "2147629844"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7c 5f 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 74 00 61 00 73 00 6b 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 00 74 00 69 00 76 00 61 00 64 00 6f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_LM_2147629984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.LM"
        threat_id = "2147629984"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 24 6a 10 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 8d 55 fc a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 8b 45 fc ba 06 00 00 00 e8 ?? ?? ?? ?? 6a 00 6a 00 8d 45 f8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 7a 55 70 74 50 69 74 75 2e 64 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_LQ_2147630178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.LQ"
        threat_id = "2147630178"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 70 65 72 66 74 65 6d 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 73 6e 6c 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 73 6e 73 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 74 74 74 00 00 00 00 ff ff ff ff 04 00 00 00 2e 64 64 64 00 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZDQ_2147631064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZDQ"
        threat_id = "2147631064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 42 52 41 20 20 45 4d 20 4f 55 54 52 4f 20 43 4f 4d 50 55 54 41 44 4f 52 21 21 00}  //weight: 2, accuracy: High
        $x_2_2 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 41 72 71 75 69 76 6f 73 20 63 6f 6d 75 6e 73 5c 2d (2e 2e|2e) 65 78 65}  //weight: 2, accuracy: Low
        $x_1_3 = {2f 31 31 31 31 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = "Kelberque" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_MI_2147631483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.MI"
        threat_id = "2147631483"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&btnG=Google+%CB%D1%CB%F7&aq=f&oq=" ascii //weight: 1
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 75 70 64 61 74 65 2e 65 78 65 00 00 00 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f [0-32] 2f 69 65 78 70 6c 65 72 6f 72 2f 75 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Microsoft\\Internet Explorer\\Quick Launch\\Internet Expleror.lnk" ascii //weight: 1
        $x_2_4 = {6a 05 6a 00 6a 01 8b 96 20 02 00 00 8b 83 78 05 00 00 b9 05 00 00 00 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_MJ_2147631484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.MJ"
        threat_id = "2147631484"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 38 ff 89 45 ?? b8 ?? ?? ?? ?? 0f b6 44 18 ff 89 45 ?? 8d 45 ?? 8b 55 ?? 2b 55}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 54 46 72 6d 53 70 6f 6f 6c 56 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_MM_2147631712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.MM"
        threat_id = "2147631712"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Recadastramento - Caixa" wide //weight: 10
        $x_10_2 = "MAC do cpmputador" wide //weight: 10
        $x_10_3 = "titulo=Infectado" wide //weight: 10
        $x_5_4 = "/data/temp/send.php" wide //weight: 5
        $x_2_5 = "Pass of card(4 digit) " wide //weight: 2
        $x_2_6 = "Serial do HD.............:" wide //weight: 2
        $x_2_7 = "Internet Pass____: " wide //weight: 2
        $x_2_8 = "Nome do Computador.......:" wide //weight: 2
        $x_1_9 = "Operation_____: " wide //weight: 1
        $x_1_10 = "Cont__________: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_MN_2147631715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.MN"
        threat_id = "2147631715"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 6f 67 64 61 66 65 73 74 61 32 30 31 30 2e 63 6f 6d 2f 4d 73 6e 6c 6f 67 65 2e 67 69 66 06}  //weight: 1, accuracy: High
        $x_1_2 = {2a 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 6f 67 64 61 66 65 73 74 61 32 30 31 30 2e 63 6f 6d 2f 4d 73 6e 6d 65 73 73 2e 67 69 66 06}  //weight: 1, accuracy: High
        $x_1_3 = {56 68 74 74 70 3a 2f 2f 6c 68 33 2e 67 67 70 68 74 2e 63 6f 6d 2f 5f 72 68 32 6f 33 57 52 32 36 4b 6b 2f 53 7a 43 7a 44 42 35 53 54 41 49 2f 41 41 41 41 41 41 41 41 41 42 63 2f 41 42 5f 67 71 4c 4b 33 62 67 30 2f 73 34 30 30 2f 69 6d 61 67 65 6d 31 2e 6a 70 67 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_NW_2147633746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.NW"
        threat_id = "2147633746"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".dominiotemporario.com/" ascii //weight: 1
        $x_1_2 = {68 98 3a 00 00 e8 ?? ?? ?? ff 8d ?? ?? 8b ?? ?? 8b ?? ?? e8 ?? ?? ?? ff 8b ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 6a 00 8d ?? ?? 8b ?? ?? 8b ?? ?? e8 ?? ?? ?? ff 8b ?? ?? e8 ?? ?? ?? ff 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "netbeans_db\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_OG_2147634609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OG"
        threat_id = "2147634609"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\new_send.vbp" wide //weight: 1
        $x_1_2 = {6a 2e 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 6a 63 8d 95 ?? ?? ff ff 52 ff 15 ?? ?? ?? ?? 6a 6f 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 6a 6d 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 6a 2e 8d 95 ?? ?? ff ff 52 ff 15 ?? ?? ?? ?? 6a 62 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 6a 72}  //weight: 1, accuracy: Low
        $x_2_3 = {6a 2e 51 ff d6 8d ?? ?? ?? ff ff 6a 43 52 ff d6 8d ?? ?? ?? ff ff 6a 65 50 ff d6 8d ?? ?? ?? ff ff 6a 6e 51 ff d6 8d ?? ?? ?? ff ff 6a 74 52 ff d6 8d ?? ?? ?? ff ff 6a 65 50 ff d6 8d ?? ?? ?? ff ff 6a 72 51 ff d6 8d ?? ?? ?? ff ff 6a 50 52 ff d6 8d ?? ?? ?? ff ff 6a 6c 50 ff d6 8d ?? ?? ?? ff ff 6a 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_OJ_2147634820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OJ"
        threat_id = "2147634820"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 6d 6b 69 6c 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f [0-37] 6d 73 6e 2e 70 6e 67}  //weight: 2, accuracy: Low
        $x_2_2 = {73 69 73 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f [0-37] 2e 70 6e 67}  //weight: 2, accuracy: Low
        $x_2_3 = {73 6d 6d 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f [0-37] 2e 70 6e 67}  //weight: 2, accuracy: Low
        $x_2_4 = {73 69 73 73 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f [0-37] 2e 70 6e 67}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_OL_2147635814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OL"
        threat_id = "2147635814"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 0e 8b 1f 38 d9 75 41 4a 74 17 38 fd 75 3a 4a 74 10 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 27}  //weight: 4, accuracy: High
        $x_2_2 = "LT9G4PN0j|cFMZi7IKxzmqeyJb6Yu2Xrf1EHvatkpOlwA58DWnhSCQRoV3dB" ascii //weight: 2
        $x_2_3 = "0zz7://" ascii //weight: 2
        $x_2_4 = {73 79 73 74 65 6d 33 32 5c [0-16] 2e 6a 70 67}  //weight: 2, accuracy: Low
        $x_2_5 = "0izMLjF.Km" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_OV_2147636423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OV"
        threat_id = "2147636423"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {70 75 6d 61 6e 65 77 2e 64 6c 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 10, accuracy: High
        $x_10_2 = {76 65 74 6e 65 77 2e 64 6c 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 10, accuracy: High
        $x_10_3 = {66 6c 61 73 68 62 61 63 6b 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 10, accuracy: High
        $x_10_4 = "\\Projetos\\Javan\\start\\pumanew\\pumanew.dpr" ascii //weight: 10
        $x_10_5 = "\\Projetos\\Javan\\start\\vetnew\\vetnew.dpr" ascii //weight: 10
        $x_10_6 = "\\Projetos\\Javan\\start\\pumanew_1\\flashback.dpr" ascii //weight: 10
        $x_1_7 = {89 45 e8 33 ff 8d 45 d8 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 f0 e8}  //weight: 1, accuracy: High
        $x_1_8 = "89B057EA1DDB0F0C75D4A2" ascii //weight: 1
        $x_1_9 = "9EFF6D9232E04D7ECA05331E36E20E3B" ascii //weight: 1
        $x_1_10 = {50 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 53 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_OV_2147636423_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OV"
        threat_id = "2147636423"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4a 08 33 c9 89 4a 0c 8d 7a 14 be ?? ?? ?? ?? b9 08 00 00 00 f3 a5 8d 7a 34 be ?? ?? ?? ?? b9 10 00 00 00 f3 a5 8d 7a 74 be ?? ?? ?? ?? b9 20 00 00 00 f3 a5 eb ?? 33 c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {66 6c 61 73 68 62 61 63 6b 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_OW_2147636437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OW"
        threat_id = "2147636437"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 32 e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 43 4e 75 dc}  //weight: 3, accuracy: Low
        $x_1_2 = "o arquivo" ascii //weight: 1
        $x_1_3 = "MsnHot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_OY_2147636451_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.OY"
        threat_id = "2147636451"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6a 70 67 00 [0-7] 43 3a 5c 41 72 71 75 69 76 6f [0-3] 64 65 20 70 72 6f 67 72 61 6d 61 [0-48] 2e 65 78 65 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_PA_2147636514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.PA"
        threat_id = "2147636514"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 64 6c 6c 00 [0-80] 2e 6a 70 67 00 [0-80] 2e 6a 70 67 00 [0-128] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "attrib +S +H" wide //weight: 1
        $x_1_3 = "regsvr32 /s " wide //weight: 1
        $x_1_4 = "\"c:\\windows\\system32\\jscript.dll\"" wide //weight: 1
        $x_1_5 = "\"c:\\windows\\system32\\vbscript.dll\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_PB_2147636523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.PB"
        threat_id = "2147636523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 3a 5c 43 6f 6d 6d 6f 6e 66 69 6c 65 73 5c 78 68 6f 73 74 ?? 2e 63 70 6c}  //weight: 2, accuracy: Low
        $x_1_2 = "M1-(%20%20)" ascii //weight: 1
        $x_1_3 = "contador.php?url=%20-|-%20" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_PC_2147636554_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.PC"
        threat_id = "2147636554"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 00 1f 00 2f 73 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 6f 64 75 6c 6f 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 72 61 6c 00 00 00 ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {61 75 74 6f 6d 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "ASDFERMVNZSFEWBNUFN3478R2ZBRRZSKJDFNIQREY89WQE7FN25GIN5RE67QBQE49832N47R89E1RFN7MFG5435436E98R7T98T6B8Q9RNF8D7TQE8RT79QREM" ascii //weight: 1
        $x_2_6 = {5c 6d 6f 64 33 32 5f 00 [0-10] 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_7 = {5c 64 6c 6c 33 32 5f 00 [0-10] 2e 64 6c 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_PE_2147636662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.PE"
        threat_id = "2147636662"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 95 f0 fb ff ff b9 00 04 00 00 8b c6 8b 18 ff 53 0c 8b d8 85 db 74 10 8d 95 f0 fb ff ff 8b cb 8b 45 f0 8b 38 ff 57 10 85 db 7f d4}  //weight: 4, accuracy: High
        $x_1_2 = "C:\\WINDOWS\\hunter" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\ieploreritau.js" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\ctfrmon.exe" ascii //weight: 1
        $x_1_5 = {2e 63 6f 6d 2e 62 72 2f [0-12] 2e 6a 73}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 63 6f 6d 2e 62 72 2f [0-12] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_PM_2147637532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.PM"
        threat_id = "2147637532"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 70 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? f5 65 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 66 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 69 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 6c 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 65 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 73 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? 60}  //weight: 1, accuracy: Low
        $x_2_2 = {f5 4f 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? f5 20 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 4c 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 6f 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 62 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 6f 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? 60}  //weight: 2, accuracy: Low
        $x_1_3 = {f5 68 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? f5 74 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 74 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 70 00 00 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? f5 3a 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZU_2147637592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZU"
        threat_id = "2147637592"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 63 00 72 00 [0-10] 2e 00 65 00 78 00 65 00 00 [0-22] 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-38] 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 [0-38] 2e 00 70 00 6e 00 67 00 00 [0-48] 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_QD_2147637828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QD"
        threat_id = "2147637828"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {52 00 65 00 63 00 65 00 69 00 74 00 61 00 ?? ?? 2e 00 64 00 63 00 78 00}  //weight: 2, accuracy: Low
        $x_1_2 = "desco.exe" wide //weight: 1
        $x_1_3 = "cssys.exe" wide //weight: 1
        $x_2_4 = {68 00 04 00 00 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 00 ba ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 75 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_QF_2147637844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QF"
        threat_id = "2147637844"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 76 00 74 00 68 00 65 00 6b 00 69 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 00 64 00 6b 00 74 00 61 00 73 00 6b 00 2e 00 65 00 78 00 65 00 4a 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 [0-15] 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 74 72 45 6d 61 69 6c 54 4f 4f 00 73 74 72 45 6d 61 69 6c 54 4f 4f 4f 00 00 00 00 73 74 72 53 65 6e 64 4d 61 69 6c 00 73 74 72 4c 6f 67 69 6e 53 65 6e 64 00 00 00 00 73 74 72 53 65 6e 68 61 53 65 6e 64 00 00 00 00 73 74 72 45 6d 61 69 6c 54 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_QG_2147637935_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QG"
        threat_id = "2147637935"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {63 6d 64 20 2f 6b 20 43 3a 5c 74 65 6d 70 5c 69 6d 67 ?? 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_2 = "/images/folle/bb.txt" wide //weight: 1
        $x_1_3 = "/images/folle/deco.txt" wide //weight: 1
        $x_1_4 = "/images/folle/cf.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_QH_2147637974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QH"
        threat_id = "2147637974"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6a 70 67 00 [0-2] 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c [0-19] 2e 63 70 6c 00 e0 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_QI_2147638062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QI"
        threat_id = "2147638062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b d8 66 83 eb 02 66 83 fb 03 76 40 8d 45 f0 50 0f b7 d3 b9 03 00 00 00 8b 45 fc e8}  //weight: 4, accuracy: High
        $x_1_2 = "modulo.txt" ascii //weight: 1
        $x_1_3 = "mshot.txt" ascii //weight: 1
        $x_1_4 = "htp.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_QI_2147638062_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QI"
        threat_id = "2147638062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 66 83 eb 02 66 83 fb 03 76 40 8d 45 f0 50 0f b7 d3 b9 03 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f0 e8 ?? ?? ?? ?? 8b f8 66 2b 7d fa 8d 45 ec 8b d7 e8 ?? ?? ?? ?? 8b 55 ec 8b c6 e8 ?? ?? ?? ?? 66 83 eb 03 66 83 fb 03 77 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {68 01 01 00 00 e8 ?? ?? ?? ?? 6a 00 6a 01 6a 02 e8 ?? ?? ?? ?? 89 45 f0 66 c7 85 48 fe ff ff 02 00 6a 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 b8 50 68 40 0d 03 00 8d 55 b0 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZV_2147638336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZV"
        threat_id = "2147638336"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 44 24 14 50 56 8d 8c 24 ?? ?? 00 00 51 53 ff 15 ?? ?? ?? ?? 8b 44 24 0c 6a 00 68 28 27 00 00 8d 94 24 ?? ?? 00 00 52 50 ff 15 ?? ?? ?? ?? 8b f0 85 f6 7f c9}  //weight: 1, accuracy: Low
        $x_1_2 = {61 72 71 75 69 76 6f 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_QP_2147638573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QP"
        threat_id = "2147638573"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 66 69 6c 65 2e 61 73 70 78 3f 66 69 6c 65 3d 31 26 67 65 6e 3d 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 40 0c 8b 00 8b 00 89 85 ?? ?? ?? ?? 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 45 ec 6a 10 8d 85 ?? ?? ?? ?? 50 8b 45 ec 50 e8 ?? ?? ?? ?? 40 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {68 01 04 00 00 8d 85 ?? ?? ?? ?? 50 8b 45 ec 50 e8 ?? ?? ?? ?? 89 45 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_QR_2147638631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.QR"
        threat_id = "2147638631"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f [0-15] 2f 66 6f 74 6f 73 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {44 69 72 65 63 74 58 73 2e 65 78 65 [0-5] 43 3a 5c 77 69 6e 64 6f 77 73 5c 6d 73 6e 67 72 73 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_RK_2147639475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.RK"
        threat_id = "2147639475"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 65 72 50 72 6f 66 69 6c 65 [0-64] ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 03 00 00 00 70 6e 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 83 c3 08 4e 0f 85 d3 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_RL_2147639503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.RL"
        threat_id = "2147639503"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 6b 20 63 3a 5c 6c 69 6e 6b [0-2] 2e 67 69 66 00 63 6d 64 20 2f 6b 20 63 3a 5c 6c 69 6e 6b [0-2] 2e 67 69 66 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 63 6f 6d 2e 62 72 2f [0-21] 2f 76 69 64 65 6f [0-2] 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_SC_2147640352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.SC"
        threat_id = "2147640352"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 7c 30 ff 8b 45 e0 0f b6 00 89 45 f4 8b 45 dc e8 ?? ?? ?? ?? 40 50 8d 45 dc b9 01 00 00 00 8b 15 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4}  //weight: 1, accuracy: Low
        $x_1_3 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
        $x_1_4 = {ff ff ff ff 03 00 00 00 d4 e0 e0 00 ff ff ff ff 04 00 00 00 dc a6 9b 9b 00 00 00 00 ff ff ff ff 03 00 00 00 e3 e3 e3 00 ff ff ff ff 02 00 00 00 9a e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_SG_2147640371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.SG"
        threat_id = "2147640371"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 3d 16 04 0f 85 05 00 e8}  //weight: 3, accuracy: Low
        $x_1_2 = {5c 52 75 6e [0-3] 22 20 2f 76 20 [0-3] 73 [0-3] 79 [0-3] 73 [0-10] 20 2f 64 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 5c 61 74 75 61 6c 69 7a 61 6e 64 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 65 6c 6c [0-2] 33 32 2e [0-3] 44 [0-2] 4c [0-2] 4c 2c 20 43 6f [0-2] 6e 74 [0-2] 72 [0-2] 6f [0-3] 6c 5f 52}  //weight: 1, accuracy: Low
        $x_2_5 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85}  //weight: 2, accuracy: Low
        $x_1_6 = {4e 65 74 20 [0-16] 41 75 74 6f 20 [0-32] 47 65 72 61 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ST_2147640632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ST"
        threat_id = "2147640632"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 45 b8 50 6a 00 6a 00 6a 30 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ff 50 6a 00 e8 ?? ?? ?? ff 83 f8 01}  //weight: 3, accuracy: Low
        $x_2_2 = {50 72 6f 63 65 73 73 53 69 6d 70 6c 65 00 44 6f 77 6e 00 45 78 74 72 61 69 72}  //weight: 2, accuracy: High
        $x_1_3 = "EDecompressionError" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_TD_2147641164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.TD"
        threat_id = "2147641164"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 75 53 74 72 74 44 77 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {0c 54 6d 72 49 6e 69 63 54 69 6d 65 72 13 00}  //weight: 1, accuracy: High
        $x_1_3 = {0c 54 6d 72 42 78 61 72 54 69 6d 65 72 13 00}  //weight: 1, accuracy: High
        $x_1_4 = {0c 54 6d 72 53 63 44 77 54 69 6d 65 72 13 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_TI_2147641252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.TI"
        threat_id = "2147641252"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\hotel.zip" ascii //weight: 1
        $x_1_2 = "545D451B44455C5D55525B125250226F2C2A3724352839242E3F222421263C3E377D212635302D287474672D2B2B09" ascii //weight: 1
        $x_1_3 = {ba 02 00 00 00 e8 3a 78 f9 ff 68 b8 0b 00 00 e8 c4 55 f9 ff 8d 4d bc 8b 83 f8 02 00 00 ba 00 18 47 00 e8 59 02 ff ff 8b 45 bc 33 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_UD_2147641996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.UD"
        threat_id = "2147641996"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-8] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_UG_2147642255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.UG"
        threat_id = "2147642255"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*h@t*@tp:*/*/" ascii //weight: 1
        $x_1_2 = "S*hell*|*32.D*@L*@L" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_UH_2147642262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.UH"
        threat_id = "2147642262"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Ulitizador:" wide //weight: 10
        $x_10_2 = "Cod. secreto:" wide //weight: 10
        $x_10_3 = "https://caixadirecta.cgd.pt" wide //weight: 10
        $x_1_4 = "200.13.244.245/cw-assenda/bin/es" wide //weight: 1
        $x_1_5 = "202.96.164.70/BBS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZAA_2147642699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZAA"
        threat_id = "2147642699"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\msdax86.dll" ascii //weight: 3
        $x_3_2 = "\\GbPlugin\\bb.gpc" ascii //weight: 3
        $x_3_3 = "/mastetred.com.br/new/more.php" ascii //weight: 3
        $x_1_4 = "/mwmw.com.br/" ascii //weight: 1
        $x_1_5 = "187.45.213.61/~frostfaa/" ascii //weight: 1
        $x_1_6 = "/joycilene.com/imagens/" ascii //weight: 1
        $x_1_7 = "/djwaltanl.dominiotemporario.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_UQ_2147642852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.UQ"
        threat_id = "2147642852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 2b fa 2b 7d ?? 8d 45 ?? 8b d7 e8 ?? ?? ?? ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 43 4e 75 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {01 75 1a 8d 45 ?? 8b 55 ?? 8b 92 ?? ?? ?? ?? 8b 4d ?? 8b 14 8a 8b 52 ?? e8 ?? ?? ?? ?? 83 7d ?? 02 75 2d}  //weight: 1, accuracy: Low
        $x_1_3 = {75 17 8b 45 ?? 8b 80 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 8b 55 ?? 8b 08 ff 51 ?? 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ?? 50 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 68 e8 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_UQ_2147642852_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.UQ"
        threat_id = "2147642852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 80 18 03 00 00 8b 55 f8 8b 04 90 8b 08 8b 45 fc 8b 90 20 03 00 00 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 e8 e8 ?? ?? ?? ?? 50 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 5e 5b 59 59 5d c3 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 01 00 00 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_Q_2147643108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!Q"
        threat_id = "2147643108"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 dc}  //weight: 4, accuracy: Low
        $x_2_2 = {0a 00 00 00 42 61 69 78 61 6e 64 6f 3a 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_UX_2147643206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.UX"
        threat_id = "2147643206"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Loadervb_Modulo" ascii //weight: 2
        $x_2_2 = "desenvolvimento\\loaders\\Loadervb" wide //weight: 2
        $x_1_3 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_4 = "OpenTextFile" wide //weight: 1
        $x_1_5 = "ProgramFiles" wide //weight: 1
        $x_1_6 = "regsvr32.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_VD_2147643346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VD"
        threat_id = "2147643346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 78 74 72 61 69 72 5f 44 4c 4c 00}  //weight: 5, accuracy: High
        $x_5_2 = {45 78 74 72 61 69 72 5f 44 6c 6c 47 72 61 6e 64 65 00}  //weight: 5, accuracy: High
        $x_5_3 = {45 78 74 72 61 69 72 5f 41 55 54 4f 00}  //weight: 5, accuracy: High
        $x_5_4 = {45 78 74 72 61 69 72 5f 55 50 44 00}  //weight: 5, accuracy: High
        $x_5_5 = {43 72 79 70 74 00}  //weight: 5, accuracy: High
        $x_5_6 = {43 72 69 61 52 65 67 69 73 74 72 6f 00}  //weight: 5, accuracy: High
        $x_1_7 = "regsvr32 -s" wide //weight: 1
        $x_1_8 = "regsvr32 /s /u" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_VM_2147643786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VM"
        threat_id = "2147643786"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 74 2d 63 61 6e 65 74 65 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 74 69 67 72 61 6f 2e 6a 70 67 00 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 4a 61 76 61 73 73 39 31 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {6d 74 2d 63 61 6e 65 74 65 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 73 65 63 64 65 6d 6f 2e 6a 70 67 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 4a 61 76 61 73 73 39 32 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_VN_2147643787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VN"
        threat_id = "2147643787"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 68 74 6d 6c [0-16] 43 3a 5c 57 49 4e 44 4f 57 53 [0-32] 66 69 6c 65 [0-2] 2e 65 78 65 [0-16] 6d 64 69 74 [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_VN_2147643787_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VN"
        threat_id = "2147643787"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 68 74 6d 6c 00 [0-16] 77 69 6e 64 6f 77 2e 6c 6f 63 61 74 69 6f 6e 00 [0-8] 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-32] 66 6c [0-2] 2e 65 78 65 [0-16] 6d 64 69 74 [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_VR_2147643953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VR"
        threat_id = "2147643953"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GerenciadorTimer" ascii //weight: 1
        $x_1_2 = "msconfigTimer" ascii //weight: 1
        $x_1_3 = {66 69 72 65 66 6f 78 ?? ?? ?? ?? ?? ?? ?? 55 72 6c 41 63 65 73 73 61 ?? ?? ?? ?? ?? ?? ?? 42 41 4e 53 41 4e ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 41 52 41 4e 4a 41 54 69 6d 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_VT_2147644060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VT"
        threat_id = "2147644060"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f3 01 eb 04 43 4e 75 b5 80 7d f3 00 75 0a 8b c7 8b 55 f4}  //weight: 1, accuracy: High
        $x_1_2 = {2e 6a 70 67 20 48 54 54 50 2f 31 2e 31 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_VV_2147644268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.VV"
        threat_id = "2147644268"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 00 73 00 2e 00 6a 00 75 00 6e 00 69 00 6f 00 72 00 31 00 39 00 38 00 38 00 2e 00 73 00 69 00 74 00 65 00 73 00 2e 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 [0-16] 2e 00 70 00 6e 00 67 00}  //weight: 10, accuracy: Low
        $x_1_2 = "novopuxador\\Project1.vbp" wide //weight: 1
        $x_1_3 = "\\system32\\Winlr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_WC_2147644534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.WC"
        threat_id = "2147644534"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b c6 33 c9 ba 40 00 00 00 e8 ?? ?? ?? ?? c6 06 33 88 5e 30 c6 46 0a 2a 8d 45 84 89 46 04 66 c7 46 08 3c 00 56 e8 ?? ?? ?? ?? 55 8b c3}  //weight: 1, accuracy: Low
        $x_1_2 = "58bbx.com" ascii //weight: 1
        $x_1_3 = {6c 6f 63 61 6c 69 70 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 6f 66 74 66 69 6c 65 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_WI_2147644655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.WI"
        threat_id = "2147644655"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8 ?? ?? ?? ff 8b 55 ec 8d 45 f4 e8 ?? ?? ?? ff 46 4b 75 d6}  //weight: 2, accuracy: Low
        $x_1_2 = {77 32 6a 00 68 80 00 00 00 6a 03 6a 00 8b c3 25 f0 00 00 00 c1 e8 04 8b 04 85 4c 71 46 00 50 8b 04 b5 40 71 46 00 50 8b c7 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {59 45 45 41 0b 1e 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_XA_2147645350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XA"
        threat_id = "2147645350"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 0f b6 54 32 ff 59 2a d1 f6 d2 e8 ?? ?? ?? ?? 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ?? 46 4b 75 d9}  //weight: 5, accuracy: Low
        $x_1_2 = {6c 6f 67 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "[LINK" ascii //weight: 1
        $x_1_4 = "[modulo" ascii //weight: 1
        $x_1_5 = "[Senha]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_XB_2147645352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XB"
        threat_id = "2147645352"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 68 61 76 65 00 00 00 ff ff ff ff 01 00 00 00 24 00 00 00 55 8b ec 81 c4 04 f0 ff ff 50 81 c4 e8 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_XG_2147645552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XG"
        threat_id = "2147645552"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 6d 73 6e 5c 61 72 71 75 69 76 6f 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 33 35 45 43 44 37 42 41 34 32 41 41 42 34 33 45 38 36 39 45 39 31 42 43 32 30 30 35 46 38 35 46 41 35 41 39 37 33 44 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 24 68 d0 07 00 00 e8 ?? ?? ?? ?? 6a 01 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 6a 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_XH_2147645553_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XH"
        threat_id = "2147645553"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Microsoft\\Security Center" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_4_3 = "Erro ao abrir o arquivo,ou o arquivo esta corrompido" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_XK_2147645651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XK"
        threat_id = "2147645651"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "TmrIncrTimer" ascii //weight: 3
        $x_2_2 = "GBxOrgm" ascii //weight: 2
        $x_2_3 = "TFrmUNS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_XO_2147645801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XO"
        threat_id = "2147645801"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "CBxFnlz" ascii //weight: 4
        $x_4_2 = "TmrVrfc" ascii //weight: 4
        $x_2_3 = "TFRMUNS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_XP_2147645829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XP"
        threat_id = "2147645829"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/temp/ss.com" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_3 = "XPPROBT2009" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_XP_2147645829_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XP"
        threat_id = "2147645829"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 77 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c [0-5] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Inteligencia Artificial ACT" ascii //weight: 1
        $x_1_3 = ":*:Enabled:Microsoft Windows Update Platform" ascii //weight: 1
        $x_1_4 = "internetbankingcaixamozillafirefox" ascii //weight: 1
        $x_1_5 = "www.grupobci.com.br/sistema/" ascii //weight: 1
        $x_1_6 = "Banco Santander Brasil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_XV_2147646140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.XV"
        threat_id = "2147646140"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".exe;.bat;.com;.cmd;" ascii //weight: 1
        $x_1_2 = "HideFileExt" ascii //weight: 1
        $x_1_3 = "AntiVirusDisable" ascii //weight: 1
        $x_1_4 = "AutoUpdateDisable" ascii //weight: 1
        $x_5_5 = {8b 45 e4 83 f8 08 77 59 ff 24 85 ?? ?? ?? 00 22 30}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_YA_2147646346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YA"
        threat_id = "2147646346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 69 6e 48 65 78 69 46 6f 72 6d [0-32] 57 69 6e 43 72 6f 73 6f 66 74 73}  //weight: 10, accuracy: Low
        $x_10_2 = {3c 00 50 00 61 00 73 00 73 00 3e 00 [0-240] 3c 00 2f 00 55 00 73 00 65 00 72 00 3e 00 [0-176] 55 00 73 00 75 00 61 00 72 00 69 00 6f 00 3a 00 [0-64] 2d 00 2d 00 2d 00 4d 00 73 00 6e 00 20 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 2d 00 2d 00 [0-208] 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00}  //weight: 10, accuracy: Low
        $x_1_3 = {72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 42 00 6f 00 64 00 79 00 [0-32] 77 00 72 00 69 00 74 00 65 00 [0-32] 53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_YC_2147646393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YC"
        threat_id = "2147646393"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "tristeza" wide //weight: 2
        $x_1_2 = {4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 69 6c 6c 50 72 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = {56 65 72 73 61 6f 57 69 6e 64 6f 77 73 00 20}  //weight: 1, accuracy: High
        $x_5_5 = {83 c4 20 66 85 f6 7d 0b 66 81 c6 00 01 0f 80 ?? ?? 00 00 8b 55 0c 8b 02 50 ff 15 ?? ?? ?? ?? 3b ?? 7d 13 66 8b 4d d0 66 83 c1 01}  //weight: 5, accuracy: Low
        $x_3_6 = {75 38 c7 45 fc ?? 00 00 00 68 30 75 00 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 e8 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? eb b7}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_YI_2147646573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YI"
        threat_id = "2147646573"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "QueIsso\\Project1.vbp" wide //weight: 1
        $x_1_2 = {2e 00 73 00 77 00 66 00 [0-16] 5c 00 77 00 69 00 6e 00 73 00 63 00 6b 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YJ_2147646588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YJ"
        threat_id = "2147646588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 3e 03 7c b5 80 3b 00 74 1f 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? ff 4d fc 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "Z:\\Projetos\\newhope\\cfg\\vdb\\lib\\VDB_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YJ_2147646588_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YJ"
        threat_id = "2147646588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Z:\\Projetos\\newhope\\cfg\\vdb\\lib\\VDB_IND.dpr" ascii //weight: 5
        $x_2_2 = "SVCHOST" wide //weight: 2
        $x_2_3 = "VDB_IND.cpl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YK_2147646674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YK"
        threat_id = "2147646674"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 76 67 75 69 78 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 32 00}  //weight: 1, accuracy: High
        $x_1_3 = "CurrentVersion\\Run\" /v avguix" ascii //weight: 1
        $x_1_4 = {83 7b 58 00 74 06 83 7b 5c 00 75 0c b2 03 8b c3 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YM_2147646777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YM"
        threat_id = "2147646777"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{enter} ja tinha visto estas fotos antes" ascii //weight: 1
        $x_1_2 = {f6 17 47 80 7f ff 00 75 ?? c1 f1 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YP_2147646938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YP"
        threat_id = "2147646938"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.2shared.com/file" ascii //weight: 1
        $x_1_2 = {73 61 6e 74 61 ?? ?? 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 61 70 65 ?? ?? 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_4_5 = {8b 55 f0 8b 83 5c 03 00 00 8b 80 20 02 00 00 8b 08 ff 51 74 b2 01 8b 83 48 03 00 00 e8}  //weight: 4, accuracy: High
        $x_4_6 = {8b 83 5c 03 00 00 8b 10 ff 92 e0 00 00 00 8b 83 5c 03 00 00 8b 80 20 02 00 00 ba}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_YT_2147647057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YT"
        threat_id = "2147647057"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 76 67 73 65 74 75 70 31 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 76 67 64 61 74 61 66 69 6c 65 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-20] 2f 69 6e 63 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = "gzy.jpg" ascii //weight: 1
        $x_1_5 = ":\\Windows\\System32\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YW_2147647155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YW"
        threat_id = "2147647155"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LdrGbpsv" ascii //weight: 2
        $x_2_2 = "BtnScClick" ascii //weight: 2
        $x_4_3 = "P.V.X.4.D.0.R. 3.4.89" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_YX_2147647236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.YX"
        threat_id = "2147647236"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "TUTFM_CADASTRO" wide //weight: 3
        $x_2_2 = "Tm_SystemTimer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZB_2147647284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZB"
        threat_id = "2147647284"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 8d 45 f8 50 b1 01 33 d2 b8 06 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b f0 46 8d 45 f0 8b 55 f8 8a 54 32 ff e8 d9 75 f9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZD_2147647433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZD"
        threat_id = "2147647433"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xservicex" ascii //weight: 1
        $x_1_2 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 0f 94 c3 33 c0 5a 59 59 64 89 10 eb 0c e9 ?? ?? ?? ?? 33 db e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZJ_2147647566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZJ"
        threat_id = "2147647566"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 72 65 64 69 72 65 63 74 [0-2] 2e 68 74 6d 6c}  //weight: 10, accuracy: Low
        $x_1_2 = "11.11.1.98%" ascii //weight: 1
        $x_1_3 = "110.200.1.4%" ascii //weight: 1
        $x_1_4 = "112.168.252.10%" ascii //weight: 1
        $x_1_5 = "12.11.1.98%" ascii //weight: 1
        $x_1_6 = "12.44.11.1%" ascii //weight: 1
        $x_1_7 = "120.200.1.4%" ascii //weight: 1
        $x_1_8 = "18.12.34.42%" ascii //weight: 1
        $x_1_9 = "19.23.11.30%" ascii //weight: 1
        $x_1_10 = "191.168.33.110%" ascii //weight: 1
        $x_1_11 = "194.168.33.110%" ascii //weight: 1
        $x_1_12 = "222.24.94.15%" ascii //weight: 1
        $x_1_13 = "61.142.83.227%" ascii //weight: 1
        $x_1_14 = "98.12.32.31%" ascii //weight: 1
        $x_1_15 = {43 3a 5c 54 45 4d 50 5c [0-8] 5c 65 6e 63 72 79 70 74 [0-6] 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZX_2147647697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZX"
        threat_id = "2147647697"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 f8 89 45 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff b2 01 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 75 0a b8 ?? ?? ?? ?? e8 ?? ?? ?? ff ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0 74 ?? 33 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 6d 00 61 00 7a 00 64 00 61 00 2e 00 65 00 78 00 65 00 50 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZY_2147647742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZY"
        threat_id = "2147647742"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_2_3 = {77 32 6a 00 68 80 00 00 00 6a 03 6a 00 8b c3 25 f0 00 00 00 c1 e8 04 8b 04 85 4c 71 46 00 50 8b 04 b5 40 71 46 00 50 8b c7 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_1_4 = "mozilla/3.0 (compatible; indy library)" ascii //weight: 1
        $x_1_5 = {66 74 70 54 72 61 6e 73 66 65 72 [0-2] 66 74 70 52 65 61 64 79}  //weight: 1, accuracy: Low
        $x_1_6 = {00 68 74 74 70 3a 2f 2f [0-255] 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZY_2147647742_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZY"
        threat_id = "2147647742"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {4b 85 db 7c ?? 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 50, accuracy: Low
        $x_50_2 = {8b f0 85 f6 7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 32 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 dc 8b c7 8b 55 f8}  //weight: 50, accuracy: Low
        $x_2_3 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 45 72 72 6f 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 2c 6f 75 20 6f}  //weight: 2, accuracy: High
        $x_2_4 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 46 61 6c 68 61 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 20 6f 75 20 6f}  //weight: 2, accuracy: High
        $x_2_5 = " ELSE (taskkill /F /IM rundll32.exe /T)" ascii //weight: 2
        $x_2_6 = {4d 61 74 74 65 72 4f 66 46 65 65 6c 69 6e 67 [0-16] 4b 45 50 4c 45 52 33 37}  //weight: 2, accuracy: Low
        $x_1_7 = {2e 65 78 65 00 ff ff ff ff 10 00 00 00 54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d}  //weight: 1, accuracy: High
        $x_1_8 = {2e 65 78 65 00 ff ff ff ff 19 00 00 00 43 6f 6e 66 69 67 5c 62 75 73 69 6e 65 73 73 69 74 61 6d 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_2_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZZ_2147647783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZZ"
        threat_id = "2147647783"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 45 72 72 6f 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 2c 6f 75 20 6f}  //weight: 1, accuracy: High
        $x_1_2 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 46 61 6c 68 61 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 20 6f 75 20 6f}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 [0-48] 10 00 00 00 55 61 63 44 69 73 61 62 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {69 65 78 70 6c 6f 72 65 72 [0-48] 70 6c 61 6e 65 74 68 6f 74}  //weight: 1, accuracy: Low
        $x_1_5 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 [0-48] 2d 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54}  //weight: 1, accuracy: Low
        $x_1_6 = {43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e [0-48] 69 65 78 70 6c 6f 72 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AAA_2147647785_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAA"
        threat_id = "2147647785"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4b 85 db 7c ?? 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d8 85 db 7e 2f be 01 00 00 00 8d 45 ec 8b ?? ?? ?? ?? 00 8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8 b3 db f9 ff 8b 55 ec 8d 45 f4 e8 ?? ?? ?? ff 46 4b 75 d6 8d 45 fc 8b 55 f4}  //weight: 10, accuracy: Low
        $x_2_3 = {ff 6a 00 a1 ?? ?? ?? 00 8b 00 8b 40 30 50 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff 68 ff ff 00 00 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d fc b2 01 a1 ?? ?? ?? ?? ?? ?? ?? ?? ff 8b d8 8d 55 f8 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff 8b 55 f8 8b cb 8b 86 f8 02 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_4 = "ALL:!ADH:RC4+RSA:" ascii //weight: 1
        $x_1_5 = "MensagemHotmail" ascii //weight: 1
        $x_1_6 = "Anti-Virus ENABLEnetsh" ascii //weight: 1
        $x_1_7 = {27 1d 00 00 00 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64}  //weight: 1, accuracy: High
        $x_1_8 = "msghot.dll" ascii //weight: 1
        $x_1_9 = {74 69 74 75 6c 6f 3d 00 ff ff ff ff 01}  //weight: 1, accuracy: High
        $x_1_10 = {1d 00 00 00 54 65 72 72 61 20 4d 61 69 6c 20 2d 20 43 61 69 78 61}  //weight: 1, accuracy: High
        $x_1_11 = {08 00 00 00 70 65 67 61 72 68 6f 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AAD_2147647908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAD"
        threat_id = "2147647908"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8}  //weight: 2, accuracy: High
        $x_2_2 = {46 4b 75 d6 8d 45 fc 8b 55 f4 e8}  //weight: 2, accuracy: High
        $x_2_3 = {85 c0 76 07 8b 45 fc 8a 18 eb 02 33 db 33 c0 5a 59 59 64 89 10 68}  //weight: 2, accuracy: High
        $x_2_4 = {63 6d 64 20 2f 6b 20 00 ff ff ff ff 09 00 00 00 3a 5c 77 69 6e 64 6f 77 73}  //weight: 2, accuracy: High
        $x_1_5 = "leocaloteiro" ascii //weight: 1
        $x_1_6 = "jvvr8--" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AAH_2147647946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAH"
        threat_id = "2147647946"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 6b 20 63 3a 5c 50 72 6f 6a 65 63 74 [0-6] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 73 69 74 65 (62 72|62 72 61 73) 2e (6e|6f) 2f [0-21] 2e 67 69 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AAH_2147647946_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAH"
        threat_id = "2147647946"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2E636F6D2E62722F" wide //weight: 1
        $x_1_2 = "2E6E65742F696D672F" wide //weight: 1
        $x_1_3 = "2E636F6D2F696D616765732F" wide //weight: 1
        $x_1_4 = "7777772E66726565776562746F776E2E636F6D" wide //weight: 1
        $x_1_5 = "Arquivos de programas\\AVG\\AVG10\\curruco.zip" wide //weight: 1
        $x_2_6 = "633A5C77696E646F77735C73797374656D33322F" wide //weight: 2
        $x_2_7 = "2E657865" wide //weight: 2
        $x_2_8 = "2E6A7067" wide //weight: 2
        $x_3_9 = {b8 01 00 00 00 66 03 c7 0f 80 be 00 00 00 8b f8 e9 ac fe ff ff 8b 4d 0c 8b 11 8d 4d d4 ff 15}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AAG_2147647947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAG"
        threat_id = "2147647947"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/karla-saraiva." ascii //weight: 1
        $x_1_2 = "http://gata" ascii //weight: 1
        $x_1_3 = {2f 67 61 74 61 90 01 05 2e 6a 70 67}  //weight: 1, accuracy: High
        $x_1_4 = "c:\\windows\\gata" ascii //weight: 1
        $x_3_5 = {63 6d 64 20 2f 6b 20 63 3a ?? 77 69 6e 64 6f 77 73 ?? 73 79 73 74 65 6d 33 32 [0-7] 2e 63 70 6c 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AAI_2147647948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAI"
        threat_id = "2147647948"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e0 c7 45 e8 01 00 00 00 8b 45 f8 8b 55 e8 0f b7 44 50 fe 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 ec 7d 03 46 eb 05 be 01 00 00 00 8b 45 f4 0f b7 44 70 fe 33 d8 8d 45 d0 50 89 5d d4 c6 45 d8 00 8d 55 d4 33 c9 b8 24 e7 40 00}  //weight: 1, accuracy: High
        $x_1_2 = "91D972D107478F326389C81C4CF166" wide //weight: 1
        $x_1_3 = {74 72 8b 55 fc 8d 85 a8 fd ff ff e8 ?? ?? ?? ?? ba 01 00 00 00 8d 85 a8 fd ff ff e8 ?? ?? ?? ?? ?? ?? ?? ?? ff 8d 45 f8 50 68 00 04 00 00 8d 85 a8 f9 ff ff 50 57 e8 ?? ?? ?? ff 6a 00 8d 95 a8 f9 ff ff 8b 4d f8 8d 85 a8 fd ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AAS_2147648075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAS"
        threat_id = "2147648075"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "btninxClick" ascii //weight: 2
        $x_2_2 = "btndoxClick" ascii //weight: 2
        $x_2_3 = "btnsexClick" ascii //weight: 2
        $x_1_4 = "unitcript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AAX_2147648226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AAX"
        threat_id = "2147648226"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff 68 e8 03 00 00 e8}  //weight: 10, accuracy: High
        $x_10_2 = {68 80 00 00 00 6a ec}  //weight: 10, accuracy: High
        $x_10_3 = {0b 41 32 32 32 71 ac a3 9d ff cb ca c9 ff d6 d6}  //weight: 10, accuracy: High
        $x_10_4 = {b2 a3 ff ff ee e4 ff fb e8 dc ff 6c 55 3e ff 25 24 24 29 18 18 17 1a 00}  //weight: 10, accuracy: High
        $x_5_5 = "TFrmDwPrgr" ascii //weight: 5
        $x_1_6 = "D.w.P.r.g.r." ascii //weight: 1
        $x_5_7 = "TFrmStrtDwn" ascii //weight: 5
        $x_1_8 = "S.t.r.t.D.w.n." ascii //weight: 1
        $x_5_9 = "TfrPlit" ascii //weight: 5
        $x_1_10 = "Plit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ABQ_2147648782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ABQ"
        threat_id = "2147648782"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6e 66 69 67 2d 63 61 63 68 65 2e 63 6f 6d 2f 69 65 [0-16] 75 74 6f 43 6f 6e 66 69 67 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_2 = {00 74 69 70 6f 3d}  //weight: 1, accuracy: High
        $x_1_3 = "www.emotionvirtual.com/index.php" ascii //weight: 1
        $x_1_4 = {2e 00 63 00 6f 00 6d 00 2f 00 42 00 72 00 46 00 6c 00 61 00 73 00 68 00 2f 00 54 00 65 00 41 00 64 00 6f 00 72 00 6f 00 2f 00 [0-10] 2e 00 73 00 77 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ABW_2147648923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ABW"
        threat_id = "2147648923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z:\\Projetos\\newhope\\cfg\\vdb\\lib\\VDB_" ascii //weight: 1
        $x_1_2 = {e8 61 a1 fe ff 8b f0 8b 7d fc 85 ff 74 05 83 ef 04 8b 3f 8b 45 fc e8 c7 b3 fe ff 8b d0 8b cf 8b 45 f0 8b 38 ff 57 10 6a 00 6a 00 8b 45 f0 e8 73 97 ff ff 80 7d f7 00 74 25 6a 01 8b 4d f8 8b d6 8b 45 f0 e8 9e f9 ff ff 6a 00 6a 00 8b c6 e8 53 97 ff ff 8b d3 8b c6 e8 e6 fd ff ff eb 23 8b d6 8b 45 f0 e8 36 fc ff ff 6a 00 6a 00 8b c6 e8 33 97 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ACD_2147649065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACD"
        threat_id = "2147649065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\Arquivos de programs\\AVG\\AVG" ascii //weight: 1
        $x_1_2 = "Software\\Classes\\Applications\\Nicrosoft.exe" ascii //weight: 1
        $x_1_3 = "\\Atalho_.pif" ascii //weight: 1
        $x_1_4 = {5c 69 6e 69 63 69 6f 2e 65 78 65 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 68 6f 6f 6b 44 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {4e 6f 41 73 49 6e 76 6f 6b 65 72 [0-10] 5c 4d 53 44 4f 53 2e 70 69 66}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 4d 53 44 4f 53 [0-10] 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 42 65 68 6f 6c 64 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ACH_2147649403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACH"
        threat_id = "2147649403"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 4d 31 30 04 00 49 4d 41 47}  //weight: 10, accuracy: Low
        $x_10_2 = {47 45 4d 36 03 00 49 4d 41}  //weight: 10, accuracy: Low
        $x_10_3 = "\\Dados de aplicativos\\" ascii //weight: 10
        $x_5_4 = {6e 66 44 6f 77 6e 02 00 43 6f}  //weight: 5, accuracy: Low
        $x_1_5 = {01 1b 44 6f 77 6e 6c 6f 61 64 65 72}  //weight: 1, accuracy: High
        $x_5_6 = {01 ba 49 65 78 70 6c 6f 72 65 72}  //weight: 5, accuracy: High
        $x_1_7 = "UpApp32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ACI_2147649468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACI"
        threat_id = "2147649468"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "YUQL23KL23DF90WI5E1JAS" wide //weight: 5
        $x_2_2 = "23D212D7040C087CAC2B6A8ABA13B341F" wide //weight: 2
        $x_2_3 = "B48DA044F457A29A8585D47AA8256386A2221546F26396C30445E" wide //weight: 2
        $x_2_4 = {2d 00 72 00 20 00 2d 00 74 00 20 00 30 00 30 00 20 00 2d 00 66 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {5c 00 74 00 69 00 70 00 6f 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = {5c 00 78 00 73 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 6d 00 73 00 67 00 73 00 31 00 31 00 31 00 31 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_7 = "CC54EC0125A6F52ED80D" wide //weight: 2
        $x_2_8 = {42 61 69 78 61 72 54 69 6d 65 72 16 00 46 6f 72 6d 43 72 65 61 74 65 ?? ?? ?? ?? ?? ?? ?? 54 69 6d 65 72}  //weight: 2, accuracy: Low
        $x_2_9 = {42 61 73 61 5f 17 00 53 65 6e 64 65 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 46 72 61 6d 65}  //weight: 2, accuracy: Low
        $x_2_10 = "0B2ACB11CD3A5AC268E9649D4A84C879A2E5094A33201D7F" wide //weight: 2
        $x_2_11 = "8FE44AD55C4E92B86BED7CAE5583C5B2A5EA60BF" wide //weight: 2
        $x_2_12 = "5D9C44E91662A29A5EE76CDE09459B" wide //weight: 2
        $x_2_13 = "BD7FA64AF603017B90369042F653F7" wide //weight: 2
        $x_2_14 = "85B47CA15EAAEA51FE409E50F855F9" wide //weight: 2
        $x_2_15 = "110A3EFD2DAEFD1A37973FE41540955F" wide //weight: 2
        $x_2_16 = "\\showwindowsbbb1.exe" wide //weight: 2
        $x_2_17 = "20D113D60B4CB5AF92389C5038A324DA0050819E4" wide //weight: 2
        $x_2_18 = "0829C86C90F81B0134992214C01BB144E078AF2EEB0" wide //weight: 2
        $x_1_19 = {31 45 d8 8d 45 ?? 50 8b 45 d8 89 45 ?? c6 45 ?? 00 8d 55 0b 00 8b 45 e0 8b 55 ec 0f b7 44 50 fe}  //weight: 1, accuracy: Low
        $x_1_20 = {70 fe 33 d8 8d 45 ?? 50 89 0b 00 be 01 00 00 00 8b ?? ?? 0f b7 44}  //weight: 1, accuracy: Low
        $n_5_21 = "Spyware Browser" wide //weight: -5
        $n_5_22 = "engenhosoftware.com" ascii //weight: -5
        $n_100_23 = "Central de Suporte ao SACS" wide //weight: -100
        $n_100_24 = "Embarcadero Technologies Inc." wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ACJ_2147649483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACJ"
        threat_id = "2147649483"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".##j#p#g" ascii //weight: 1
        $x_1_2 = "#c:#\\#w#i#nt#x#3#2#\\#" ascii //weight: 1
        $x_1_3 = "Cu#rre#ntVer#si#on\\Ru#n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ACM_2147649556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACM"
        threat_id = "2147649556"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 75 61 6c 64 6f 2e 65 78 65 [0-16] 63 3a 5c 57 69 6e 64 6f 77 73 5c 49 6e 73 74 61 6c 6c 4d 53 4e 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "VOXCARDS - Visualizar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ACO_2147649636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACO"
        threat_id = "2147649636"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {be 01 00 00 00 8b 45 f0 0f b7 44 70 fe 33 c3 89 45 dc 3b 7d dc 7c 0f 8b 45 dc 05 ff 00 00 00 2b c7 89 45 dc eb 03 29 7d dc 8d 45 ac 8b 55 dc}  //weight: 8, accuracy: High
        $x_4_2 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM" wide //weight: 4
        $x_2_3 = "81B070B56A96F66D95C8C66E9C3598924A89AB2E1135CE04479E40FF" wide //weight: 2
        $x_2_4 = "81B070B56A96F66D95C8C66E9C3598924A89AB2E1135CE04479E40FF27" wide //weight: 2
        $x_2_5 = "3BFA3AFF3C444024DC70D0769B389C9D4882AAE8" wide //weight: 2
        $x_2_6 = "E414DD033F4B4933D00F4FFC18B9D7699534ED6" wide //weight: 2
        $x_2_7 = "36C7698CB0D83B21D47EC6B062EF6580A729CF0D38EB4AF" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ACP_2147649644_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACP"
        threat_id = "2147649644"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 3d 16 04 0f 85 05 00 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85}  //weight: 2, accuracy: Low
        $x_1_3 = {23 64 20 22 [0-2] 48 [0-1] 4b [0-2] 45 [0-2] 59 [0-2] 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {23 2e 6a 23 [0-1] 70 [0-2] 67}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 23 23 69 6e [0-2] 66 [0-2] 65 [0-2] 63 [0-2] 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ACS_2147649750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACS"
        threat_id = "2147649750"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 45 fa 02 c3 88 45 fb 8d 85 ec fe ff ff 8b 55 fc 8a 54 1a ff 32 55 fb}  //weight: 10, accuracy: High
        $x_1_2 = "Label_Arquivos" ascii //weight: 1
        $x_1_3 = "VerificaEmpresa" ascii //weight: 1
        $x_1_4 = "BaixaMusicEnd" ascii //weight: 1
        $x_1_5 = "TempDinamicoEnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ACX_2147649787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACX"
        threat_id = "2147649787"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 0c}  //weight: 1, accuracy: High
        $x_1_2 = {63 68 65 63 6b 0c}  //weight: 1, accuracy: High
        $x_1_3 = {65 6d 70 74 79 0c}  //weight: 1, accuracy: High
        $x_1_4 = "Flash Player" ascii //weight: 1
        $x_2_5 = {68 2f 21 00 00 66 b9 67 24 b2 01 a1 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_2_6 = {36 32 34 46 38 37 38 31 [0-4] 38 42 37 35 00}  //weight: 2, accuracy: Low
        $x_2_7 = "624F878E12458B75" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ACY_2147649789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACY"
        threat_id = "2147649789"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75}  //weight: 1, accuracy: Low
        $x_1_2 = "vullmaster01" ascii //weight: 1
        $x_1_3 = "LdArq" ascii //weight: 1
        $x_1_4 = "Ocorreu um erro inesperado" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ACZ_2147649872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ACZ"
        threat_id = "2147649872"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 32 64 89 22 3d d9 1e 00 00 74 ?? 8d 45 fc b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-32] 2e 62 72 2f [0-32] 2e (65|6a)}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 [0-32] 63 3a 5c 61 72 71 75 69 76 6f 20 64 65 20 70 72 6f 67 72 61 6d 61 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ADA_2147649901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADA"
        threat_id = "2147649901"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 3d 16 04 0f 85 81 08 00 00 8d 55 ec b8}  //weight: 2, accuracy: High
        $x_1_2 = "#r#e#g ad##d \"H#K#EY#_CU#RR#EN#T" ascii //weight: 1
        $x_1_3 = {2e 23 23 63 23 23 23 70 23 23 23 23 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 23 23 6a 23 23 70 23 67 00}  //weight: 1, accuracy: High
        $x_1_5 = "#c:#\\#w##i#n" ascii //weight: 1
        $x_1_6 = {2f 23 3f 23 63 68 23 23 61 76 23 65 3d 23 78 23 63 23 68 61 23 76 65 23 26 75 23 72 23 6c 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADD_2147650160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADD"
        threat_id = "2147650160"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4}  //weight: 2, accuracy: Low
        $x_1_2 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\Temp\\asytws.exe" ascii //weight: 1
        $x_1_4 = "hdfree.com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADG_2147650344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADG"
        threat_id = "2147650344"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i*n#f@1#" ascii //weight: 1
        $x_1_2 = "winx*t#3*2*\\*#p@jc#t@a*.j#p#g@" ascii //weight: 1
        $x_1_3 = "R#u#n*D#L#L@3#2.@exe@" ascii //weight: 1
        $x_1_4 = "ch#a*v*e*=*x*c*h#a#ve*&#u#r*l#=#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ADG_2147650344_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADG"
        threat_id = "2147650344"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4}  //weight: 2, accuracy: Low
        $x_1_2 = {43 3a 5c 73 79 73 36 34 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 6a 75 62 61 73 2f [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "YMD recalc order:" ascii //weight: 1
        $x_1_5 = "DMY recalc order:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADK_2147650486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADK"
        threat_id = "2147650486"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "6E167C797E76756115607D791563" ascii //weight: 8
        $x_4_2 = "667515444C5C4615" ascii //weight: 4
        $x_4_3 = "667515737D7F73617016" ascii //weight: 4
        $x_4_4 = "667515646C7C661517574" ascii //weight: 4
        $x_4_5 = "5A545F604B5B655D505A581647425B1614" ascii //weight: 4
        $x_2_6 = "504E50544D47575B515914" ascii //weight: 2
        $x_1_7 = "69574350645240520C6A554E52405145405B1B524D54" ascii //weight: 1
        $x_1_8 = "544052545040404D1B534C5D" ascii //weight: 1
        $x_1_9 = "7460727E7C60775250584016504F50" ascii //weight: 1
        $x_1_10 = "514F400F1B504E51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_8_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADN_2147650530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADN"
        threat_id = "2147650530"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2276C73CBB3F4FA319299A1B9" ascii //weight: 2
        $x_1_2 = "F22460BC02459AFC4080C20258B1ED23" ascii //weight: 1
        $x_1_3 = "4E9F0060DC56A91B9F199817277BCC51A2EE" ascii //weight: 1
        $x_4_4 = "DF58DC41A1CBEA0A6DC62381FA76CF2887E5" ascii //weight: 4
        $x_2_5 = "AB1E91EC0B7DF04C" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADN_2147650530_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADN"
        threat_id = "2147650530"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 44 38 ff 03 c6 b9 ff 00 00 00 99 f7 f9 8b da 8b 45 ec 3b 45 f0 7d 05 ff 45 ec eb 07 c7 45 ec 01 00 00 00 83 f3 10 8d 45 d0 50 89 5d d4 c6 45 d8 00 8d 55 d4 33 c9}  //weight: 10, accuracy: High
        $x_1_2 = {89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8d 45 e4 8b d3 e8 ?? ?? ?? ?? 8b 55 e4 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 ff 45 f4 4e 0f 85 74 ff ff ff}  //weight: 1, accuracy: Low
        $x_2_3 = {45 45 34 31 42 34 33 30 34 45 41 30 31 34 36 46 00}  //weight: 2, accuracy: High
        $x_2_4 = {41 42 31 45 39 31 45 43 30 42 37 44 46 30 34 43 00}  //weight: 2, accuracy: High
        $x_2_5 = {42 32 30 35 37 38 46 33 33 32 38 34 46 37 37 33 00}  //weight: 2, accuracy: High
        $x_2_6 = {32 43 36 30 44 31 32 36 38 35 45 38 31 39 36 44 43 32 46 32 34 34 41 34 30 31 37 41 43 44 33 46 41 33 31 44 38 33 45 32 34 36 42 32 00}  //weight: 2, accuracy: High
        $x_1_7 = "Digite o texto conforme mostrado na caixa." ascii //weight: 1
        $x_1_8 = {73 6d 76 69 63 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADO_2147650556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADO"
        threat_id = "2147650556"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 2e 2a 00 [0-16] 2e 64 62 78 00 [0-16] 2e 77 61 62 00 [0-16] 2e 6d 62 78 00 [0-16] 2e 6d 61 69 00 [0-16] 2e 65 6d 6c 00 [0-16] 2e 74 62 62 00 [0-16] 2e 6d 62 6f 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 00 2f 63 20 64 65 6c 02 30 00 20 3e 3e 20 4e 55 4c [0-4] 43 6f 6d 53 70 65 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 74 72 61 63 74 45 6d 61 69 6c 73 46 75 6e 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 6c 75 67 69 6e 20 [0-5] 65 6e 63 6f 6e 74 72 61 64 6f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {53 56 57 55 51 89 14 24 8b f8 8b c7 e8 ?? ?? ?? ff 8b d8 e8 ?? ?? ?? ff 8b f0 0f b6 c3 8b 6c 87 04 eb 03 8b 6d 00 85 ed 74 05 3b 75 04 75 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ADP_2147650566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADP"
        threat_id = "2147650566"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d c8 0f bf d0 51 52 ff 15 a4 10 40 00 8b 35 e8 10 40 00 8b d0 8d 4d c0 ff d6 50 ff 15 2c 10 40 00}  //weight: 2, accuracy: High
        $x_2_2 = {78 41 44 00 e2 00 e8 00 d5 00 7f 00 9d 00 a3 00 c9 00 b1 00 53 01 d8 00 d7 00 b4 00 de 00 d6 00 d4 00}  //weight: 2, accuracy: High
        $x_1_3 = "Bug.exe" wide //weight: 1
        $x_1_4 = "jscript.exe" wide //weight: 1
        $x_1_5 = "\\Desktop\\Loader" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADP_2147650566_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADP"
        threat_id = "2147650566"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "7743800199164DB4A3A5F892184F48CC46DCFF" ascii //weight: 4
        $x_4_2 = "728258832470491417F63F624192C360A94CBB7F17F231EE" ascii //weight: 4
        $x_2_3 = "3598918521017DB97EB2DC228033BE6AC9" ascii //weight: 2
        $x_2_4 = "2257251527747D067099431F70F9382E" ascii //weight: 2
        $x_2_5 = "8262852067644B9124E69CE51367" ascii //weight: 2
        $x_2_6 = "7155374256577F8C6E22701E28" ascii //weight: 2
        $x_2_7 = "42549840642778A26B44186FFB722F63225F02994E9" ascii //weight: 2
        $x_2_8 = "83783309889557E213B0BABAF48FFF1C9CF7F22166" ascii //weight: 2
        $x_1_9 = "16877273918841F74647DDA367A22516CA1B2C032BCFA377C2" ascii //weight: 1
        $x_1_10 = "16963612919841577621728EC63BE557723F21" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ADT_2147650595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ADT"
        threat_id = "2147650595"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 54 56 58 58 9d 44 44 44 44 44 56 9c 3f 51 d3 aa b5 94 ac}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Tempo\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AEA_2147650696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AEA"
        threat_id = "2147650696"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "201317321317247313317" ascii //weight: 1
        $x_1_2 = "206322326322252322317310321" ascii //weight: 1
        $x_1_3 = "TfrLolita" ascii //weight: 1
        $x_1_4 = "Ulolita" ascii //weight: 1
        $x_1_5 = {66 83 eb 02 66 83 fb 03 76 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AEJ_2147651029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AEJ"
        threat_id = "2147651029"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 03 8b 75 f4 8b 07 8a 44 18 ff 8b d0 8b 4d f8 8a 4c 31 ff 32 d1 81 e2 ff 00 00 00 8b f2 85 f6 75 08 8b f0 81 e6 ff 00 00 00 8b c7 e8}  //weight: 2, accuracy: High
        $x_2_2 = {75 03 8b 45 f4 8b 17 0f b7 74 5a fe 8b 55 f8 0f b7 44 42 fe 66 33 f0 0f b7 f6 85 f6 75 07 8b 07 0f b7 74 58 fe 8b c7 e8}  //weight: 2, accuracy: High
        $x_1_3 = {43 3a 5c 77 69 6e 37 78 65 5c 77 69 6e [0-2] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {30 32 31 38 33 39 34 37 35 36 37 38 33 39 32 32 00}  //weight: 1, accuracy: High
        $x_1_5 = {58 46 45 48 09 16 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AEL_2147651114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AEL"
        threat_id = "2147651114"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 85 c0 74 05 83 e8 04 8b 00 8b d8 85 db 7e 2c be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 0f b6 54 32 ff 59 2a d1 f6 d2 e8 ?? ?? ?? ?? 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ?? 46 4b 75 d9}  //weight: 5, accuracy: Low
        $x_1_2 = {8b 4d e0 8b c3 5a 8b 18 ff 13 84 c0 74 16 b2 01 a1}  //weight: 1, accuracy: High
        $x_1_3 = {63 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 5c 00 54 00 61 00 73 00 6b 00 6d 00 73 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 5c 00 54 00 41 00 73 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AEP_2147651264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AEP"
        threat_id = "2147651264"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 66 62 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://dl.dropbox.com/u/" ascii //weight: 1
        $x_1_3 = {8b c3 8b 18 ff 13 84 c0 74 16 b2 01 a1 [0-4] e8 [0-4] 8b 15 [0-4] 8b 08 ff 11 33 c0 5a 59 59 64 89 10 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AEX_2147651581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AEX"
        threat_id = "2147651581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b8 0b 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? 00 8b 00 e8 ?? ?? ?? ?? c3 [0-7] 3a 5c 57 69 6e 64 6f 77 73 5c [0-16] 2e 65 78 65 00 [0-5] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZDR_2147651653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZDR"
        threat_id = "2147651653"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "objFSO.CreateTextFile(\"diretorio.txt" ascii //weight: 3
        $x_3_2 = ".jpg@http://" ascii //weight: 3
        $x_3_3 = "objTextFile.WriteLine(strStartup" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AEZ_2147651671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AEZ"
        threat_id = "2147651671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitBtn1Click" ascii //weight: 1
        $x_1_2 = "Novidade" ascii //weight: 1
        $x_3_3 = "http://www.coalaonline.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AFC_2147651786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFC"
        threat_id = "2147651786"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b f8 85 ff 74 69 8b d5 8d 44 24 04 e8}  //weight: 10, accuracy: High
        $x_1_2 = "duarte.machado.sites.uol.com.br" ascii //weight: 1
        $x_1_3 = "~donwload/modulos" ascii //weight: 1
        $x_1_4 = {48 65 6c 70 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 76 68 6f 73 74 78 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 69 6e 79 6d 65 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 63 68 6f 76 6c 6f 6f 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {6c 69 76 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AFI_2147651895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFI"
        threat_id = "2147651895"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6EB254A97BD172C047C94FD437FA3DCF46DB6EB053A4A070B445D525EC2F2DFF16EB7B8C8FA3" ascii //weight: 2
        $x_2_2 = "FF0CF30918361624E225E422E226E631E53B0D11F30547D65DAD7C8B8A8ACA5CBC4A19E22032" ascii //weight: 2
        $x_1_3 = "080037C74ADB3AFE091CFC3DE339CA54C655E735D75B" ascii //weight: 1
        $x_1_4 = "ED25072CE15DED21023FFF0D0314E232D258A864C" ascii //weight: 1
        $x_1_5 = "49F83BE054CF62D57FBA7B809062B040DC22F22EF" ascii //weight: 1
        $x_1_6 = "3FFF37C74ADB3AFE091CFC3D" ascii //weight: 1
        $x_1_7 = "CD75DC58CE5CB97F8A63A566CA25F90A1CE878CB5B" ascii //weight: 1
        $x_1_8 = "14031FF3091FF7105ADE24ED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AFO_2147651983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFO"
        threat_id = "2147651983"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BC75AE65D70B32D90A26DE0B35E91036C9629156D06186AB80B572" ascii //weight: 2
        $x_2_2 = "AF598F47F36BDC4BF32FD20A21C7769050EF31C9A359" ascii //weight: 2
        $x_2_3 = "51F82FE0150A7FE912CD7DA048FC23C36380A158D26E" ascii //weight: 2
        $x_2_4 = "A048FE30E45ACFB9629D4DF018CC7393539056EC4FE2" ascii //weight: 2
        $x_2_5 = "D87BB264974BF623CCB26A98B092BD6E83A749EB4EEB022A" ascii //weight: 2
        $x_1_6 = "02047C9B984EF928D919C27DD17BAE81A145E61DDB6883BC699289EF0E52" ascii //weight: 1
        $x_1_7 = "2C2FC346CE51E261F80F14252223212D233DDD70E267E9" ascii //weight: 1
        $x_1_8 = "6FF00101010310142B3BC05BEE76F576EE100D091A" ascii //weight: 1
        $x_1_9 = "C347CA5AD96CF97C829FAAB3BB4CD05CFE11362C2C2" ascii //weight: 1
        $x_1_10 = "DD61E06CEB7E979FA5B0BB41C942DA52F467E861F91" ascii //weight: 1
        $x_1_11 = "A3A4A7B6BD48DD58EE0A01040404181537292E24243" ascii //weight: 1
        $x_1_12 = "151615202733C045DB79F074F47787868898B950C85" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AFQ_2147651984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFQ"
        threat_id = "2147651984"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 88 08 80 00 00 8d 55 d0 52 8d 45 88 50 ff 15 dc 10 40 00 0f bf c8 85 c9 74 04 eb 7d eb 12 c7 45 fc 08 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {ff 15 7c 10 40 00 dd 5d a0 8d 4d b8 ff 15 10 10 40 00 c7 45 fc 08 00 00 00 68 ?? ?? 40 00 8b 55 cc 52 ff 15 2c 10 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = "libmysql41.dll" wide //weight: 1
        $x_1_4 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-16] 2e 63 73 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AFT_2147652065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFT"
        threat_id = "2147652065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 46 69 6e 61 6c 46 61 6e 74 61 73 79 54 79 70 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 75 74 61 72 69 61 62 62 62}  //weight: 1, accuracy: Low
        $x_1_2 = "\\GbPlugin\\gbiehabn.dll" wide //weight: 1
        $x_1_3 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_4 = {00 20 00 3a 00 2e 00 2e 00 20 00 41 00 4e 00 54 00 49 00 56 00 49 00 52 00 55 00 53 00 20 00 2e 00 2e 00 3a 00 20 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 20 00 3a 00 2e 00 2e 00 56 00 45 00 52 00 53 00 41 00 4f 00 20 00 4b 00 6c 00 2e 00 2e 00 3a 00 20 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AFT_2147652065_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFT"
        threat_id = "2147652065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 0f b6 c3 8b 6c 87 04 eb ?? 8b 6d 00 85 ed 74 ?? 3b 75 04 75}  //weight: 2, accuracy: Low
        $x_1_2 = "ControlOfs%.8X%.8X" wide //weight: 1
        $x_1_3 = "WndProcPtr%.8X%.8X" wide //weight: 1
        $x_1_4 = "System<\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AFT_2147652065_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFT"
        threat_id = "2147652065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 0f b6 c3 8b 6c 87 04 eb ?? 8b 6d 00 85 ed 74 ?? 3b 75 04 75}  //weight: 2, accuracy: Low
        $x_1_2 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_3 = {66 74 70 54 72 61 6e 73 66 65 72 [0-2] 66 74 70 52 65 61 64 79}  //weight: 1, accuracy: Low
        $x_1_4 = "ControlOfs%.8X%.8X" wide //weight: 1
        $x_1_5 = "jacapodre.dominiotemporario.com" wide //weight: 1
        $x_1_6 = "smtp.strato.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AFY_2147652158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFY"
        threat_id = "2147652158"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 6d 00 6d 00 6d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 00 72 00 75 00 2e 00 61 00 63 00 2e 00 62 00 64 00 2f 00 61 00 72 00 61 00 62 00 69 00 63 00 2f 00 6c 00 6f 00 67 00 73 00 2f 00 [0-15] 2e 00 67 00 69 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AGL_2147652407_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AGL"
        threat_id = "2147652407"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 42 44 5c 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 00 00 00 00 ff ff ff ff 04 00 00 00 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_2 = {05 00 00 00 63 68 61 76 65 00 00 00 ff ff ff ff 01 00 00 00 24 00}  //weight: 1, accuracy: High
        $x_1_3 = {07 55 4c 6f 61 64 65 72}  //weight: 1, accuracy: High
        $x_1_4 = {8b b3 1c 03 00 00 8d 55 f8 8b 83 f8 02 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AGM_2147652413_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AGM"
        threat_id = "2147652413"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 61 74 61 72 61 74 61 73 74 72 69 6b 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 6f 73 74 73 79 73 74 65 6d 2e 65 78 65 [0-10] 6f 66 66 69 63 65 32}  //weight: 1, accuracy: Low
        $x_1_3 = {69 6d 67 6c 6f 67 2e 65 78 65 [0-10] 57 6f 72 64 38}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 4c 00 4e 00 4b 00 00 00}  //weight: 1, accuracy: High
        $x_3_5 = {7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AGP_2147652516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AGP"
        threat_id = "2147652516"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 06 8b 45 f4 8b 10 ff 12 8b c8 8b 16 8b 45 f4 8b 30 ff 56 0c 8b 45 f4 8b 10 ff 12 89 03 c6 45 ff 01}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 05 8d 55 ?? e8 ?? ?? ?? ?? 8b 45 00 89 45 ?? c6 45 ?? 0b 8d 55 ?? b8 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 05 89 45 ?? c6 45 ?? 0b 8d 55 ?? b9 02 00 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AGR_2147652603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AGR"
        threat_id = "2147652603"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 8b 80 68 03 00 00 66 be eb ff e8}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 74 75 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 90 02 0a 2e 6a 70 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AGT_2147652763_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AGT"
        threat_id = "2147652763"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 10 8b 45 ec 8b 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 eb 68 ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AGY_2147652990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AGY"
        threat_id = "2147652990"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autlookexpp" ascii //weight: 1
        $x_1_2 = "nkc.com.vn" ascii //weight: 1
        $x_1_3 = "iexplore32" ascii //weight: 1
        $x_1_4 = "javaflash3" ascii //weight: 1
        $x_1_5 = {6c 75 61 20 6e 6f 76 61 00 00 00 00 ff ff ff ff 3a 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_T_2147653090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!T"
        threat_id = "2147653090"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wcmXvYVUd" wide //weight: 1
        $x_1_2 = "\\loader\\Loader.vbp" wide //weight: 1
        $x_1_3 = "YU#MK%FRTG&VBGTYU*WI(LLF@IASW!OL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AHB_2147653131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHB"
        threat_id = "2147653131"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 63 6f 6d 2e 62 72 2f 61 74 6d 70 2e 7a 69 70 00 [0-16] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 00 41 64 6f 62 65 20 52 65 61 64 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AHD_2147653165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHD"
        threat_id = "2147653165"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 5c 30 ff 33 5d e4 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02}  //weight: 10, accuracy: High
        $x_10_2 = {dd 5d b8 9b ff 75 bc ff 75 b8 8d 45 f8 ba ?? ?? ?? ?? e8 22 4e ff ff 6a 05 8d 85 40 ff ff ff e8}  //weight: 10, accuracy: Low
        $x_1_3 = "$Avira$" ascii //weight: 1
        $x_1_4 = "$Antivir" ascii //weight: 1
        $x_1_5 = "$PANDA" ascii //weight: 1
        $x_1_6 = "$NORTON" ascii //weight: 1
        $x_1_7 = "$KASPERSKY$" ascii //weight: 1
        $x_1_8 = "$McAfee$" ascii //weight: 1
        $x_1_9 = "$AVG" ascii //weight: 1
        $x_1_10 = "$MSE$" ascii //weight: 1
        $x_1_11 = "$COMODO$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AHE_2147653199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHE"
        threat_id = "2147653199"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 0f b6 44 30 ff 33 d8 8d 45 ?? 50 89 5d ?? c6 45 ?? 00 8d 55 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 20 e8 ?? ?? ?? ?? 83 f8 03 7e 46 4f 75 ?? 8b 83 ?? ?? 00 00 8b 10 ff 52 14 85 c0 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AHP_2147653355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHP"
        threat_id = "2147653355"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vetim_load_vb\\Project1.vbp" wide //weight: 1
        $x_1_2 = "system32\\msngrss.exe" wide //weight: 1
        $x_1_3 = "china cracking group" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AHQ_2147653370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHQ"
        threat_id = "2147653370"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H6bj84zYQaTbT2mWH6boPNHlScblKtHo" ascii //weight: 1
        $x_1_2 = "KsXbR6mkTc9p" ascii //weight: 1
        $x_1_3 = "SdLkSsXbR6mkQMvf" ascii //weight: 1
        $x_1_4 = "55954854855362662162155854654754656856555155456954" ascii //weight: 1
        $x_1_5 = "52569621585565547551553548555621597600622546564546" ascii //weight: 1
        $x_1_6 = "599597622565547546554548546" ascii //weight: 1
        $x_1_7 = "StHoKtHXSdHrS20z85TpQ5DePMniBbD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AHR_2147653372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHR"
        threat_id = "2147653372"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SsLq85TpQ5DePMni83qWLrDZScbmT2v3ScLXT" ascii //weight: 2
        $x_2_2 = "0YN3myRczjPJu+BcnkQo8fG6zJQ6LiR" ascii //weight: 2
        $x_2_3 = "HfScLZT6zoUI0z87DqSabkQMDfON90RrDePMniJ6bkQovJONPb" ascii //weight: 2
        $x_2_4 = "BcDoPM5qPG" ascii //weight: 2
        $x_1_5 = "F3nkRsrbFZu" ascii //weight: 1
        $x_1_6 = "F3nZOMrfRcXlFZu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AHS_2147653373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHS"
        threat_id = "2147653373"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BcDoPM5qPG" ascii //weight: 2
        $x_2_2 = "F3nkRsrbFZu" ascii //weight: 2
        $x_2_3 = "F3nZOMrfRcXlFZu" ascii //weight: 2
        $x_1_4 = "IMvqPN9kPNGWHNXmR6zoPN9VKsLoTcLo" ascii //weight: 1
        $x_1_5 = "Q6zqRM5fR0" ascii //weight: 1
        $x_1_6 = "PMvqSc5o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AHX_2147653445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AHX"
        threat_id = "2147653445"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OpfSK79lPt9XRKHXT64" wide //weight: 1
        $x_1_2 = {85 db 7c 5f 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 99 f7 f9 89 55 f0 b9 00 01 00 00 8b c3 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AIB_2147653614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIB"
        threat_id = "2147653614"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32 /s " ascii //weight: 1
        $x_4_2 = {23 4c 23 00 ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 0c 00 00 00 72 65 67 73 76 72 33 32 20 2f 73 20}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AIF_2147653666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIF"
        threat_id = "2147653666"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 85 64 ff ff ff 50 8d 4d 98 51 8d 95 68 ff ff ff 52 8d 45 88 50 ff 15 ?? ?? ?? ?? 50 8d 4d bc 51 ff 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8b 55 08 8b 02 8b 4d 08 51 ff 90 ?? ?? ?? ?? 89 85 58 ff ff ff 83 bd 58 ff ff ff 00 7d}  //weight: 10, accuracy: Low
        $x_1_2 = "http://01gyn01.com" wide //weight: 1
        $x_1_3 = "system32\\wynndy.exe" wide //weight: 1
        $x_1_4 = "regsvr32.exe /s wynndy.dl" wide //weight: 1
        $x_1_5 = "new/win64.gif" wide //weight: 1
        $x_1_6 = "new/win32.gif" wide //weight: 1
        $x_1_7 = "new/sms.gif" wide //weight: 1
        $x_1_8 = "new/msdos.gif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AIM_2147653814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIM"
        threat_id = "2147653814"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c4 a0 fa ff ff 53 56 57 33 c0 89 45 ec 8b 75 0c 8b 5d 08 33 c0 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8b 45 ec e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 f8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 00 8b c3 e8 ?? ?? ?? ?? 8b f8 57 8b 45 f8 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 89 45 f8 8b c3 2c 04 74 33 c0 8a c3 50 8b c7 5a 8b ca 99 f7 f9 85 d2 75 33 c0 8a c3 8b d7 2b d0 8b 45 fc 8b 44 90 08 33 45 f8 89 46 04 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AIN_2147653893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIN"
        threat_id = "2147653893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "0F478B3090FA1A79D67CD0025FE479EA29BB1BA03F92C70" ascii //weight: 4
        $x_4_2 = "035BFF44848E8D8CC90F43943297CB1D7BED6DD271E47AD" ascii //weight: 4
        $x_4_3 = "7ED67BDF60AAE929A62CA032AF15499AF86BEA508EC117B" ascii //weight: 4
        $x_4_4 = "1AB217BB1C66A5E462E77CED6BD00556B427A62CAA3E933" ascii //weight: 4
        $x_4_5 = "66FE4387C73251B02E93C719B61CB02260F252F75689DE7" ascii //weight: 4
        $x_4_6 = "B52E923797E12160FD4397C8064B9F316FE161E665F86EE" ascii //weight: 4
        $x_4_7 = "40983D81C1CBCAC9074C80D10FB429BAD80B4A8FCD0156F" ascii //weight: 4
        $x_3_8 = "91C5084187DC7FC22F" ascii //weight: 3
        $x_3_9 = "2D94CD0C409F27AA37" ascii //weight: 3
        $x_3_10 = "F5076D8494EA64E67CC315B12E" ascii //weight: 3
        $x_2_11 = "BE17B614B3104F86D70C4B499E27BC" ascii //weight: 2
        $x_2_12 = "9FD177DB60FF5E" ascii //weight: 2
        $x_1_13 = "F356FA57BADC2367A52C94C8" ascii //weight: 1
        $x_1_14 = "BD0044808283838B89CB70EC" ascii //weight: 1
        $x_1_15 = "6FD176D23A5EA3DA399F28BC" ascii //weight: 1
        $x_1_16 = "094B8FCB355EA5EB2A9039AD" ascii //weight: 1
        $x_1_17 = "9235993658BDC3C108B025" ascii //weight: 1
        $x_1_18 = "24A62BA7EF117A9EFC438BDF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((3 of ($x_4_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AIT_2147654061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIT"
        threat_id = "2147654061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 5e 5b c3 00 00 00 ff ff ff ff 0f 00 00 00 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-64] 2e 73 77 66 00 00 07 54 42 75 74 74 6f 6e 07 42 75 74 74 6f 6e 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AIV_2147654097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIV"
        threat_id = "2147654097"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 74 65 6d 70 73 62 72 61 73 69 6c 2e 6e 65 74 2f [0-24] 2e 65 78 65 [0-8] 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c [0-24] 2e 65 78 65 [0-5] 55 8b ec 6a 00 33 c0 55 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AIW_2147654151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AIW"
        threat_id = "2147654151"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ewoGcOk8desQexAMd8sGZ92PYwEebf6Ra8YCexoAZOsQaOkfcesCbf2H" ascii //weight: 2
        $x_2_2 = "h92PYuYUZPgZifQSZP2Ca9cBewYMaPkGY8oZl8gDZPgHYwcQZOoMa96Zj" ascii //weight: 2
        $x_2_3 = "legBaBoGaPcMcAgji/" ascii //weight: 2
        $x_1_4 = "ggowhQ+jiBcsixh" ascii //weight: 1
        $x_1_5 = "lg+lkxwhll" ascii //weight: 1
        $x_1_6 = "evoBcPAGZT6QXvh" ascii //weight: 1
        $x_1_7 = "d8kPaf2D" ascii //weight: 1
        $x_1_8 = "ZusQcOpHbOp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AJE_2147654427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJE"
        threat_id = "2147654427"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 69 00 20 00 74 00 68 00 65 00 72 00 65 00 20 00 68 00 61 00 63 00 6b 00 65 00 72 00 73 00 0d 00 0d 00 0d 00 68 00 61 00 63 00 6b 00 69 00 6e 00 67 00 20 00 69 00 73 00 20 00 66 00 75 00 6e 00 21 00}  //weight: 1, accuracy: High
        $x_1_2 = "c:\\winsys\\wne.exe" wide //weight: 1
        $x_1_3 = "Game - Overdue Loans -" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJG_2147654442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJG"
        threat_id = "2147654442"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pjct1.jpg" ascii //weight: 1
        $x_1_2 = "java.jpg" ascii //weight: 1
        $x_1_3 = "Run\" /v pjct1 /d" ascii //weight: 1
        $x_1_4 = "chave=xchave&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJH_2147654457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJH"
        threat_id = "2147654457"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "dl.dropbox.com/u/" ascii //weight: 3
        $x_5_2 = {8b d8 85 db 7e 2c e8 ?? ?? ?? ff b8 ?? 00 00 00 e8 ?? ?? ?? ff ba ?? ?? ?? ?? 8a 14 02 8d 45 fc e8 ?? ?? ?? ff 8b 55 fc 8b c6 e8 ?? ?? ?? ff 4b 75 d4 33 c0 5a}  //weight: 5, accuracy: Low
        $x_2_3 = {8d 55 d0 b8 06 00 00 00 e8 ?? ?? ?? ff ff 75 d0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? [0-5] 8d 45 d4 ba (03|04) 00 00 00 e8 ?? ?? ?? ff 8b 45 d4 e8 ?? ?? ?? ff 8b d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJK_2147654480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJK"
        threat_id = "2147654480"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 1c 00 00 00 e8 ?? ?? fe ff ba ?? ?? 41 00 8a 14 02 8d 45 f8 e8 ?? ?? fe ff 8b 55 f8 8d 45 fc e8 ?? ?? fe ff 4b 75 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "zaybxjkqrclmwnopdtustefghiuv" ascii //weight: 1
        $x_1_3 = "hosp-att06.nm.ru" ascii //weight: 1
        $x_1_4 = {07 00 00 00 5c 46 6f 6e 74 73 5c 00 ff ff ff ff 04 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJL_2147654505_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJL"
        threat_id = "2147654505"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8}  //weight: 4, accuracy: High
        $x_4_2 = {97 8b 8b 8f c5 d0 d0 9b 9e 88 9e 8b 9a 96 8c 93 9e 92 96 d1 91 9a 8b d0 97 8b 92 93 d0 99 90 91 8b 8c d0}  //weight: 4, accuracy: High
        $x_2_3 = {8b 9e 8c 94 94 96 93 93 df d0 99 df d0 b6 b2 df be 89 9e 8c}  //weight: 2, accuracy: High
        $x_2_4 = {bc c5 a3 be 8d 8e 8a 96 89 90 8c df 9b 9a df 8f 8d 90 98 8d}  //weight: 2, accuracy: High
        $x_2_5 = {9e 92 9e 8c a3 b6 91 8b 9a 8d 91 9a 8b df ba 87 8f 93 90 8d}  //weight: 2, accuracy: High
        $x_1_6 = {9c c5 a3 af 8d 90 98 8d 9e 92 bb 9e 8b 9e a3 00}  //weight: 1, accuracy: High
        $x_1_7 = {89 96 8c 8b 9e d1 9c 90 92 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZDT_2147654516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZDT"
        threat_id = "2147654516"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 5c 30 ff 33 5d e4 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02}  //weight: 1, accuracy: High
        $x_1_2 = {6a 05 8d 45 ?? e8 17 00 dd 5d ?? 9b ff 75 ?? ff 75 ?? 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {4a 41 48 53 00 ff ff ff ff 01 00 00 00 24 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJO_2147654556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJO"
        threat_id = "2147654556"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 01 75 df a1 ?? b7 40 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ff ff e9 ?? 01 00 00 8d 55 cc 33 c0 e8 ?? ?? ff ff 8b 55 cc b8 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 0f 8e ?? 01 00 00 b8 ?? b7 40 00 ba ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 69 63 00 ff ff ff ff 07 00 00 00 68 61 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJQ_2147654577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJQ"
        threat_id = "2147654577"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 d0 fb 44 00 e8 48 7e ff ff ba ?? ?? 44 00 b8 ?? ?? 44 00 e8 b9 fe ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 44 00 e8 49 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {a1 bc df 44 00 8b 00 e8 ?? ?? ff ff c3 [0-2] ff ff ff ff ?? 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d [0-2] 5c [0-8] 2e 65 78 65 00 [0-3] ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AJU_2147654934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJU"
        threat_id = "2147654934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "DC21ED040B0D0FF64CDE27ED5DB444CA57D562F85DBA50C366BB5CF01031E2180532F01A" ascii //weight: 50
        $x_10_2 = "C943C050B298BE98A3BC9CAB97ABBF97A3BF86DB77D665AE4AD369B" ascii //weight: 10
        $x_10_3 = "BA79988E00525D05D8E49F5211D0864D758C7BCA081FB7FF67EFD1F" ascii //weight: 10
        $x_10_4 = "61AAEA6AD67C9BF51C6E81EF76CA1573F14EEB71F41963BAC4D83B4" ascii //weight: 10
        $x_5_5 = "FA58B9799E" ascii //weight: 5
        $x_5_6 = "FC5AB446DD" ascii //weight: 5
        $x_5_7 = "2EF83CEF46D7" ascii //weight: 5
        $x_5_8 = "F045C357B8590025EF0CF03320393F020259F" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AJV_2147654945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AJV"
        threat_id = "2147654945"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "KcLdStPoCp8WBrCWN5mnCZSkC2umBZ5SGMHjQMuaN69oOMHXBcHiR0" ascii //weight: 10
        $x_8_2 = "bb-gerenciadorfinanceiro.com/files" ascii //weight: 8
        $x_4_3 = "Downloads\\brada7.exe" ascii //weight: 4
        $x_4_4 = "Public\\Downloads\\instant.exe" ascii //weight: 4
        $x_4_5 = "brada.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AKH_2147655354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKH"
        threat_id = "2147655354"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "170"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Q7HqS3elBt" ascii //weight: 100
        $x_50_2 = "9fPtLfR6XbScrbBdDfT6LpBdLlR2vZRsqkOd8l" ascii //weight: 50
        $x_50_3 = "9lP79fPsykSs5iRsrXRovpQNHbSovrRsmk" ascii //weight: 50
        $x_20_4 = "OpfSK79lPt9XRKHXT65SQNHsSovqU7G" ascii //weight: 20
        $x_20_5 = "Ss5kT65kP6Lo" ascii //weight: 20
        $x_20_6 = "QNHXTG" ascii //weight: 20
        $x_20_7 = "MrP1Kab1LaL9KqzBNG" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 4 of ($x_20_*))) or
            ((1 of ($x_100_*) and 4 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AKI_2147655382_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKI"
        threat_id = "2147655382"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//bymix.ru/" ascii //weight: 1
        $x_1_2 = "/vir/link.php" ascii //weight: 1
        $x_1_3 = "/vir/baza.php" ascii //weight: 1
        $x_1_4 = "/vir/time.php" ascii //weight: 1
        $x_1_5 = "/vir/up.exe" ascii //weight: 1
        $x_1_6 = "/vir/ver.php" ascii //weight: 1
        $x_1_7 = "DisableScriptDebuggerIE" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AKK_2147655536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKK"
        threat_id = "2147655536"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "PtU88okiIEimHy/tjhSYE" ascii //weight: 100
        $x_40_2 = "qEcuwk90+qL53trD+AWkc" ascii //weight: 40
        $x_20_3 = "x+8SY+prbgbrInPzNQ1PkhfB6r5NMxqk3xPFZD4PZ0M=" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AKS_2147655725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKS"
        threat_id = "2147655725"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {2f 61 74 6d 70 2e 7a 69 70 00}  //weight: 100, accuracy: High
        $x_100_2 = {2f 6d 65 6d 62 72 6f 73 2e 70 68 70 00}  //weight: 100, accuracy: High
        $x_100_3 = {2f 6e 69 63 68 61 6e 2e 7a 69 70 00}  //weight: 100, accuracy: High
        $x_20_4 = "megaimports05.com" ascii //weight: 20
        $x_20_5 = "topvipz01.dominiotemporario.com" ascii //weight: 20
        $x_20_6 = "andrelucarna.web102.f1.k8.com.br" ascii //weight: 20
        $x_20_7 = "baladagynnight.com" ascii //weight: 20
        $x_20_8 = "76.73.80.98/~" ascii //weight: 20
        $x_20_9 = "4shared.com/download" ascii //weight: 20
        $x_20_10 = "hostx0011.dominiotemporario.com" ascii //weight: 20
        $x_20_11 = "107.22.158.193/" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 5 of ($x_20_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AKT_2147655726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKT"
        threat_id = "2147655726"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "320"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2f 6e 69 63 68 61 6e ?? 2e 7a 69 70 00}  //weight: 100, accuracy: Low
        $x_100_2 = {2f 61 72 71 61 2e 62 6d 70 00}  //weight: 100, accuracy: High
        $x_100_3 = "dominiotemporario.com" ascii //weight: 100
        $x_200_4 = "dl.dropbox.com/u/74647960" ascii //weight: 200
        $x_20_5 = {43 4d 44 20 2f 43 20 43 6f 70 79 00}  //weight: 20, accuracy: High
        $x_20_6 = "Falha!!! Arquivo " ascii //weight: 20
        $x_20_7 = {62 69 67 6d 61 63 2e 65 78 65 00}  //weight: 20, accuracy: High
        $x_20_8 = {72 65 61 72 64 65 72 2e 65 78 65 00}  //weight: 20, accuracy: High
        $x_20_9 = {00 63 72 66 72 73 2e 65 78 65 00}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_20_*))) or
            ((1 of ($x_200_*) and 1 of ($x_100_*) and 1 of ($x_20_*))) or
            ((1 of ($x_200_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AKU_2147655790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKU"
        threat_id = "2147655790"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 4d 75 07 80 fb 48 75 02 b0 4e 8b d8 25 ff 00 00 00 83 c0 de 83 f8 38 0f 87 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? ff 24 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75}  //weight: 1, accuracy: Low
        $x_1_3 = "GRANDE MEDIO DIRETAS" ascii //weight: 1
        $x_1_4 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AKW_2147655994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKW"
        threat_id = "2147655994"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://showjapao.hut2.ru/moduloa.jpg" ascii //weight: 1
        $x_1_2 = "brasilwinwos1.exe" ascii //weight: 1
        $x_1_3 = "TaskbarCreated" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AKX_2147656033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKX"
        threat_id = "2147656033"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-32] 2e 70 64 66}  //weight: 1, accuracy: Low
        $x_1_2 = "winhost.exe" ascii //weight: 1
        $x_1_3 = "TaskbarCreated" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AKY_2147656083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKY"
        threat_id = "2147656083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 70 6a 45 00 e8 5d de fa ff a1 ?? 9a 45 00 b9 ?? 6a 45 00 8b 55 fc}  //weight: 1, accuracy: Low
        $x_1_2 = ".jpg" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AKY_2147656083_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKY"
        threat_id = "2147656083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-32] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-32] 2e 73 77 66}  //weight: 1, accuracy: Low
        $x_1_3 = "mfrs095.exe" ascii //weight: 1
        $x_1_4 = "TaskbarCreated" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AKZ_2147656093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AKZ"
        threat_id = "2147656093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-32] 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 37 33 31 36 32 36 31 31 [0-32] 2e 73 77 66 [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "TaskbarCreated" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALA_2147656247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALA"
        threat_id = "2147656247"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "- ]ue.prf.ee[" ascii //weight: 100
        $x_100_2 = "uhuroswH xhquhxqL vcrgqlC" ascii //weight: 100
        $x_20_3 = "QZU\\QRLVUHYXQHUUZF\\VCRGQLC\\XIRVRUFLP\\HUDCXIRV" ascii //weight: 20
        $x_20_4 = "phxvbV\\vhlflorS\\qrlvuhYxqhuuzF\\vcrgqlC\\xirvruflP\\hudcxirV\\" ascii //weight: 20
        $x_20_5 = "DZOhoedqH" ascii //weight: 20
        $x_20_6 = "ujPnvdXhoedvlG" ascii //weight: 20
        $x_20_7 = "oog.05OTVbpelo\\" ascii //weight: 20
        $x_20_8 = "uhyuhV_uhuroswH xhquhxqL" ascii //weight: 20
        $x_20_9 = "chlY xfhmeRfrG oohkV" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ALC_2147656311_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALC"
        threat_id = "2147656311"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/msnmsgr.png" ascii //weight: 1
        $x_1_2 = "/TaskMGR.png" ascii //weight: 1
        $x_1_3 = {63 3a 5c 46 69 6c 65 73 20 50 72 6f 67 72 61 6d 61 5c [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "pornhub.com/view_video.php?viewkey" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALD_2147656314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALD"
        threat_id = "2147656314"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 [0-16] 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-8] 2f 6d 6f 64 75 6c 6f 61 2e 6a 70 67 [0-16] 6d 66 72 73 [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 [0-4] 49 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALI_2147656600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALI"
        threat_id = "2147656600"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tmacuco" ascii //weight: 1
        $x_1_2 = "http://s3.amazonaws.com/macabro01/" ascii //weight: 1
        $x_1_3 = "Game - Overdue Loans - " ascii //weight: 1
        $x_1_4 = "DelphiBasics - Game" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALK_2147656736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALK"
        threat_id = "2147656736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 64 6c 43 72 79 70 74 [0-5] 6d 64 6c 44 6f 77 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 62 00 69 00 6e 00 2e 00 62 00 61 00 73 00 65 00 36 00 34 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALM_2147656789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALM"
        threat_id = "2147656789"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 6c 65 73 75 70 64 6f 77 6e [0-10] 68 74 74 70 3a 2f 2f 31 38 39 2e 33 36 2e 31 33 37 2e 38 32 2f 69 6d 61 67 65 6e 73 2f 6e 6f 74 69 63 69 61 73 2f 76 69 73 69 74 61 2f 45 4e 2f 4d 79 53 71 6c 2f 65 6e 64 6e 6e 65 77 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "\\msnmsggr2.exe" ascii //weight: 1
        $x_1_3 = "\\javahunt232.exe" ascii //weight: 1
        $x_1_4 = "UacDisableNotify" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALQ_2147656951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALQ"
        threat_id = "2147656951"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dl.dropbox.com/u/" ascii //weight: 1
        $x_1_2 = {ff b5 7c ff ff ff 8d 45 c4 ba 12 00 00 00 e8 ?? ?? ?? ?? 8b 45 c4 e8 ?? ?? ?? ?? 50 53 e8 ?? ?? ?? ?? 8b f8}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 55 fc 33 c0 e8 ?? ?? ?? ?? ff 75 fc 8d 55 f8 33 c0 e8 ?? ?? ?? ?? ff 75 f8}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 ff d6 85 c0 0f 94 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ALT_2147657039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ALT"
        threat_id = "2147657039"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "221"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {2f 49 6e 73 74 61 6c 2e 62 63 6b 00}  //weight: 100, accuracy: High
        $x_100_2 = {2f 54 69 6d 65 2e 63 6f 6d 00}  //weight: 100, accuracy: High
        $x_20_3 = "segksa2014.com" ascii //weight: 20
        $x_20_4 = "emporiogospel.com" ascii //weight: 20
        $x_20_5 = "personnalitexclusivehs.com" ascii //weight: 20
        $x_20_6 = "grandesgigas.com" ascii //weight: 20
        $x_20_7 = "facebuksconect.com" ascii //weight: 20
        $x_1_8 = {00 4d 65 6e 75 20 49 6e 69 63 69 61 72 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 a3 ab 96 92 9a d1 9a 87 9a 00}  //weight: 1, accuracy: High
        $x_1_10 = "C:\\windir\\time" ascii //weight: 1
        $x_1_11 = "/installlogs/" ascii //weight: 1
        $x_1_12 = "/laslog/" ascii //weight: 1
        $x_1_13 = "loja/lote/" ascii //weight: 1
        $x_1_14 = {00 74 69 6d 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMA_2147657269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMA"
        threat_id = "2147657269"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 98 89 5d 90 89 8d 68 ff ff ff c7 85 60 ff ff ff 08 40 00 00 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {b9 ff 00 00 00 66 3b c1 7e 05 0f bf c0 eb ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 1e 00 00 00 0f bf c0 03 c1 0f 80 35 01 00 00 2b c6 0f 80 2d 01 00 00 50 8d 45 90 50 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {0f bf ca 33 c0 0f bf c0 03 c1 0f 80 35 01 00 00 2b c6 0f 80 2d 01 00 00 50 8d 45 90 50 ff 15}  //weight: 1, accuracy: High
        $x_5_5 = {5c 00 62 00 69 00 6e 00 5c 00 70 00 72 00 6f 00 6a 00 65 00 74 00 6f 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 5, accuracy: High
        $x_1_6 = {52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {77 00 69 00 6e 00 64 00 69 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {52 00 65 00 67 00 52 00 65 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {52 00 45 00 47 00 5f 00 53 00 5a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMH_2147657536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMH"
        threat_id = "2147657536"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$gcapt" ascii //weight: 5
        $x_5_2 = "svchos:" ascii //weight: 5
        $x_5_3 = "{05DCD7B5-53FF-4d3a-91A8-27B4BB463436}" ascii //weight: 5
        $x_2_4 = ".bb.com.br/aapj/loginmpe.bb" ascii //weight: 2
        $x_2_5 = ".bb.com.br/aapj/loginpfe.bb" ascii //weight: 2
        $x_2_6 = "\\BaBy\\Desktop\\PEN\\Rotinas Uteis\\NOVO BHO - TNT - CAPTHA\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMI_2147657546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMI"
        threat_id = "2147657546"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "WindowsLive:name=*" ascii //weight: 5
        $x_5_2 = "POP3 User Name" ascii //weight: 5
        $x_1_3 = ".jematkd.com/img/rounded-box/.../" ascii //weight: 1
        $x_1_4 = {63 6c 65 61 6e 69 6e 67 2d 64 6f 72 73 65 74 2e 6c 69 6e 75 78 70 6c 2e 65 75 2f 47 50 2f 75 70 6c 6f 61 64 2f 64 72 6f 62 6e 65 2f [0-8] 2f 73 73 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMK_2147657667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMK"
        threat_id = "2147657667"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 48 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 00 00 00 01 01 00 8c 53 65 6e 64 00 00 00 00 01 00 00 52 65 73 70 6f 6e 73 65 54 65 78 74}  //weight: 5, accuracy: High
        $x_1_2 = "Software\\Classes\\Applications\\msngr.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Security Center" ascii //weight: 1
        $x_1_4 = "Identity Protection\\Agent\\Bin\\AVGIDSAgent.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AML_2147657699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AML"
        threat_id = "2147657699"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "725"
        strings_accuracy = "High"
    strings:
        $x_300_1 = "V~e!r~s!i~o!n^\\^R~u!n~" ascii //weight: 300
        $x_300_2 = "~c+h^a~v~e!=!x!c+h~a~v~e!" ascii //weight: 300
        $x_100_3 = "!h^t~t~p+:^/~/!b!l+a!c~k!a+n~d~w~h~i+t^e~x^.^c~o!m" ascii //weight: 100
        $x_50_4 = "~E^S!E!T~ ~C~l+i^e!n~t" ascii //weight: 50
        $x_50_5 = "r!x!9!/!!w^x~1!~.~j+p^g" ascii //weight: 50
        $x_50_6 = "v~2!5^/!r!x!9!/!+w+x~6!~.~j+p^g" ascii //weight: 50
        $x_25_7 = "~R^u!n^D+L^L^3~2^.~e~x^e" ascii //weight: 25
        $x_25_8 = "!w^x~1!+.~c+p~l" ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_300_*) and 2 of ($x_50_*) and 1 of ($x_25_*))) or
            ((2 of ($x_300_*) and 3 of ($x_50_*))) or
            ((2 of ($x_300_*) and 1 of ($x_100_*) and 1 of ($x_25_*))) or
            ((2 of ($x_300_*) and 1 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMP_2147657828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMP"
        threat_id = "2147657828"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "450"
        strings_accuracy = "High"
    strings:
        $x_300_1 = "BZOE6YOF80RH7YQH7XOE5VMC5WME5VMC3TJ2VLC2" ascii //weight: 300
        $x_100_2 = "44E276AB65FC36EB17B3E37BBB1BDE1FD9082231DF7" ascii //weight: 100
        $x_10_3 = "0BE628DC96B9D8EC66983" ascii //weight: 10
        $x_50_4 = "B553CC5ADE03112C3746BF41DD070F3D" ascii //weight: 50
        $x_50_5 = "43DC73F30764ED0C225BAFACB623" ascii //weight: 50
        $x_50_6 = "63915E82AC29D30E32A320D703" ascii //weight: 50
        $x_10_7 = "944AE811C013DB1CCC" ascii //weight: 10
        $x_10_8 = "1629212223A445FC2FA638CE6BED6D87BB160F" ascii //weight: 10
        $x_10_9 = "5184AD5C8BCD19C768E96699" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_300_*) and 3 of ($x_50_*))) or
            ((1 of ($x_300_*) and 1 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMS_2147657888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMS"
        threat_id = "2147657888"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Q7HqS3elBtTtTovpT6HqON9pONDXPoveTIzfRM5dPNClRczqPNC" ascii //weight: 100
        $x_30_2 = "JMbZSczpRsPq84zcPcbZPG" ascii //weight: 30
        $x_30_3 = "QMLuS6nlScLoSYvbU6K" ascii //weight: 30
        $x_20_4 = "N5DlPdHtON9bN4rfOt9lSszcT5nNQMvaR" ascii //weight: 20
        $x_20_5 = "Hc5iQ64WOMyWOM9oQN8WRo1XSd5rQNPl8" ascii //weight: 20
        $x_20_6 = "N5DlPdHtON9bN4rfOt9lSszcT5nJPMDrS" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMV_2147658029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMV"
        threat_id = "2147658029"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Q7HqS3elB" ascii //weight: 1
        $x_1_2 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 73 79 73 74 65 6d 33 32 5c 73 69 73 74 65 6d 6b 69 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 5c 77 6d 70 6c 61 79 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 73 79 73 74 65 6d 33 32 5c 70 69 6e 67 77 ?? 62}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 73 79 73 74 65 6d 33 32 5c 70 69 6e 67 6b 69 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AMW_2147658080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMW"
        threat_id = "2147658080"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q7HqS3elB" ascii //weight: 1
        $x_1_2 = "JMbZSczpRsPq84zcPcbZPG" ascii //weight: 1
        $x_1_3 = {7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AMW_2147658080_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMW"
        threat_id = "2147658080"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 e8 1d 73 fd ff 6a 01 8d 45 f4 b9 ec d2 44 00 8b 93 f8 02 00 00 e8 14 70 fb ff 8b 45 f4 e8 c0 71 fb ff 50 e8 b2 8e fb ff}  //weight: 5, accuracy: High
        $x_5_2 = {47 00 8d 45 fc ba ?? 00 00 00 e8 ?? ac f8 ff 8b 55 fc b8 ?? 96 47 00 e8 ?? fe ff ff 26 00 68 ?? 96 47 00 68 ?? 96 47 00 68 ?? 96 47 00 68 ?? 96 47 00 68 ?? 96 47 00 68 ?? 96 47 00 68 ?? 96 47 00 68 ?? 96 47 00}  //weight: 5, accuracy: Low
        $x_5_3 = {8d 45 fc ba 09 00 00 00 e8 ?? ?? fa ff 8b 4d fc ba ?? ?? ?? 00 8b c3 e8 ?? fe ff ff 28 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00 68 ?? ?? (45|46) 00}  //weight: 5, accuracy: Low
        $x_1_4 = "UacDisableNotify" ascii //weight: 1
        $x_1_5 = "Security Center" ascii //weight: 1
        $x_1_6 = "Erro ao abrir o arquivo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AMZ_2147658251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AMZ"
        threat_id = "2147658251"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Revolta.vbp" wide //weight: 1
        $x_1_2 = "\\Dia da Mulher" wide //weight: 1
        $x_1_3 = {2e 00 65 00 78 00 65 00 00 00 ?? 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 fc 06 00 00 00 6a 00 6a 00 68 ?? 19 40 00 8b 45 dc 50 ff 15 ?? 10 40 00 8b d0 8d 4d d0 ff 15 ?? 10 40 00 50 8d 4d cc 51 ff 15 ?? 10 40 00 50 68 ?? ?? 40 00 8d 55 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANC_2147658405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANC"
        threat_id = "2147658405"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 08 8b 45 fc e8 ?? ?? ?? ?? a1 ?? ?? 45 00 ba ?? ?? 45 00 e8 ?? ?? ?? ?? a1 ?? ?? 45 00 b9 ?? ?? 45 00 8b 55 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 6f 67 72 61 6d 44 61 74 61 5c [0-10] 68 74 74 70 3a 2f 2f [0-80] 2e 7a 69 70 [0-16] 77 [0-2] 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 6f 67 72 61 6d 44 61 74 61 5c [0-10] 68 74 74 70 3a 2f 2f [0-80] 2e 62 6d 70 [0-16] 77 [0-2] 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANF_2147658595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANF"
        threat_id = "2147658595"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "dl.dropbox.com/u/76724452" ascii //weight: 100
        $x_10_2 = "1itas.gif" ascii //weight: 10
        $x_10_3 = "2santa.gif" ascii //weight: 10
        $x_10_4 = "3plogi.gif" ascii //weight: 10
        $x_10_5 = "4pegavb.gif" ascii //weight: 10
        $x_10_6 = "5cxert.gif" ascii //weight: 10
        $x_10_7 = "6msnz.gif" ascii //weight: 10
        $x_10_8 = "7ztec.gif" ascii //weight: 10
        $x_30_9 = "windelete.cpl" ascii //weight: 30
        $x_20_10 = "blog.php?post=10150408488962131" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ANG_2147658631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANG"
        threat_id = "2147658631"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 eb 05 be 01 00 00 00 8b 45 ?? 0f b6 5c 30 ff 33 5d ?? 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45}  //weight: 1, accuracy: Low
        $x_1_2 = {83 38 06 7c 33 db 6a 00 6a 00 8b c7 e8 ?? ?? ?? ?? 50 8b c6 e8 ?? ?? ?? ?? 50 53 6a 00 e8 ?? ?? ?? ?? 83 f8 20 0f 97 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANI_2147658701_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANI"
        threat_id = "2147658701"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "595056605820555056505710572056905300605053405550530" wide //weight: 1
        $x_1_2 = {4f 00 20 00 61 00 72 00 71 00 75 00 69 00 76 00 6f 00 20 00 65 00 73 00 74 00 e1 00 20 00 65 00 6d 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 6f 00 20 00 64 00 65 00 73 00 63 00 6f 00 6e 00 68 00 65 00 63 00 69 00 64 00 6f 00 20 00 6f 00 75 00 20 00 64 00 61 00 6e 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = "dl.dropbox.com/u/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANJ_2147658771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANJ"
        threat_id = "2147658771"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=_nextpart_2rfkindysadvnqw3nerasdf" ascii //weight: 1
        $x_1_2 = "%s%s%s%s%s%s%s%s%s%s" ascii //weight: 1
        $x_1_3 = "ie(al(\"%s\",4),\"al(\\\"%0:s\\\",3)\",\"jk(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
        $x_1_4 = "password" ascii //weight: 1
        $x_1_5 = {62 6b 62 68 74 62 7e 78 62 6b 21 3b ba 28 c3}  //weight: 1, accuracy: High
        $x_1_6 = {7e 35 be 01 00 00 00 8b 45 ec 0f b6 7c 30 ff 8b 45 e0 0f b6 00 89 45 f4 8d 45 e4 8b d7 2b 55 f4 2b 55 f0 e8}  //weight: 1, accuracy: High
        $x_1_7 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b}  //weight: 1, accuracy: High
        $x_1_8 = "callnexthookex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANL_2147658920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANL"
        threat_id = "2147658920"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ?? ?? ?? ?? 83 f8 07 75 1c 6a 01 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 1, accuracy: High
        $x_1_3 = {46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 0f b6 44 30 ff 33 d8 8d 45 ?? 50 89 5d ?? c6 45 ?? 00 8d 55 02}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 1
        $x_1_5 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANP_2147659133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANP"
        threat_id = "2147659133"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "196310" wide //weight: 1
        $x_1_2 = "206255" wide //weight: 1
        $x_1_3 = "195312" wide //weight: 1
        $x_3_4 = "201248248259313317317" wide //weight: 3
        $x_3_5 = "2063223263222523" wide //weight: 3
        $x_3_6 = "174220294285276275288279276266294285276275288279244206271282282279296285" wide //weight: 3
        $x_3_7 = {66 83 fb 03 (76 40|77 c0) 08 00 66 83 eb (02|03)}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ANU_2147659501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANU"
        threat_id = "2147659501"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 69 00 72 00 65 00 20 00 6d 00 61 00 6e 00 73 00 20 00 6d 00 61 00 6e 00 73 00 73 00 73 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 6d 00 66 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "DelphiBasics - Game" wide //weight: 1
        $x_1_4 = {5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 00 00 00 00 ?? ?? ?? ?? ff ff ff ff 09 00 00 00 45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 05 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ANX_2147659645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANX"
        threat_id = "2147659645"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b f3 81 e6 ff 00 00 00 8b 55 fc 0f b6 54 32 ff 83 ea 10 88 54 30 ff 8d 45 f0 8b 55 fc 8a 54 32 ff}  //weight: 10, accuracy: High
        $x_1_2 = {79 75 88 80 7c 7f 82 75 43 42 3e 75 88 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 71 73 54 79 83 71 72 7c 75 5e 7f 84 79 76 89 00}  //weight: 1, accuracy: High
        $x_10_4 = {8b d8 85 db 7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2}  //weight: 10, accuracy: High
        $x_1_5 = {a3 a7 94 9c a0 9d 9a a7 9a 9a de a7 94 a7 00}  //weight: 1, accuracy: High
        $x_1_6 = {b7 ab a9 c8 a3 99 ab aa a0 a7 be 9d 98 a3 a6 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ANY_2147659653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANY"
        threat_id = "2147659653"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 e8 04 8b 00 8b d8 85 db 7e 2a be 01 00 00 00 8d 45 ec 8b 55 fc 0f b7 54 72 fe 66 2b d7 66 f7 d2}  //weight: 10, accuracy: High
        $x_1_2 = {5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 41 64 6f 62 65 41 52 4d 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 67 00 68 00 6f 00 73 00 74 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {dd 00 e6 00 c4 00 c9 00 d7 00 d2 00 dc 00 d1 00 c9 00 cd 00 c4 00 b9 00 b8 00 b1 00 ad 00 ac 00 f2 00 a6 00 b7 00 b0 00}  //weight: 1, accuracy: High
        $x_1_5 = {fb 00 04 01 e2 00 e7 00 f5 00 f0 00 fa 00 ef 00 e7 00 eb 00 e2 00 d7 00 d6 00 cf 00 cb 00 ca 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ANZ_2147659654_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANZ"
        threat_id = "2147659654"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 e8 07 00 00 00 6a 00 8d 45 e8 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 3c 01 75 17 6a 00 6a 01 68}  //weight: 5, accuracy: Low
        $x_5_2 = {54 65 6d 70 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f}  //weight: 5, accuracy: Low
        $x_1_3 = {69 70 63 6f 6e 66 69 67 20 2f 72 65 6e 65 77 00 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {4f 20 41 64 6f 62 65 20 52 65 61 64 65 72 20 6e e3 6f 20 70 f4 64 65 20 61 62 72 69 72 20 27 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 4d 44 20 2f 43 20 43 6f 70 79 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AOE_2147659857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOE"
        threat_id = "2147659857"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 0f b6 44 30 ff 8b 55 e0 89 02 8b 45 e4 0f b6 00 8b 55 e0 8b f8 89 7a 04 8d 45 e8 8b 55 e0 8b 12 2b d7}  //weight: 1, accuracy: High
        $x_1_2 = {44 43 72 70 74 ?? ?? ?? ?? ?? ?? ?? 47 65 74 55 73 44 69 72}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 73 6c 61 72 ?? ?? ?? ?? ?? ?? ?? 44 6e 4c 6f 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AOI_2147660139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOI"
        threat_id = "2147660139"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 62 00 6f 00 75 00 74 00 3a 00 62 00 6c 00 61 00 6e 00 6b 00 3f 00 63 00 68 00 65 00 63 00 6b 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 2e 00 64 00 61 00 74 00 00 00 00 00 00 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "wBloqGF.dat" wide //weight: 1
        $x_1_4 = {23 00 70 00 61 00 67 00 69 00 6e 00 61 00 2d 00 3e 00 7b 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 00 70 00 65 00 6e 00 46 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {24 00 67 00 63 00 61 00 70 00 74 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {74 00 6f 00 6b 00 65 00 6e 00 53 00 65 00 73 00 73 00 61 00 6f 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 00 3a 00 5c 00 74 00 6d 00 70 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "234214216161226225228108" wide //weight: 1
        $x_1_10 = "359401417395401363292" wide //weight: 1
        $x_1_11 = "\\HCB\\Desktop\\PEN\\2010\\BHO Remote\\Modulo Principal\\" wide //weight: 1
        $x_1_12 = {66 83 eb 03 66 ff 45 f6 66 83 fb 01 77 b1 8d 45 e4 50 0f b7 d3 b9 03 00 00 00 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_13 = {73 00 76 00 63 00 68 00 6f 00 6c 00 73 00 00 00 b0 04}  //weight: 1, accuracy: High
        $x_1_14 = "svchos:" wide //weight: 1
        $x_1_15 = {22 00 29 00 7b 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 67 00 65 00 74 00 45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 73 00 42 00 79 00 54 00 61 00 67 00 4e 00 61 00 6d 00 65 00 28 00 22 00 49 00 4e 00 50 00 55 00 54 00 22 00 29 00 2e 00 69 00 74 00 65 00 6d 00 28 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 00 2e 00 76 00 61 00 6c 00 75 00 65 00 3d 00 22 00}  //weight: 1, accuracy: Low
        $x_1_16 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3d 00 22 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3c 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_17 = {45 6e 76 69 61 53 65 6e 68 61 73 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AOG_2147660239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOG"
        threat_id = "2147660239"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sLGgLaOCV" ascii //weight: 10
        $x_1_2 = "X71YBZTPBuna4gG" ascii //weight: 1
        $x_1_3 = "YT7cHdsQ" ascii //weight: 1
        $x_1_4 = {32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AOO_2147660621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOO"
        threat_id = "2147660621"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 89 20 8d 55 f4 b8 1c 00 00 00 e8 ?? ?? ?? ?? 8d 45 f0 8b 55 f4 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 fc ba 03 00 00 00 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 f8 ba 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {84 c0 75 1b 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a 33 d2 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 84 c0 75 1b 8b 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AOQ_2147661085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOQ"
        threat_id = "2147661085"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "topshow2012.com" wide //weight: 1
        $x_1_2 = {68 00 74 00 70 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\tpp.dat" wide //weight: 1
        $x_1_4 = "\\msgs.cpl" wide //weight: 1
        $x_1_5 = "DE39825A-CB0C-4EB5-BA6F-E8555AD868D0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AOV_2147661312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOV"
        threat_id = "2147661312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Ext\\CLSID\\" ascii //weight: 3
        $x_3_2 = "Form_Guerra" ascii //weight: 3
        $x_2_3 = "www.google.com.br" wide //weight: 2
        $x_5_4 = "UPpro.dll" ascii //weight: 5
        $x_6_5 = "UPpro.Up_Class\\Clsid" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AOX_2147661338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AOX"
        threat_id = "2147661338"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "270"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "FBS\\My Proyects\\Downloader ultimo" wide //weight: 100
        $x_100_2 = "vidadeprogramador.com.br/wp-content/plugins/wlogonf.exe" wide //weight: 100
        $x_50_3 = "cgi-bin/cgibbss.exe/CORE-Main%20Web/" wide //weight: 50
        $x_20_4 = "::: BANCO DAVIVIENDA :::" wide //weight: 20
        $x_10_5 = "c:\\wlogonf.exe" wide //weight: 10
        $x_10_6 = "\\WinServiss.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ANT_2147661599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ANT"
        threat_id = "2147661599"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 55 49 45 4d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 61 71 75 69 6e 61 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 72 65 66 32 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 70 6f 73 74 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {74 00 72 00 61 00 6e 00 73 00 6c 00 65 00 74 00 2d 00 50 00 72 00 6f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_APB_2147662279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APB"
        threat_id = "2147662279"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9E52F52DE550FE34E91F016AD84521" ascii //weight: 1
        $x_1_2 = "BA49FA36DB0D3FE75FDA433814719A45E20231F" ascii //weight: 1
        $x_1_3 = "GK93H4L6HqX9IajCJKvFK55IKrHLLbXPLremEJWtDZKqCp8n85bLKKmoCqjCCZD4H" ascii //weight: 1
        $x_1_4 = "8pD3T5IaXAIqH6CpGoD5DBJ21BCqn1IqHAKqmvKbH9Iqf1GaD4HKP7I4bAIqnDJaz" ascii //weight: 1
        $x_1_5 = "_lleihBimqkz" ascii //weight: 1
        $x_1_6 = "kmleAhlpjy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_APD_2147663240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APD"
        threat_id = "2147663240"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 20, accuracy: High
        $x_1_2 = {50 8d 55 dc b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 45 dc e8 ?? ?? fe ff 50 6a 00 e8 ?? ?? ff ff b8 e8 03 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 8b 45 fc 8b 40 04 50 e8 ?? ?? ff ff 68 88 13 00 00 e8 ?? ?? fe ff 43 fe 4d ?? 75 aa}  //weight: 1, accuracy: Low
        $x_1_4 = {5b 4c 49 4e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 4c 49 4e 4b 4d 4f 44 00}  //weight: 1, accuracy: High
        $x_1_6 = "[LINKEXE 1]" ascii //weight: 1
        $x_1_7 = {2e 6d 6f 64 20 48 54 54 50 2f 31 2e 30 00}  //weight: 1, accuracy: High
        $x_1_8 = "\\AVAST Software\\Avast\\aswWebRepIE.dll" ascii //weight: 1
        $x_1_9 = {5b 46 54 50 64 00}  //weight: 1, accuracy: High
        $x_1_10 = {5b 46 54 50 55 53 45 52 00}  //weight: 1, accuracy: High
        $x_1_11 = {5b 46 54 50 50 41 53 53 00}  //weight: 1, accuracy: High
        $x_1_12 = "[FTPFOLDER]/" ascii //weight: 1
        $x_2_13 = {fe 45 ff fe cb 75 d6 68 90 5f 01 00 e8}  //weight: 2, accuracy: High
        $x_1_14 = "[CHAVEREGISTRO]\\Software\\Microsoft\\" ascii //weight: 1
        $x_1_15 = {5c 53 63 70 61 64 5c 2a 2e 2a 22 20 2f 45 20 2f 54 20 2f 52 20 41 64 6d 69 6e 69 73 74 72 61 64 6f 72 65 73 00}  //weight: 1, accuracy: High
        $x_1_16 = {5c 45 53 45 54 5c 22 20 2f 45 20 2f 43 20 2f 50 20 53 59 53 54 45 4d 3a 4e 20 54 6f 64 6f 73 3a 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_APH_2147663544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APH"
        threat_id = "2147663544"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 0f b6 92 ?? ?? ?? 00 8b 45 08 03 45 fc 0f b6 08 33 ca 8b 55 08 03 55 fc 88 0a eb c7}  //weight: 1, accuracy: Low
        $x_1_2 = {7d 26 8b 45 fc 33 d2 6a 04 59 f7 f1 0f b6 82 ?? ?? ?? ?? 8b 4d 08 03 4d fc 0f b6 09 33 c8 8b 45 08 03 45 fc 88 08 eb cb}  //weight: 1, accuracy: Low
        $x_10_3 = {68 53 11 70 6f 49 0e 70 70 54 00}  //weight: 10, accuracy: High
        $x_10_4 = {09 08 48 75 6a 21 4c 11 3b 03 56 31 3b 04 4b 2a 31 09 00 00 09 08 48 75 6a 35 5a 35 3b 15 4b}  //weight: 10, accuracy: High
        $x_10_5 = {09 08 48 75 6a 35 5a 35 3b 15 4b 14 31 10 09 77 18 14 6d 26 3a 0e 4d 26 3d 13 56 2c 30}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_APM_2147663668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APM"
        threat_id = "2147663668"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 69 62 7a 69 70 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 6d 65 6d 62 72 6f 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "{OU45MD3F-RV2M-EGW0-2W2I-OHWWWH1NH7G0}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_APP_2147664036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APP"
        threat_id = "2147664036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "iphoneupdate.cpl" ascii //weight: 1
        $x_1_2 = "DesUAC.bat" ascii //weight: 1
        $x_1_3 = {be 01 00 00 00 8b 45 ?? 0f b6 5c 30 ff 33 5d ?? 3b fb 7c ?? 81 c3 ff 00 00 00 2b df eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEC_2147665068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEC"
        threat_id = "2147665068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchoust.exe" wide //weight: 1
        $x_1_2 = "http://www.mediatown.com.br" wide //weight: 1
        $x_1_3 = "Processo finalizado com sucesso!" wide //weight: 1
        $x_1_4 = "/setup1.exe" wide //weight: 1
        $x_1_5 = "/etico/mhost/novos/google/com/br/medField" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_APS_2147665121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APS"
        threat_id = "2147665121"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 fc 17 f6 ff 8d 45 f4 ba ?? ?? 4a 00 e8 53 3e f6 ff 8d 45 f8 ba ?? ?? 4a 00 e8 46 3e f6 ff 8d 45 fc ba ?? ?? 4a 00 e8 39 3e f6 ff b8 03 00 00 00 e8 f3 17 f6 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_APT_2147665169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APT"
        threat_id = "2147665169"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~r[e]g~ [a]d[d~ [" ascii //weight: 1
        $x_1_2 = "~R]u~n^D~L^L^3]2]" ascii //weight: 1
        $x_1_3 = "^h~t[t~p~:]/~/~" ascii //weight: 1
        $x_1_4 = "[.]c]p~l[" ascii //weight: 1
        $x_1_5 = "~A]v[i~r~a" ascii //weight: 1
        $x_1_6 = "[A^v~g]T^r]a[y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_APU_2147665212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.APU"
        threat_id = "2147665212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchoust.exe" wide //weight: 1
        $x_1_2 = "http://www.mediatown.com.br/bnews/adhost/install.exe" wide //weight: 1
        $x_1_3 = "Denabled" wide //weight: 1
        $x_1_4 = "UacDisableNotify" wide //weight: 1
        $x_1_5 = "Erro ao abrir o arquivo ou o arquivo esta corrompido !" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQH_2147666528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQH"
        threat_id = "2147666528"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "casanena.com.br/img/temporario.txt?autosommundial" ascii //weight: 20
        $x_10_2 = "918EDC659E45E10434F2629B20B04F" ascii //weight: 10
        $x_10_3 = "47F06087BE729391A545E45DAE22CD74D675DE14CE79A75B82" ascii //weight: 10
        $x_10_4 = "4BD878AEBB43C2A586E718C81E0F20CB054486FE79EE79899A97F20027DC1AC1619CA8AF7DDB111F287C" ascii //weight: 10
        $x_5_5 = "0F27B9578ABDBDBFBC52CB405CAE5C89C9094EFD152EE91417323B6D" ascii //weight: 5
        $x_5_6 = "3BEC649B45F42C0A3CFF39" ascii //weight: 5
        $x_5_7 = "CB0453FE649B46FD" ascii //weight: 5
        $x_5_8 = "D066ED1411162F323530C061F6" ascii //weight: 5
        $x_10_9 = "656757657657.3utilities.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_5_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AQI_2147666707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQI"
        threat_id = "2147666707"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-10] 2f 61 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_2 = {73 69 73 74 65 6d 61 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 2e 65 78 65 00 00 00 00 00 00 00 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {80 7c 30 ff 2f 75 d2 8d 85 44 fe ff ff 50 68 01 01 00 00 e8 ?? ?? ?? ?? 6a 00 6a 01 6a 02 e8 ?? ?? ?? ?? 8b f0 66 c7 85 34 fe ff ff 02 00 83 ff 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQK_2147666846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQK"
        threat_id = "2147666846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 52 4c 4d 4f 4e 2e 44 4c 4c 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: High
        $x_10_2 = {44 00 6a 00 e8 ?? ?? ?? ff 68 ?? ?? 44 00 e8 ?? ?? ?? ff 8b d8 85 db (74 24|0f 84) [0-4] 68 ?? ?? 44 00}  //weight: 10, accuracy: Low
        $x_10_3 = {44 00 6a 00 e8 ?? ?? ?? ff 6a 05 68 ?? ?? 44 00 e8 ?? ?? ?? ff 6a 00 6a 00 68 ?? ?? 44 00 68 ?? ?? 44 00 6a 00 e8 ?? ?? ?? ff 6a 05 68 ?? ?? 44 00 e8 ?? ?? ?? ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQL_2147667203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQL"
        threat_id = "2147667203"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qubkdD" ascii //weight: 1
        $x_1_2 = "sLGgLaOCV" ascii //weight: 1
        $x_1_3 = {e8 cd fe ff ff 8b 45 fc 8b ce 66 ba c3 84 e8 5b ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQM_2147667645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQM"
        threat_id = "2147667645"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 2d f4 1e 70 64 ff 28 30 ff 01 00 fc f6 50 ff f3 ff 00 70 66 ff 1b ?? 00 43 74 ff 28 10 ff 01 00 04 40 ff 80 0c 00 4a fd 69 20 ff fe 68 f0 fe 77 01 0a ?? 00 00 00 04 50 ff 28 30 ff 01 00 fb 9c e0 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQN_2147669198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQN"
        threat_id = "2147669198"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 83 e2 03 8a 92 ?? ?? 40 00 30 14 08 40 3b c6 7c ed c3}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d5 eb 3b 33 ff 8d 9b 00 00 00 00 8b 4c fc 10 51 56 ff d3 89 44 fc 14 85 c0 74 e3 47 83 ff 03 7c ea 8b 54 24 14}  //weight: 1, accuracy: High
        $x_10_3 = {09 08 48 75 6a 21 4c 11 3b 03 56 31 3b 04 4b 2a 31 09 00 00 09 08 48 75 6a 35 5a 35 3b 15 4b}  //weight: 10, accuracy: High
        $x_10_4 = {09 08 48 75 6a 35 5a 35 3b 15 4b 14 31 10 09 77 18 14 6d 26 3a 0e 4d 26 3d 13 56 2c 30}  //weight: 10, accuracy: High
        $x_10_5 = {29 10 48 6d 37 17 5c 26 30 13 5a 31 70 06 4b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AQO_2147669199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQO"
        threat_id = "2147669199"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 0f b6 92 ?? ?? 40 00 8b 45 08 03 45 fc 0f b6 08 33 ca 8b 55 08 03 55 fc 88 0a eb c7}  //weight: 1, accuracy: Low
        $x_1_2 = {7d 26 8b 45 fc 33 d2 6a 04 59 f7 f1 0f b6 82 ?? ?? 40 00 8b 4d 08 03 4d fc 0f b6 09 33 c8 8b 45 08 03 45 fc 88 08 eb cb}  //weight: 1, accuracy: Low
        $x_10_3 = {67 71 bd fe 4d 70 bd e4 67 72 ad e7 50 78 e1 e4 42 66}  //weight: 10, accuracy: High
        $x_10_4 = {0d 21 e1 a4 0a 3b fe a4 15 26 00}  //weight: 10, accuracy: High
        $x_10_5 = {5a 77 ac f3 5e 73 a8 ff 52 7f a4 fb 56 7b a0 e7 4a 67 bc e3 4e 63 b8 ef 42 6f ff a6 09 26 fb a2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AQS_2147671233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQS"
        threat_id = "2147671233"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 30 37 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 6d 00 00 ff ff ff ff 06 00 00 00 69 64 2e 73 79 73 00 00 ff ff ff ff 5c 00 00 00 44 38 37 35 39 31 38 36 39 36 44 46 31 32 32 46 33 38 41 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQS_2147671233_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQS"
        threat_id = "2147671233"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "257"
        strings_accuracy = "High"
    strings:
        $x_200_1 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 200, accuracy: High
        $x_50_2 = {00 68 74 74 70 3a 2f 2f 31 36 38 2e 36 31 2e 38 37 2e 31 37 39 2f}  //weight: 50, accuracy: High
        $x_50_3 = {41 70 70 6c 65 74 4d 6f 64 75 6c 65 41 63 74 69 76 61 74 65 09 54 4f 76 6f 66 72 69 74 6f}  //weight: 50, accuracy: High
        $x_5_4 = {54 6f 72 61 54 6f 72 61 00}  //weight: 5, accuracy: High
        $x_1_5 = {00 53 68 65 6c 6c 33 32 2e 44 4c 4c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 00 ff ff ff}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff ff ff 04 00 00 00 32 30 30 30 00 00 00 00 ff ff ff ff 02 00 00 00 58 50 00 00 ff ff ff ff 05 00 00 00 56 69 73 74 61 00 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_7 = {ff ff ff ff 07 00 00 00 75 61 63 2e 6c 6f 67 00 ff ff ff ff 04 00 00 00 5a 45 52 4f 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_200_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AQU_2147671749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQU"
        threat_id = "2147671749"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 70 6c 65 74 4d 6f 64 75 6c 65 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 56 41 4c 4f 52 45 53 52 45 47 49 53 54 52 4f 44 45 4c 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = "[CHAVEREGISTRO" ascii //weight: 1
        $x_1_4 = "[COMANDO" ascii //weight: 1
        $x_1_5 = {63 6d 64 20 2f 4b 20 63 61 63 6c 73 20 22 25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 53 63 70 61 64 22 20 2f 45 20 2f 54 20 2f 44 20 54 4f 44 4f 53 00}  //weight: 1, accuracy: High
        $x_1_6 = {22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 61 76 67 66 77 64 78 2e 64 6c 6c 22 20 2f 45 20 2f 54 20 2f 44 20 53 59 53 54 45 4d 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c 4d 46 41 44 61 74 61 5c 2a 2e 2a 22 20 2f 45 20 2f 54 20 2f 52 20 41 64 6d 69 6e 69 73 74 72 61 64 6f 72 65 73 00}  //weight: 1, accuracy: High
        $x_1_8 = "cmd /K cacls \"%programfiles%\\Avira\\AntiVir Desktop" ascii //weight: 1
        $x_1_9 = "cmd /K cacls \"%programfiles%\\AVG\\AVG2013\\*.*\"" ascii //weight: 1
        $x_1_10 = {5b 4c 49 4e 4b 4d 4f 44 20 ?? 5d 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_11 = {22 25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 41 56 41 53 54 20 53 6f 66 74 77 61 72 65 22 20 2f 45 20 2f 54 20 2f 44 20 53 59 53 54 45 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AQV_2147676004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQV"
        threat_id = "2147676004"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 00 00 00 4f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 74 00 61 00 74 00 65 00 00 00 43 00 6c 00 6f 00 73 00 65 00}  //weight: 1, accuracy: High
        $x_10_3 = {83 7a 34 00 75 20 8b 45 08 83 c0 34 09 00 ff 90}  //weight: 10, accuracy: Low
        $x_100_4 = {50 51 ff d7 50 8d 55 94 56 52 ff 15 ?? ?? 40 00 8b d0 8d 4d a4 ff 15 ?? ?? 40 00 50 6a 00 ff 15 ?? ?? 40 00 8d 4d a4}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AQY_2147678353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AQY"
        threat_id = "2147678353"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 55 df 88 54 30 ff 46 4f 75 c1}  //weight: 1, accuracy: High
        $x_1_2 = {8b 00 8b 08 ff 51 38 8d 45 ?? 50 8b 0e 8b 13 b8 ?? ?? ?? 00 e8 ?? ?? 00 00 8b 55 ?? a1 ?? ?? ?? 00 8b 00 8b 08 ff 51 38 8d 45 ?? 50 8b 0e 8b 13 b8 ?? ?? ?? 00 e8 ?? ?? 00 00 8b 55 ?? a1 ?? ?? ?? 00 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARC_2147678580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARC"
        threat_id = "2147678580"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 5c 30 ff 8d 55 ?? 8b c3 25 01 00 00 80 79 05 48 83 c8 fe 40}  //weight: 10, accuracy: Low
        $x_5_2 = {50 8b 0e 8b 13 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f8 50 8b 0e 8b 13 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 ec b8 1a 00 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = {50 8b 0e 8b 13 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 fc 8b 07 e8 ?? ?? ?? ?? 8d 45 f8 50 8b 0e 8b 13 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f8 8b 07 83 c0 04 e8 ?? ?? ?? ?? 8d 45 f4 50 8b 0e 8b 13 b8}  //weight: 5, accuracy: Low
        $x_3_4 = {46 46 46 1f 56 5f 5f 56 5d 54 1f 52 5f 5d 1f 53 43 00}  //weight: 3, accuracy: High
        $x_2_5 = {42 59 54 5c 5c 03 02 1f 55 5d 5d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZED_2147678766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZED"
        threat_id = "2147678766"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 05 83 fb 03 7e de 1b 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 ?? 8b 55 ?? e8 ?? ?? ff ff 43 84 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 ?? ?? fe ff 8b 55 f0 8d 45 f8 e8 ?? ?? fe ff 80 f3 01 47 4e 75 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARE_2147678794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARE"
        threat_id = "2147678794"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 6e 69 63 69 6f 75 20 44 6f 77 6e 6c 6f 61 64 00}  //weight: 5, accuracy: High
        $x_5_2 = {32 00 45 00 37 00 41 00 36 00 39 00 37 00 30 00 00 00 00 00 07 00 00 00 75 72 6c 6d 6f 6e 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54}  //weight: 5, accuracy: High
        $x_1_3 = {35 00 43 00 37 00 33 00 37 00 39 00 37 00 33 00 37 00 34 00 36 00 35 00 36 00 44 00 33 00 33 00 33 00 32 00 32 00 46 00 [0-16] 32 00 45 00 37 00 41 00 36 00 39 00 37 00 30}  //weight: 1, accuracy: Low
        $x_1_4 = {36 00 33 00 33 00 41 00 35 00 43 00 37 00 37 00 36 00 39 00 36 00 45 00 36 00 34 00 36 00 46 00 37 00 37 00 37 00 33 00 32 00 46 00 [0-16] 32 00 45 00 37 00 41 00 36 00 39 00 37 00 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZEE_2147679030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEE"
        threat_id = "2147679030"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 10, accuracy: High
        $x_10_2 = "ao abrir o arquivo" ascii //weight: 10
        $x_10_3 = "certifico.com.br/" ascii //weight: 10
        $x_1_4 = "Tmain019290" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEE_2147679030_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEE"
        threat_id = "2147679030"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_2 = "ao abrir o arquivo" ascii //weight: 1
        $x_1_3 = "TAppJava" ascii //weight: 1
        $x_1_4 = "TGerming" ascii //weight: 1
        $x_1_5 = {8d 45 f8 e8 85 fe ff ff ff 75 f8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? [0-16] 8d 45 fc ba ?? 00 00 00 e8 ?? ?? ?? ?? 8b 4d fc ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEE_2147679030_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEE"
        threat_id = "2147679030"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 10, accuracy: High
        $x_10_2 = "ao abrir o arquivo" ascii //weight: 10
        $x_10_3 = ".mediatown.com.br" ascii //weight: 10
        $x_10_4 = ".copercana.com.br" ascii //weight: 10
        $x_1_5 = "OWS\\ctfmon" wide //weight: 1
        $x_1_6 = "OWS\\taskman" wide //weight: 1
        $x_1_7 = "taskmann.exe" ascii //weight: 1
        $x_1_8 = {6d 6f 6d 33 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ARM_2147679259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARM"
        threat_id = "2147679259"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://uploads.boxify.me/" ascii //weight: 1
        $x_1_2 = {eb 52 80 7d e7 00 74 4c 8b 45 fc 80 b8 8b 00 00 00 02 75 40 8b 45 fc 66 81 b8 38 01 00 00 fc 00 73 0f 8d 45 e8 ba}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f4 05 a0 00 00 00 8b 55 fc e8 ?? ?? ?? ff 8b 45 f4 05 b0 00 00 00 8b 55 f8 e8 ?? ?? ?? ff 33 d2 8b 45 f4 8b 08 ff 51 40 33 c0 5a 59 59}  //weight: 1, accuracy: Low
        $x_1_4 = {80 7d ff 00 75 7e b8 1a 00 00 00 e8 ?? ?? ?? ff 8b 14 85 ?? ?? ?? ?? 8d 45 f8 e8 ?? ?? ?? ff 80 7d fe 00 74 40 b8 02 00 00 00 e8 ?? ?? ?? ff 2c 01 72 04 74 19 eb 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARQ_2147679408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARQ"
        threat_id = "2147679408"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "n\\Run /f /v evx /d \"regsvr32" ascii //weight: 1
        $x_1_2 = {5c 65 76 78 2e 72 33 78 00 72 [0-6] ?? ?? ?? ?? (68|74|70|5b|5d|3a|2f) (68|74|70|5b|5d|3a|2f)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARQ_2147679408_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARQ"
        threat_id = "2147679408"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc b9 2b 00 00 00 b0 00 f3 aa 8b 45 ?? 89 44 24 04}  //weight: 1, accuracy: Low
        $x_1_2 = "?chave=xchave&url=infected_" ascii //weight: 1
        $x_1_3 = "add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /v evx /d \"regsvr32 /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARR_2147679430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARR"
        threat_id = "2147679430"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 54 72 fe 66 2b d7 66 f7 d2 e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 46 4b 75 db}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd /c start c:\\arquiv~1\\wlanapp.cpl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ART_2147679610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ART"
        threat_id = "2147679610"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f bf c7 52 8b 11 50 52 c7 45 ?? 01 00 00 00 c7 45 ?? 02 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 8d 4d}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\Fontes\\Evx13\\load" wide //weight: 1
        $x_1_3 = {63 00 3a 00 5c 00 61 00 73 00 64 00 66 00 5c 00 73 00 64 00 66 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 6f 6d 65 50 43 00 00 43 6f 6e 74 61 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 77 69 6e 68 74 74 70 2e 64 6c 6c 00 57 69 6e 48 74 74 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARV_2147679749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARV"
        threat_id = "2147679749"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Program Files (x86)\\GbPlugin\\bb.gpc" ascii //weight: 2
        $x_2_2 = "CICLS.d" ascii //weight: 2
        $x_2_3 = "GarantirDLL" ascii //weight: 2
        $x_3_4 = "InforInfec" ascii //weight: 3
        $x_5_5 = "Provider=SQLOLEDB.1;Password=master19778212;Persist Security Info=True;User ID=logcontagem;Initial Catalog=contagem;Data Sourc" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARW_2147679766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARW"
        threat_id = "2147679766"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 52 41 4e 44 4f 4d 25 00}  //weight: 1, accuracy: High
        $x_1_2 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 ?? ?? ?? ff 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ff 80 f3 01 47}  //weight: 1, accuracy: Low
        $x_1_3 = {75 05 83 fb 03 7e d9 8d 4d 20 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 ?? 8b 55 ?? e8 ?? ?? ff ff 88 45 ?? 43 80 7d ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 e0 ef ff ff e8 ?? ?? ?? ff 50 e8 ?? ?? ff ff 8b f0 85 f6 0f 84 cd 00 00 00 6a 00 68 00 01 00 84 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ff 50 56 e8 0a 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARY_2147679809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARY"
        threat_id = "2147679809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0}  //weight: 2, accuracy: High
        $x_2_2 = {64 ff 30 64 89 20 8d 55 f8 b8 1c 00 00 00 e8 ?? ?? ?? ?? 8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 03 0f 8e 58 01 00 00 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 55 f0 33 c0 e8 ?? ?? ?? ?? 8b 45 f0 8d 55 f4 e8}  //weight: 2, accuracy: Low
        $x_1_4 = {43 4d 44 20 2f 43 20 53 74 61 72 74 20 00 00 00 53 56 81 c4 f8 fe ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {5c 6c 69 62 6d 79 73 71 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 72 65 73 6f 6c 76 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 75 62 65 72 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 61 72 71 75 69 76 6f 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ASB_2147679947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASB"
        threat_id = "2147679947"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 ?? ?? ?? ff 8b 55 f0 8d 45 f8 e8 ?? ?? ?? ff 80 f3 01 47}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f4 50 68 00 10 00 00 8d 85 e6 ef ff ff 50 53 e8 ?? ?? ?? ?? 85 c0 74 26 83 7d f4 00 76 1a 81 7d f4 00 10 00 00 77 11 8d 95 e6 ef ff ff 8b 4d f4 8b 45 f8 8b 30}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e8 04 8b 00 83 f8 01 7c 13 8b 55 fc 80 7c 02 ff 2f 75 04 8b d8 eb}  //weight: 1, accuracy: High
        $x_1_4 = "madSecurityU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASI_2147680208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASI"
        threat_id = "2147680208"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcessHacker" wide //weight: 1
        $x_1_2 = "filemon.exe" wide //weight: 1
        $x_1_3 = "snxhk" wide //weight: 1
        $x_1_4 = "C:\\analysis" wide //weight: 1
        $x_1_5 = "(Brasil)" wide //weight: 1
        $x_1_6 = "Penteste" wide //weight: 1
        $x_1_7 = "winmgmts:\\\\%s\\%s" wide //weight: 1
        $x_1_8 = {46 00 55 00 52 00 54 00 45 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASJ_2147680303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASJ"
        threat_id = "2147680303"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 e2 fe fe fa b0 a5 a5}  //weight: 1, accuracy: High
        $x_1_2 = {00 41 6c 72 55 6e 65 70 4f 74 65 6e 72 65 74 6e 49 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 c2 c5 c7 cf ce d8 c3 dc cf 00}  //weight: 1, accuracy: High
        $x_1_4 = {ba 89 8a 01 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {33 d2 8a 55 ?? 8b 4d ?? 8a 54 11 ff 8b ce c1 e9 08 32 d1 e8 ?? ?? ff ff 8b 55 ?? 8d 45 ?? e8 ?? ?? ff ff fe 45 ?? fe cb 75 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASK_2147680365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASK"
        threat_id = "2147680365"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 85 64 ff ff ff 08 40 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb 6d 66 8b c8 66 2b 4d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3b cb 7d 3b b9 ff 00 00 00 6a 1e 66 2b 4d}  //weight: 5, accuracy: Low
        $x_5_2 = {68 34 08 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 4c 04 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 b8 0b 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 83 7d fc 00 75 05}  //weight: 5, accuracy: Low
        $x_5_3 = {c7 45 fc 03 00 00 00 8b 45 08 83 78 34 00 75 1f 8b 45 08 83 c0 34 50 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 08 83 c0 34 89 85 7c ff ff ff eb 0c 8b 45 08 83 c0 34}  //weight: 5, accuracy: Low
        $x_1_4 = {52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 00 00 52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 00 69 00 65 00 6c 00 64 00 73 00 00 00 00 00 56 00 61 00 6c 00 75 00 65 00 00 00 57 00 72 00 69 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 00 00 00 4f 00 70 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "SaveToFile" wide //weight: 1
        $x_1_8 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {53 00 74 00 61 00 74 00 65 00 00 00 43 00 6c 00 6f 00 73 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ASL_2147680403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASL"
        threat_id = "2147680403"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 0f b7 44 70 fe 33 c3 89 45 dc 3b 7d dc 7c ?? 8b 45 dc 05 ff 00 00 00 2b c7 89 45 dc eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f4 33 d2 e8 ?? ?? ?? ?? 8b 45 f0 85 c0 74 ?? 8b d0 83 ea 0a 66 83 3a 02}  //weight: 1, accuracy: Low
        $x_1_3 = {89 03 8b 03 8b 10 ff 52 44 8d 4d fc ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 fc 8b 03 8b 08 ff 51 38 8d 4d f8 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f8 8b 03 8b 08 ff 51 38 8d 4d f4 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AST_2147681738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AST"
        threat_id = "2147681738"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f bf c7 52 8b 11 50 52 c7 45 ?? 01 00 00 00 c7 45 ?? 02 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 8d 4d}  //weight: 2, accuracy: Low
        $x_3_2 = "Project1.VbDL" ascii //weight: 3
        $x_3_3 = "krai2" ascii //weight: 3
        $x_4_4 = {63 00 3a 00 5c 00 61 00 73 00 64 00 66 00 5c 00 73 00 64 00 66 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASV_2147682074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASV"
        threat_id = "2147682074"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 44 30 ff 33 c3 89 45}  //weight: 1, accuracy: High
        $x_10_3 = {8b 18 ff 53 10 83 7d e8 00 75 d0 33 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASW_2147682100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASW"
        threat_id = "2147682100"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\WINDOWS\\Inf\\~3778.tmp" ascii //weight: 2
        $x_2_2 = "CPlApplet" ascii //weight: 2
        $x_3_3 = "MadException" ascii //weight: 3
        $x_3_4 = "madStrings" ascii //weight: 3
        $x_4_5 = "madSecurity" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASX_2147682130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASX"
        threat_id = "2147682130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "69.64.39.131/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_2 = "74.63.220.41/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_3 = "198.56.181.246/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_4 = "216.245.193.27/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_5 = "69.162.68.219/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_6 = "208.115.197.117/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_7 = "comicexpressmma.com.br/autrsuhpconfig.pac" ascii //weight: 1
        $x_1_8 = "C:\\Windows\\System32\\lordpbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ASZ_2147682357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASZ"
        threat_id = "2147682357"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 5c 72 65 73 6f 6c 76 65 72 2e 65 78 65 00 00 00 ff ff ff ff 06 00 00 00 2f 6e 6f 67 75 69 00 00 ff ff ff ff 09 00 00 00 5c 75 62 65 72 2e 74 78 74 00}  //weight: 5, accuracy: High
        $x_1_2 = {5c 74 65 6d 70 2e 7a 69 70 00 00 00 ff ff ff ff ?? 00 00 00 5c [0-15] 2e 65 78 65 [0-3] 00 ff ff ff ff ?? 00 00 00 5c 6d 65 64 69 61 63 65 6e 74 [0-3] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 74 65 6d 70 2e 7a 69 70 00 00 00 ff ff ff ff 11 00 00 00 5c 65 78 74 65 6e 73 6f 72 6a 61 76 61 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ASZ_2147682357_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASZ"
        threat_id = "2147682357"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3}  //weight: 5, accuracy: High
        $x_1_2 = {2e 62 61 74 00 00 00 00 ff ff ff ff 02 00 00 00 3a 31 00 00 ff ff ff ff 0a 00 00 00 65 72 61 73 65 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_3 = "If exist \"%s\" Goto 1" ascii //weight: 1
        $x_1_4 = "ie(al(\"%s\",4),\"al(\\\"%0:s\\\",3)\",\"jk(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
        $x_1_5 = "{DELETE}" ascii //weight: 1
        $x_1_6 = "{PGDN}" ascii //weight: 1
        $x_1_7 = "{DOWN}" ascii //weight: 1
        $x_1_8 = "{BKSP}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ASZ_2147682357_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ASZ"
        threat_id = "2147682357"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "211"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55}  //weight: 100, accuracy: Low
        $x_100_2 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM" ascii //weight: 100
        $x_10_3 = {2e 62 61 74 00 00 00 00 ff ff ff ff 02 00 00 00 3a 31 00 00 ff ff ff ff 0a 00 00 00 65 72 61 73 65 20 22 25 73 22}  //weight: 10, accuracy: High
        $x_10_4 = "If exist \"%s\" Goto 1" ascii //weight: 10
        $x_1_5 = "TaskbarCreated" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ATA_2147682438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ATA"
        threat_id = "2147682438"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 50 72 6f 6a 65 63 74 ?? 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 100, accuracy: Low
        $x_1_2 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 46 6c 61 73 68 50 6c 61 79 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 63 6f 6d 2e 62 72 2f 46 6c 61 73 68 50 6c 61 79 65 72 2f 46 6c 61 73 68 50 6c 61 79 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ATA_2147682438_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ATA"
        threat_id = "2147682438"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "531"
        strings_accuracy = "Low"
    strings:
        $x_500_1 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 500, accuracy: High
        $x_20_2 = {2f 73 65 74 75 70 2e 78 6d 6c 00 [0-4] ff ff ff ff 0a 00 00 00 49 6e 73 74 61 6c 2e 78 6d 6c}  //weight: 20, accuracy: Low
        $x_20_3 = {16 00 00 00 5c 47 62 50 6c 75 67 69 6e 5c 67 62 69 65 68 61 62 6e 2e 64 6c 6c 00}  //weight: 20, accuracy: High
        $x_20_4 = {54 41 70 70 6c 65 74 4d 6f 64 75 6c 65 47 6f 6f 67 6c 65 ?? ?? ?? ?? ?? ?? ?? ?? 10 00 0c 41 70 70 6c 65 74 47 6f 6f 67 6c 65 00}  //weight: 20, accuracy: Low
        $x_10_5 = {2f 76 61 6d 6f 73 30 30 31 2f 73 65 74 75 70 2e 78 6d 6c 00}  //weight: 10, accuracy: High
        $x_10_6 = {44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c (53 74 61|4d 79 78) [0-32] 5c 00 [0-18] ff ff ff ff 09 00 00 00 73 65 74 75 70 2e 78 6d 6c 00}  //weight: 10, accuracy: Low
        $x_10_7 = {2f 63 65 72 74 69 66 69 63 61 64 6f 2f 72 65 73 74 61 75 72 65 2e 6d 70 33 00}  //weight: 10, accuracy: High
        $x_10_8 = "/bdvr001/restaure." ascii //weight: 10
        $x_10_9 = {2f 6c 69 76 72 61 72 69 61 [0-2] 2f 73 65 74 75 70 2e 78 6d 6c}  //weight: 10, accuracy: Low
        $x_10_10 = {2f 61 6e 64 72 6f 69 64 [0-2] 2f 73 65 74 75 70 2e 78 6d 6c 00}  //weight: 10, accuracy: Low
        $x_10_11 = {2e 69 6e 66 6f 2f 64 6f 63 [0-2] 2f 64 6f 63 75 6d 65 6e 74 6f 2e 64 6f 63 00}  //weight: 10, accuracy: Low
        $x_10_12 = {2f 43 6f 6d 70 61 63 74 61 64 6f 2e 7a 6c 69 62 00}  //weight: 10, accuracy: High
        $x_10_13 = {00 41 64 6f 62 65 2d 46 6c 61 73 68 2d 50 6c 61 79 65 72 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_14 = {00 49 6e 73 74 61 6c 61 64 6f 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_15 = {2f 72 65 73 74 61 75 72 65 2e 78 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 72 65 73 74 61 75 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_17 = {2f 66 69 6c 65 2e 64 6f 63 00}  //weight: 1, accuracy: High
        $x_1_18 = {ff ff ff ff 07 00 00 00 64 6f 63 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_500_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_500_*) and 4 of ($x_10_*))) or
            ((1 of ($x_500_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_500_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_500_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ATB_2147682441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ATB"
        threat_id = "2147682441"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 6f 64 31 30 2f 6d 61 6e 61 34 2e 70 64 66 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 6f 64 37 30 2f 6a 75 6c 69 61 31 30 2e 68 6c 70 00}  //weight: 1, accuracy: High
        $x_2_3 = "http://cpro17738.publiccloud.com.br/" ascii //weight: 2
        $x_10_4 = {00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ATC_2147682578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ATC"
        threat_id = "2147682578"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 38 41 30 32 38 38 33 39 46 43 33 44 31 44 38 37 37 34 35 38 35 36 41 45 46 31 42 35 34 00 00 ff ff ff ff 06 00 00 00 61 72 71 75 69 76 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 32 44 42 31 31 36 34 36 38 38 43 44 31 46 42 43 31 31 42 31 00 00 00 00 ff ff ff ff 16 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 63 65 74 2e 65 78 65 00 ff ff ff ff 2e 00 00}  //weight: 2, accuracy: High
        $x_3_4 = {00 4c 6f 61 64 65 72 5f 32 30 31 33 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 3, accuracy: High
        $x_3_5 = {00 4c 6f 61 64 5f 63 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 3, accuracy: High
        $x_3_6 = {00 4c 6f 61 64 65 72 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ATE_2147682677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ATE"
        threat_id = "2147682677"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 34 00 50 00 35 00 45 00 33 00 4b 00 6e 00 43 00 4a 00 4c 00 31 00 43 00 4b 00 4f 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 00 45 00 4d 00 50 00 00 00 00 00 b0 04 02 00 ff ff ff ff 08 00 00 00 5c 00 6c 00 66 00 6f 00 2e 00 62 00 61 00 74 00 00 00 00 00 b0 04 02 00 ff ff ff ff 02 00 00 00 3a 00 31 00 00 00 00 00 b0 04 02 00 ff ff ff ff 04 00 00 00 22 00 25 00 73 00 22 00 00 00 00 00 b0 04 02 00 ff ff ff ff 0a 00 00 00 45 00 72 00 61 00 73 00 65 00 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ATU_2147683603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ATU"
        threat_id = "2147683603"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Button7Click" ascii //weight: 2
        $x_2_2 = "CPlApplet" ascii //weight: 2
        $x_3_3 = "ACCTimer" ascii //weight: 3
        $x_3_4 = "TABAJARA" ascii //weight: 3
        $x_3_5 = "C:\\Documents and Settings\\Administrator\\HAL9TH.log" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AUK_2147684342_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AUK"
        threat_id = "2147684342"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "conf.xml" ascii //weight: 1
        $x_1_3 = "servicesnb.exe" ascii //weight: 1
        $x_1_4 = "ol.dll" ascii //weight: 1
        $x_1_5 = "AppletModuleActivate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AUU_2147684583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AUU"
        threat_id = "2147684583"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Loader.cpl" ascii //weight: 2
        $x_2_2 = "TAPPMOD" wide //weight: 2
        $x_4_3 = "%Ijkg37IUHGSAD4dagumbil" ascii //weight: 4
        $x_5_4 = "%#$8732g6asd{OFF.LINES}SGH87y32g890{BERTIOLY}tbsmnspeleialeielsgbk+=(" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AUV_2147684605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AUV"
        threat_id = "2147684605"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 55 47 43 50 6c 2e 63 70 6c [0-32] 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e0 a0 06 10 8d 85 5c fb ff ff 50 e8 4c 47 00 00 83 c4 08 c7 85 24 f7 ff ff ?? ?? 06 10 8d 85 5c fb ff ff 89 85 18 f7 ff ff 6a 00 6a 00 8b 85 18 f7 ff ff 50 8b 8d 24 f7 ff ff 51 6a 00 e8 92 2e 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AVC_2147685073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AVC"
        threat_id = "2147685073"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 b8 44 00 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {66 b8 44 00 e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 83 f8 20 0f 97 c3 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {bf 00 01 00 00 66 83 eb 43 74 0e 66 ff cb 0f 84 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AVF_2147685317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AVF"
        threat_id = "2147685317"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "-y -pxupa" wide //weight: 5
        $x_1_2 = "jw-player-plugin-for-wordpress/" wide //weight: 1
        $x_1_3 = "cri.servegame.com/?u=" wide //weight: 1
        $x_1_4 = {53 00 6d 00 61 00 72 00 74 00 53 00 63 00 72 00 65 00 65 00 6e 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 00 07 4f 00 66 00 66 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 68 00 69 00 73 00 68 00 69 00 6e 00 67 00 46 00 69 00 6c 00 74 00 65 00 72 00 [0-5] 6e 00 61 00 62 00 6c 00 65 00 64 00 56 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AVQ_2147685915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AVQ"
        threat_id = "2147685915"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\chris.txt" wide //weight: 1
        $x_1_2 = "cmd /c start C:\\ProgramData\\authd.cpl" ascii //weight: 1
        $x_1_3 = "cmd /c start C:\\ARQUIV~1\\26.cpl" ascii //weight: 1
        $x_1_4 = "cmd /c start C:\\ProgramData\\76.cpl" ascii //weight: 1
        $x_1_5 = "C:\\Program Files\\76.cpl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AVT_2147685980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AVT"
        threat_id = "2147685980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "alreadrycomparepricespopularearh" ascii //weight: 1
        $x_1_2 = "kidinlhatinaformem-soltlavin" ascii //weight: 1
        $x_1_3 = {5c 52 75 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 73 65 72 50 72 6f 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {36 34 2e 65 78 65 15 00 61 73 77}  //weight: 1, accuracy: Low
        $x_1_5 = "GetPCName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWE_2147687036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWE"
        threat_id = "2147687036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 74 16 48 74 1f 83 e8 03 0f 84 8b 00 00 00 83 e8 03 74 1a e9 88 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {c7 45 f0 01 00 00 00 8d 45 e0 8b 55 fc 8b 4d f0 66 8b 54 4a fe 66 8b 4d fa 66 2b d1 66 f7 d2 e8}  //weight: 5, accuracy: High
        $x_1_3 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 [0-64] 5c 00 53 00 63 00 70 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 63 00 70 00 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 00 45 00 72 00 72 00 6f 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 61 00 73 00 20 00}  //weight: 1, accuracy: Low
        $x_1_6 = "\\compx86.zip" wide //weight: 1
        $x_1_7 = "/c sc config wscsvc start=" wide //weight: 1
        $x_1_8 = "LUSTADORES, COMPROMETIDOS, HONESTIDADE" wide //weight: 1
        $x_1_9 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 [0-16] 5c [0-16] 2e 63 70 6c}  //weight: 1, accuracy: Low
        $x_1_10 = {45 00 73 00 74 00 65 00 20 00 61 00 72 00 71 00 75 00 69 00 76 00 6f 00 20 00 65 00 73 00 74 00 e1 00 20 00 63 00 6f 00 72 00 72 00 6f 00 6d 00 70 00 69 00 64 00 6f 00 20 00 65 00 20 00 6e 00 e3 00 6f 00 20 00 70 00 6f 00 64 00 65 00 20 00 73 00 65 00 72 00 20 00 61 00 62 00 65 00 72 00 74 00 6f 00 21 00}  //weight: 1, accuracy: High
        $x_1_11 = "\\chris.txt" wide //weight: 1
        $x_1_12 = "frm_daruma" wide //weight: 1
        $x_1_13 = "IgfxTray Launch..." wide //weight: 1
        $x_1_14 = "MediaPlayer.dll" wide //weight: 1
        $x_1_15 = "frm_drops" wide //weight: 1
        $x_1_16 = "\\ntuser.log" wide //weight: 1
        $x_1_17 = {67 00 65 00 72 00 6f 00 75 00 20 00 75 00 6d 00 20 00 65 00 72 00 72 00 6f 00 20 00 65 00 20 00 6e 00 e3 00 6f 00 20 00 70 00 6f 00 64 00 65 00 20 00 73 00 65 00 72 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 61 00 64 00 6f 00}  //weight: 1, accuracy: High
        $x_1_18 = "\\devicepack.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AWF_2147687117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWF"
        threat_id = "2147687117"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 72 69 76 38 2e 67 6f 6f 67 6c 65 63 6f 64 65 2e 63 6f 6d 2f 73 76 6e 2f 52 75 6e 61 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 52 75 6e 61 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWI_2147687561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWI"
        threat_id = "2147687561"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 e8 0f b6 44 30 ff 33 c3 89 45 e0 3b 7d e0 7c 0f 8b 45 e0}  //weight: 4, accuracy: High
        $x_1_2 = "\\cmd.exe /k regsvr32.exe  \"" ascii //weight: 1
        $x_1_3 = "aplicativos\\" ascii //weight: 1
        $x_1_4 = "2.jpg\"" ascii //weight: 1
        $x_1_5 = "5.cpl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWI_2147687561_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWI"
        threat_id = "2147687561"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {35 2e 63 70 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 2e 74 78 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 2e 6a 70 67}  //weight: 10, accuracy: Low
        $x_1_2 = {4f 4e 5c 52 55 4e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 3a 5c 57 69 6e 64 6f 77 73 5c 53}  //weight: 1, accuracy: Low
        $x_1_3 = {00 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = "Tcabecadomeupau" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AWL_2147687731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWL"
        threat_id = "2147687731"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b c3 8b 08 ff 51 30 8d 45 fc b9 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 74 73 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 05 e8 10 00 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWL_2147687731_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWL"
        threat_id = "2147687731"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 61 69 6f 73 2a 00 [0-32] 2e 7a 69 70}  //weight: 2, accuracy: Low
        $x_2_2 = {6d 65 6c 68 6f 72 2a 00 [0-32] 2e 7a 69 70}  //weight: 2, accuracy: Low
        $x_2_3 = {00 31 32 33 34 35 36 37 38 39 00 [0-16] 5c [0-16] 2e 7a 69 70}  //weight: 2, accuracy: Low
        $x_2_4 = {76 61 69 6f 31 30 31 30 [0-32] 2e 7a 69 70}  //weight: 2, accuracy: Low
        $x_2_5 = {64 6f 73 38 35 36 34 37 [0-32] 2e 7a 69 70}  //weight: 2, accuracy: Low
        $x_2_6 = {5c 6c 69 62 6d 79 73 71 6c 2e 64 6c 6c 20 00 2e (65|63)}  //weight: 2, accuracy: Low
        $x_2_7 = {5c 6c 65 74 73 6f 77 [0-5] 2e 65 78 65 00}  //weight: 2, accuracy: Low
        $x_1_8 = "CMD /C Start" ascii //weight: 1
        $x_2_9 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b c3 8b 08 ff 51 30 8d 45 fc b9 ?? ?? ?? ?? 8b 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AWN_2147687748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWN"
        threat_id = "2147687748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 69 62 6d 79 73 71 6c 2e 64 6c 6c 00 [0-16] 68 74 74 70 3a 2f 2f [0-48] 2e 03 03 03 03 67 69 66 6a 70 67 6c 6f 67 00 [0-6] ff ff ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (41|42|43|44|45|46|31|32|33|34|35|36|37|38|39|30) (41|42|43|44|45|46|31|32|33|34|35|36|37|38|39|30)}  //weight: 1, accuracy: Low
        $x_1_2 = {00 63 68 61 76 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 01 8d 45 ec b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? e8 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWP_2147687754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWP"
        threat_id = "2147687754"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 70 ff d7 8b d0 8d 4d cc ff d6 50 ff d3 8b d0 8d 4d c8 ff d6 50 6a 3a ff d7 8b d0 8d 4d c4 ff d6 50 ff d3 8b d0 8d 4d c0 ff d6 50 6a 2f ff d7 8b d0 8d 4d bc ff d6 50 ff d3 8b d0 8d 4d b8 ff d6 50 6a 2f ff d7 8b d0 8d 4d b4 ff d6 50 ff d3 8b d0 8d 4d b0 ff d6 50 6a 77}  //weight: 1, accuracy: High
        $x_1_2 = {6a 2e ff d7 8b d0 8d 8d ?? ?? ff ff ff d6 50 ff d3 8b d0 8d 8d ?? ?? ff ff ff d6 50 6a (6a|67) ff d7 8b d0 8d 8d ?? ?? ff ff ff d6 50 ff d3 8b d0 8d 8d ?? ?? ff ff ff d6 50 6a (70|69) ff d7 8b d0 8d 8d ?? ?? ff ff ff d6 50 ff d3 8b d0 8d 8d ?? ?? ff ff ff d6 50 6a (67|66)}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 74 ff d7 8b d0 8d 4d 9c ff d6 50 ff d3 8b d0 8d 4d 98 ff d6 50 6a 2e ff d7 8b d0 8d 4d 94 ff d6 50 ff d3 8b d0 8d 4d 90 ff d6 50 6a 6c ff d7 8b d0 8d 4d 8c ff d6 50 ff d3 8b d0 8d 4d 88 ff d6 50 6a 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWQ_2147687770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWQ"
        threat_id = "2147687770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6f 61 6d 69 6e 67 [0-16] 2e 74 78 74 [0-16] 2e 65 78 65 [0-16] 2e (58|70)}  //weight: 1, accuracy: Low
        $x_1_2 = {00 63 68 61 76 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 32 41 46 31 30 45 45 33 32 32 33 39}  //weight: 1, accuracy: High
        $x_1_4 = {00 36 45 42 35 34 32 44 37 33 45 31 44}  //weight: 1, accuracy: High
        $x_1_5 = {33 db 8a 5c 38 ff 33 9d ?? ?? ff ff 3b 9d f0 fe ff ff 7f 0e 81 c3 ff 00 00 00 2b 9d ?? ?? ff ff eb 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWS_2147687799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWS"
        threat_id = "2147687799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 6c 65 63 74 20 67 75 61 72 64 61 ?? 20 66 72 6f 6d 20 72 6f 70 65 69 72 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 65 00 3d 00 53 00 51 00 4c 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 53 00 6d 00 61 00 72 00 74 00 65 00 72 00 61 00 73 00 70 00 2e 00 6e 00 65 00 [0-16] 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AWS_2147687799_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWS"
        threat_id = "2147687799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 47 62 50 6c [0-16] 75 67 69 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 72 6f 67 72 61 6d 66 69 6c 65 73 00 00 00 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 01 00 00 00 47 00 00 00 ff ff ff ff 01 00 00 00 62}  //weight: 1, accuracy: High
        $x_10_3 = {73 65 6c 65 63 74 20 64 61 64 6f 73 [0-32] 66 72 6f 6d 20 74 62 6c 5f 63 61 72 72 65 67 61}  //weight: 10, accuracy: Low
        $x_10_4 = {5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00}  //weight: 10, accuracy: High
        $x_10_5 = {63 00 65 00 3d 00 53 00 51 00 4c 00 35 00 30 00 30 00 (35|39) 00 2e 00 53 00 6d 00 61 00 72 00 74 00 65 00 72 00 61 00 73 00 70 00 2e 00 6e 00 65 00}  //weight: 10, accuracy: Low
        $x_10_6 = "Source=184.168.194.55" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AWW_2147687987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AWW"
        threat_id = "2147687987"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "THackMemoryStreamG" ascii //weight: 1
        $x_1_2 = {61 00 6d 00 62 00 69 00 6c 00 6f 00 67 00 69 00 73 00 74 00 69 00 63 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6a 00 73 00 2f 00 5f 00 6e 00 6f 00 74 00 65 00 73 00 2f 00 [0-48] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 65 00 78 00 65 00 00 [0-4] 4f 00 70 00 65 00 6e 00 [0-32] 41 00 63 00 65 00 73 00 73 00 6f 00 20 00 6e 00 65 00 67 00 61 00 64 00 6f 00 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXP_2147688880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXP"
        threat_id = "2147688880"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XEdlcmVuY2VcU1RSVF9HLmJhdA==" wide //weight: 1
        $x_1_2 = "XGFzcG5ldF9zdGF0cy5sbms=" wide //weight: 1
        $x_1_3 = "YzpcVXNlciBMb2dcRl9MRC5Odw==" wide //weight: 1
        $x_1_4 = "c3RhcnQgTl9HR05ELmNwbA==" wide //weight: 1
        $x_1_5 = {2e 63 70 6c 00 54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXQ_2147688881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXQ"
        threat_id = "2147688881"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6J" ascii //weight: 4
        $x_2_2 = "JKITR9LSJDKAL3K" ascii //weight: 2
        $x_2_3 = "LKS4243FDKJHJE7432IUJHK9WYZV4A4MMOA0LCMWWUAOAJ6L" ascii //weight: 2
        $x_2_4 = "8AAB75B865EA160E71DA619C8CC90C2CD50D3980E4092BAC" ascii //weight: 2
        $x_2_5 = "0435FC20DC2567DD5FBFC3BEB5DA3C271770E72D2F1FDB7E" ascii //weight: 2
        $x_2_6 = {bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AXR_2147688896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXR"
        threat_id = "2147688896"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://198.23.250.211/1908/" ascii //weight: 1
        $x_1_2 = "http://192.210.195.50/1009/" ascii //weight: 1
        $x_1_3 = ":\\Windows\\System32\\cmd.exe /k regsvr32.exe  \"" ascii //weight: 1
        $x_1_4 = {00 69 64 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {32 2e 6a 70 67 22 [0-32] 36 2e 6a 70 67 22 [0-32] 35 2e 6a 70 67 22}  //weight: 1, accuracy: Low
        $x_1_6 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXY_2147689003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXY"
        threat_id = "2147689003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D74A82DC3953F12DF3" wide //weight: 1
        $x_1_2 = "41D374EA1476DC38C6" wide //weight: 1
        $x_1_3 = "32E07BD33456FC18E6" wide //weight: 1
        $x_1_4 = "13015BF31375DF3FC1" wide //weight: 1
        $x_1_5 = "84DA63A739" wide //weight: 1
        $x_1_6 = "04449234D4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXY_2147689003_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXY"
        threat_id = "2147689003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "986DBA51072AA729" wide //weight: 1
        $x_1_2 = "D92CF9153BFE5CFD" wide //weight: 1
        $x_1_3 = "A066A8AE72EF51" wide //weight: 1
        $x_1_4 = "40CE57AC5AF0349133" wide //weight: 1
        $x_1_5 = "B89662A764B175" wide //weight: 1
        $x_1_6 = "29E731CB839E5EFA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXY_2147689003_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXY"
        threat_id = "2147689003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0519EE252BCE0C4D" wide //weight: 1
        $x_1_2 = "D351BC9256F355" wide //weight: 1
        $x_1_3 = "34F20B18FE55983697" wide //weight: 1
        $x_1_4 = "A560A67C95BB61FE5E" wide //weight: 1
        $x_1_5 = "1533CE54B06EB1" wide //weight: 1
        $x_1_6 = "8680997CD04CED6A" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXY_2147689003_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXY"
        threat_id = "2147689003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E621E523E96085C202" wide //weight: 1
        $x_1_2 = "9791959272D81CB91B" wide //weight: 1
        $x_1_3 = "19ED3BDD74B917B6" wide //weight: 1
        $x_1_4 = "808E909573D91FBC1C" wide //weight: 1
        $x_1_5 = "F05FBA48C45295" wide //weight: 1
        $x_1_6 = "59D721FB50CB6DE9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AXY_2147689003_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AXY"
        threat_id = "2147689003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F530F60C064C91CE0E" wide //weight: 1
        $x_1_2 = "A661A563A2A84C89C8" wide //weight: 1
        $x_1_3 = "27E124E1341ADF7DDC" wide //weight: 1
        $x_1_4 = "979195927CD216B315" wide //weight: 1
        $x_1_5 = "103EDB29E533F4" wide //weight: 1
        $x_1_6 = "78B642D479A44480" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AYE_2147689068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AYE"
        threat_id = "2147689068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$1t3_@spam@" ascii //weight: 1
        $x_1_2 = "/xml/jon/yfcsxfd.zip" wide //weight: 1
        $x_1_3 = "\\yfcsxfd.exe" wide //weight: 1
        $x_1_4 = {8b 45 f8 8b 08 ff 51 34 33 d2 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 83 c0 54 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 b9 bf 28 00 00 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEK_2147689282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEK"
        threat_id = "2147689282"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "florencechen.com/css/screen/sys/default.jpg" ascii //weight: 1
        $x_1_2 = "C:\\TEMP\\winlogin.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AYO_2147689350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AYO"
        threat_id = "2147689350"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.4shared.com/download/TZDZz2RBba/aTubeWD9.exe" ascii //weight: 1
        $x_1_2 = "http://www.4shared.com/download/-u-Zcvyfce/SkyLinev5.exe" ascii //weight: 1
        $x_1_3 = "https://www.4shared.com/download/pJhaizQgba/wd11.exe" ascii //weight: 1
        $x_2_4 = {6a ff 6a 00 e8 ?? ?? ?? ff 8b d8 68 88 13 00 00 53 e8 ?? ?? ?? ff 3d 02 01 00 00 75 07 6a 00 e8 ?? ?? ?? ff 5b c3 4b 42 32 38 32 33 33 32 34 30 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AYX_2147689945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AYX"
        threat_id = "2147689945"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 66 ba 58 56 ed b8 01 00 00 00 eb 13}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 b8 07 00 00 00 e8 ?? ?? ff ff 8b 55 f0 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4d ec 33 d2 b8 07 00 00 00 e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 75 29 8b 45 f8 83 c0 60 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 83 c0 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AYY_2147689973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AYY"
        threat_id = "2147689973"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 63 65 73 73 6f 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "flashplayerplugin" ascii //weight: 1
        $x_1_3 = ":.. GbPlugin..:" ascii //weight: 1
        $x_1_4 = ":.. ANTIVIRUS ..:" ascii //weight: 1
        $x_1_5 = ":..VERSAO Kl..:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AYZ_2147689976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AYZ"
        threat_id = "2147689976"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://oglobo.globo.com/brasil/" ascii //weight: 1
        $x_1_2 = "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v" ascii //weight: 1
        $x_1_3 = "\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_4 = {78 2e 63 70 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_X_2147690046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!X"
        threat_id = "2147690046"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03 2b 5d f0 8d 45 d4 8b d3 e8}  //weight: 10, accuracy: High
        $x_1_2 = {2f 30 31 2f 00 00 00 00 ff ff ff ff 04 00 04}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 30 31 00 ff ff ff ff 04 00 03}  //weight: 1, accuracy: Low
        $x_1_4 = "tmrInicialTimer" ascii //weight: 1
        $x_1_5 = "tmrbf1Timer" ascii //weight: 1
        $x_1_6 = "Tformcdx" ascii //weight: 1
        $x_1_7 = {83 c4 f8 dd 1c 24 9b 8d 1c 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AZB_2147690093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZB"
        threat_id = "2147690093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "adobep.exe" wide //weight: 1
        $x_1_2 = "imadwm.exe" wide //weight: 1
        $x_1_3 = "modelo.zip" wide //weight: 1
        $x_3_4 = {66 75 63 6b 65 72 ?? ?? ?? ?? 23}  //weight: 3, accuracy: Low
        $x_3_5 = {36 00 36 00 37 00 35 00 36 00 33 00 36 00 42 00 36 00 35 00 37 00 32 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 00 33 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AZB_2147690093_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZB"
        threat_id = "2147690093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "6675636B6572" wide //weight: 5
        $x_1_2 = "666C617368702E657865" wide //weight: 1
        $x_1_3 = "64656661756C742E7A6970" wide //weight: 1
        $x_1_4 = "appdata" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AZB_2147690093_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZB"
        threat_id = "2147690093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "imadwm.exe" wide //weight: 10
        $x_10_2 = "modelo.zlib" wide //weight: 10
        $x_1_3 = {2e 00 74 00 78 00 74 00 [0-16] 61 00 70 00 70 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 7a 00 6c 00 69 00 62 00 [0-16] 61 00 70 00 70 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 6c 00 69 00 62 00 [0-16] 61 00 70 00 70 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_AZB_2147690093_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZB"
        threat_id = "2147690093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "77696E6C6F67696E2E657865" wide //weight: 1
        $x_1_2 = "696D6164776D2E657865" wide //weight: 1
        $x_1_3 = "756E697374" wide //weight: 1
        $x_1_4 = "2E747874" wide //weight: 1
        $x_1_5 = {36 00 38 00 37 00 34 00 37 00 34 00 37 00 30 00 [0-4] 33 00 41 00 32 00 46 00 32 00 46 00}  //weight: 1, accuracy: Low
        $x_1_6 = "piklo0099kkk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AZB_2147690093_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZB"
        threat_id = "2147690093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1A1FE522E239CB212EC651A0" wide //weight: 1
        $x_1_2 = "A67B859D73B940C84DC08F6BBA4A" wide //weight: 1
        $x_1_3 = "CE54A16D818896A56A8C90" wide //weight: 1
        $x_1_4 = "DA33F70B58DC3BC1" wide //weight: 1
        $x_1_5 = {eb 05 bf 01 00 00 00 8b 45 f0 0f b7 5c 78 fe 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_AZB_2147690093_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZB"
        threat_id = "2147690093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM4A4VZYW9KHJUI2347EJHJKDF3424SKLK3LAKDJSL9RTIKJ" wide //weight: 1
        $x_1_2 = "696D6164776D2E657865" wide //weight: 1
        $x_1_3 = "6675636B65723032303223" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEL_2147690603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEL"
        threat_id = "2147690603"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 4d 75 07 80 fb 48 75 02 b0 4e 8b d8 25 ff 00 00 00 83 c0 de 83 f8 38 0f 87 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? ff 24 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75}  //weight: 1, accuracy: Low
        $x_1_3 = "tubemode822.hlp" ascii //weight: 1
        $x_1_4 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AZO_2147690626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AZO"
        threat_id = "2147690626"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rundll32.exe shell32.dll,Control_RunDLL C:\\ProgramData\\Javachk.cpl" ascii //weight: 5
        $x_1_2 = "abaixou - GetInetFile" ascii //weight: 1
        $x_1_3 = "abaixou - DoDownload" ascii //weight: 1
        $x_1_4 = "Achou a pagina -" ascii //weight: 1
        $x_1_5 = "regicpl - try" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BZA_2147691770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BZA"
        threat_id = "2147691770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP" ascii //weight: 1
        $x_1_2 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 1
        $x_1_3 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_4 = "topo=PHISHING cx2:" ascii //weight: 1
        $x_1_5 = ".com.br/" ascii //weight: 1
        $x_1_6 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAA_2147691776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAA"
        threat_id = "2147691776"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 30 39 2e 32 34 34 2e 30 2e 33 00 32 30 38 2e 36 37 2e 32 32 32 2e 32 32 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 75 00 6e 00 61 00 73 00 00 00 25 00 6c 00 69 00 64 00 20 00 25 00 6c 00 69 00 68 00 20 00 25 00 6c 00 69 00 6d 00 20 00 25 00 6c 00 69 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "/c TASKKILL /T /F /IM %s" wide //weight: 1
        $x_1_4 = "TlVMDQo6UkVQRUFUVFdPDQpERUwgIiVzIiAvRiAvUT5OVUwNCmlmIGV4aXN0ICIlcyIgZ290byBSRVBFQVRUV08+TlVMDQpERUwgJSUwPk5VTA==" wide //weight: 1
        $x_1_5 = "Software\\Hex-Rays" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAB_2147691897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAB"
        threat_id = "2147691897"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&System Info..." ascii //weight: 1
        $x_1_2 = "Warning: ..." ascii //weight: 1
        $x_1_3 = "Central de Seguran" ascii //weight: 1
        $x_2_4 = "\\Application Data\\imadwm.exe" wide //weight: 2
        $x_2_5 = "\\Banks\\Loaders" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BAD_2147691934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAD"
        threat_id = "2147691934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/highslide/graphics/outlines/intt/nfe/nfe.rar" ascii //weight: 5
        $x_1_2 = "\\Software\\Microsoft\\Security Center" ascii //weight: 1
        $x_1_3 = "Falha ao abrir o arquivo ou o arquivo est" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAF_2147692044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAF"
        threat_id = "2147692044"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 2e 74 78 74 [0-16] 6d 69 6e 69 66 65 73 74 2e 6a 73 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {34 2e 74 78 74 [0-16] 69 63 6f 6e 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {32 2e 6a 70 67 [0-16] 32 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Dados de aplicativos\\" ascii //weight: 1
        $x_1_5 = "qZPCzg6JDw1LBNrZigfUzcbZzxr7Aw9NC1XHBgWGDxnLCNnCzgvZA2rVCfX" ascii //weight: 1
        $x_1_6 = "twLJCM6ZB8z7xeLUDgvYBMv7iev3CgXVCMvYxff1AwnRieXHDw9JAfX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAH_2147692251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAH"
        threat_id = "2147692251"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 03 47 eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 03 00 00 00 8d 45 e8 89 45 f8 8d 45 dc 89 45 f4 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 4d d0 8b 45 f8 8b 10 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d d0 b8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4d cc 8b 45 f4 8b 10 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 cc 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEM_2147692498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEM"
        threat_id = "2147692498"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 4d 75 07 80 fb 48 75 02 b0 4e 8b d8 25 ff 00 00 00 83 c0 de 83 f8 38 0f 87 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? ff 24 85}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75}  //weight: 2, accuracy: Low
        $x_2_3 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" ascii //weight: 2
        $x_1_4 = "sibcdb.jpg" ascii //weight: 1
        $x_1_5 = "radiotaxbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BAL_2147692723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAL"
        threat_id = "2147692723"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\2014-2015\\_News Loads Installs e Manipulator\\" wide //weight: 1
        $x_1_2 = "tMeiaHora" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAP_2147693307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAP"
        threat_id = "2147693307"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 63 70 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 74 6d 70 00 [0-16] 68 74 74 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAP_2147693307_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAP"
        threat_id = "2147693307"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetProcessDEPPolicy" ascii //weight: 1
        $x_1_2 = "piklo0099kkk" wide //weight: 1
        $x_1_3 = "756E697374313030392E747874" wide //weight: 1
        $x_1_4 = "687474703A2F2F3130342E3133302E3233312E38352F696E76616465722F6D61737465722E706E67" wide //weight: 1
        $x_1_5 = "77696E6C6F67696E2E657865" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAS_2147693613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAS"
        threat_id = "2147693613"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start2007" ascii //weight: 1
        $x_1_2 = "pw=%x" ascii //weight: 1
        $x_1_3 = {50 6a 00 6a 00 ff d3 8b d8 eb 0a 68 ?? ?? 00 00 e8 ?? ?? ?? ?? 84 db 74 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAS_2147693613_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAS"
        threat_id = "2147693613"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 2, accuracy: High
        $x_1_2 = "41A021A226AA23A9A5287990E367F95CF45048" ascii //weight: 1
        $x_1_3 = "5E9F3E81C40B4389458998F10546963B95336D" ascii //weight: 1
        $x_1_4 = {56 4d 57 61 72 65 [0-15] 57 69 6e 65 [0-15] 56 69 72 74 75 61 6c 20 50 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BAS_2147693613_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAS"
        threat_id = "2147693613"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 83 6c 03 00 00 ?? 00 00 00 8d 83 70 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 74 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 78 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 55 f7 b9 01 00 00 00 8b 45 fc 8b 38 ff 57 0c 8b ce 0f b7 45 f4 d3 e8 f6 d0 30 45 f7 8d 55 f7 b9 01 00 00 00 8b 45 f8 8b 38 ff 57 10}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAS_2147693613_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAS"
        threat_id = "2147693613"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "7F818284898FF41D64ACED7ED104598FC41DB42FA824A03E9C3C9C3E80C50AB11BA42F97" ascii //weight: 1
        $x_1_2 = "0E4193C4174B9DFA5AF355" ascii //weight: 1
        $x_1_3 = "58F157FA5AA5E52467A6E72751B8D7385DA4E3276FAFCD3EB0C035B5D5" ascii //weight: 1
        $x_1_4 = "84D7085B8DC11271D00849" ascii //weight: 1
        $x_10_5 = {8d 55 f7 b9 01 00 00 00 8b 45 fc 8b 38 ff 57 0c 8b ce 0f b7 45 f4 d3 e8 f6 d0 30 45 f7 8d 55 f7 b9 01 00 00 00 8b 45 f8 8b 38 ff 57 10}  //weight: 10, accuracy: High
        $x_10_6 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BAU_2147693863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAU"
        threat_id = "2147693863"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "JKITR9LSJDKAL3K LKS4243FDKJHJE7432IUJHK9WYZV4A4MMOA0LCMWWUAOAJ6LXXCMN764SAJ1E5IW09FD32LK32LQUY" ascii //weight: 1
        $x_1_2 = {ff 75 1f e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3d ?? ?? ?? 00 00 74 07 e8 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb f0 5b 59 5d c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 42 52}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAV_2147693916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAV"
        threat_id = "2147693916"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 04 00 00 00 6a 63 8d 8d f0 fe ff ff 51 ff 15 ?? ?? ?? ?? 6a 6f 8d 95 e0 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c4 d4 00 00 00 c7 45 fc 07 00 00 00 6a 4c 8d 85 f0 fe ff ff 50 ff 15 ?? ?? ?? ?? 6a 4f 8d 8d e0 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 5c 8d 85 70 fd ff ff 50 ff 15 ?? ?? ?? ?? 6a 74 8d 8d 60 fd ff ff 51 ff 15 ?? ?? ?? ?? 6a 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 00 61 00 72 00 72 00 65 00 67 00 61 00 6e 00 64 00 6f 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 00 75 00 6c 00 6f 00 20 00 65 00 73 00 70 00 65 00 63 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAV_2147693916_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAV"
        threat_id = "2147693916"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 61 00 72 00 72 00 65 00 67 00 61 00 6e 00 64 00 6f 00 2e 00 2e 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 43 00 61 00 72 00 72 00 65 00 67 00 61 00 6e 00 64 00 6f 00 2e 00 2e 00 2e 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 64 00 6f 00 62 00 65 00 20 00 46 00 6c 00 61 00 73 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 41 00 64 00 6f 00 62 00 65 00 20 00 46 00 6c 00 61 00 73 00 68 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = {55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4e e3 6f 20 66 6f 69 20 70 6f 73 73 ed 76 65 6c 20 63 61 72 72 65 67 61 72 20 6f 20 6d f3 64 75 6c 6f 20 65 73 70 65 63 69 66 69 63 61 64 6f 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAV_2147693916_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAV"
        threat_id = "2147693916"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 61 00 72 00 72 00 65 00 67 00 61 00 6e 00 64 00 6f 00 2e 00 2e 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 43 00 61 00 72 00 72 00 65 00 67 00 61 00 6e 00 64 00 6f 00 2e 00 2e 00 2e 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 64 00 6f 00 62 00 65 00 20 00 46 00 6c 00 61 00 73 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 41 00 64 00 6f 00 62 00 65 00 20 00 46 00 6c 00 61 00 73 00 68 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = {55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 00 [0-32] 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 5c}  //weight: 1, accuracy: Low
        $x_1_6 = {4e 00 e3 ff 6f 00 20 00 66 00 6f 00 69 00 20 00 70 00 6f 00 73 00 73 00 ed ff 76 00 65 00 6c 00 20 00 63 00 61 00 72 00 72 00 65 00 67 00 61 00 72 00 20 00 6f 00 20 00 6d 00 f3 ff 64 00 75 00 6c 00 6f 00 20 00 65 00 73 00 70 00 65 00 63 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 48 00 4e 00 45 00 57 00 53 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 5c 00 4e 00 6f 00 76 00 6f 00 34 00 5c 00 61 00 67 00 65 00 6e 00 64 00 61 00 [0-4] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = "\\Clientes com fotos.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BAX_2147694340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BAX"
        threat_id = "2147694340"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "*\\AD:\\Tudo\\novo pequeno - exe\\Project1.vbp" wide //weight: 1
        $x_1_2 = {66 3b f0 7f 0b 66 81 c6 ff 00 0f 80 (d9|e0) 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 00 2a 00 5c 00 41 00 44 00 3a 00 5c 00 54 00 75 00 64 00 6f 00 5c 00 31 00 20 00 2d 00 20 00 65 00 78 00 65 00 [0-16] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BBB_2147694605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BBB"
        threat_id = "2147694605"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 6f 66 66 [0-48] 75 70 64 61 74 65 2e 65 [0-48] 68 74 74 70 3a [0-80] 2e 72 61 72}  //weight: 5, accuracy: Low
        $x_1_2 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 61 62 6c 65 4c 55 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BBF_2147694650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BBF"
        threat_id = "2147694650"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_2 = "/TR \"cmd /c bitsadmin /transfer SunOne /Download /PRIORITY HIGH http://" ascii //weight: 1
        $x_1_3 = "\\System /v EnableLUA /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_4 = "/notify.php?adds=" ascii //weight: 1
        $x_1_5 = {63 6d 64 20 2f 63 20 72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 [0-40] 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 54 45 4d 50 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BBK_2147695059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BBK"
        threat_id = "2147695059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATTRIB -H \"%USERPROFILE%\\ups" ascii //weight: 1
        $x_2_2 = "advanced/dll/get." ascii //weight: 2
        $x_1_3 = "o foi possivel abrir o arquivo." ascii //weight: 1
        $x_1_4 = "set u=\"%USERPROFILE%\\kix.bat" ascii //weight: 1
        $x_1_5 = "move \"%USERPROFILE%\\strings.vbs\" strings.vbs" ascii //weight: 1
        $x_1_6 = "move \"%USERPROFILE%\\ups.bat\" \"%USERPROFILE%\\ups\\UPDATE.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BBL_2147695065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BBL"
        threat_id = "2147695065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_2 = {6d 61 71 75 69 6e 61 [0-16] 70 6c 75 67 69 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 8b d0 8d 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc (8b|b8) [0-4] b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 f0 b8}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BBO_2147695698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BBO"
        threat_id = "2147695698"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://192.169.90.29" ascii //weight: 5
        $x_1_2 = "acronymsleks.exe" ascii //weight: 1
        $x_1_3 = "gunyoutl.exe" ascii //weight: 1
        $x_1_4 = "Aswanyou.exe" ascii //weight: 1
        $x_1_5 = "Uses_pc.zlib" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BBP_2147695757_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BBP"
        threat_id = "2147695757"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 2e ff 15 94 10 40 00 8b d0 8d 4d c8 ff 15 cc 10 40 00 50 6a 65 ff 15 94 10 40 00 8b d0 8d 4d c4 ff 15 cc 10 40 00 50 ff 15 24 10 40 00 8b d0 8d 4d c0 ff 15 cc 10 40 00 50 6a 78}  //weight: 1, accuracy: High
        $x_1_2 = {6a 26 ff 15 94 10 40 00 8b d0 8d 8d ?? ?? ff ff ff 15 cc 10 40 00 50 6a 61 ff 15 94 10 40 00 8b d0 8d 8d ?? ?? ff ff ff 15 cc 10 40 00 50 ff 15 24 10 40 00 8b d0 8d 8d ?? ?? ff ff ff 15 cc 10 40 00 50 6a 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCF_2147696312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCF"
        threat_id = "2147696312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = {30 32 31 43 30 33 30 45 32 39 41 30 33 43 45 42 31 37 42 43 30 33 31 42 32 38 39 38 33 43 45 37 30 34 34 34 33 32 35 35 46 42 31 43 44 33 30 43 30 46 34 39 46 39 32 30 30 44 32 34 44 46 31 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEN_2147696373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEN"
        threat_id = "2147696373"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 6f 77 6e 6c 6f 61 64 20 6c 69 6e 6b 20 3a 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 61 7a 61 61 72 20 4c 69 6e 6b 20 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 65 78 74 69 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 61 7a 61 72 20 66 75 63 6b 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCJ_2147696435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCJ"
        threat_id = "2147696435"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f 8e 47 01 00 00 33 c0 55 68 38 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCK_2147696442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCK"
        threat_id = "2147696442"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\programdata\\winsysx\\" ascii //weight: 2
        $x_2_2 = "noticias" ascii //weight: 2
        $x_2_3 = ".php?chave=xchave&url=" ascii //weight: 2
        $x_1_4 = ".cpl.zip" ascii //weight: 1
        $x_1_5 = ".exe.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BCM_2147696487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCM"
        threat_id = "2147696487"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ":\\Loader\\versao 1.5\\Space.vbp" wide //weight: 3
        $x_1_2 = "Error While Attempting to Create Directories on Destination Drive." wide //weight: 1
        $x_1_3 = "Give Password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCN_2147696498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCN"
        threat_id = "2147696498"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "in /transfer a%RANDOM% /Download /PRIORITY HIGH http://" ascii //weight: 3
        $x_3_2 = "cmd /c reg.exe ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v 1%COMPUTERNAME% /t REG_SZ /d \"rundll32.exe %SYSTEMROOT%\\1%COMPUTERNAME%.tmp" ascii //weight: 3
        $x_3_3 = "cmd /c reg.exe ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v 2%COMPUTERNAME% /t REG_SZ /d \"%SYSTEMROOT%\\2%COMPUTERNAME%.cpl\" /f" ascii //weight: 3
        $x_1_4 = "cmd /c setx.exe UPLKVARIABLE" ascii //weight: 1
        $x_1_5 = "GbPlugin\\*.dll\"') DO netsh advfirewall firewall add rule name=\"%~nxG\" dir=in action=block program=" ascii //weight: 1
        $x_1_6 = "Diebold\\Warsaw\\*.dll\"') DO netsh advfirewall firewall add rule name=\"%~nxG\" dir=in action=block program=" ascii //weight: 1
        $x_3_7 = "reg.exe ADD \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v %COMPUTERNAME% /t REG_SZ /d \"rundll32 %SYSTEMROOT%\\%COMPUTERNAME%.tmp,#1\" /F" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BCR_2147696687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCR"
        threat_id = "2147696687"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "62617365742E657865" ascii //weight: 1
        $x_1_2 = "696D6574726F2E657865" ascii //weight: 1
        $x_1_3 = "2E7A6970" ascii //weight: 1
        $x_1_4 = "TVampiro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEP_2147696688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEP"
        threat_id = "2147696688"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 0f b7 5c 70 fe 33 5d e4 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02}  //weight: 1, accuracy: High
        $x_1_2 = "889745DB22E319EF19EE2DC348CC679044D424D825D55FC95D8198AF90" wide //weight: 1
        $x_1_3 = "BDslrNgOcfgezVFLcaTmFdrvLigpKdxaqPatbUOOdphIbkIgHVxGbNPhavqDgmsoKacwHQEUndepChVBUeMhpmtKD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCS_2147696736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCS"
        threat_id = "2147696736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "geoip.s12.com.br" ascii //weight: 1
        $x_1_2 = {6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 8d 4d ?? ba ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_4 = {85 c0 0f 8f 1b 02 00 00 8d 4d ?? ba ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 50 8d 55 ?? 8b 45 fc e8 ?? ?? ?? ?? 8b 55 ?? 58 e8 ?? ?? ?? ?? 85 c0 0f 8f e9 01 00 00 8d 4d ?? ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCV_2147696845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCV"
        threat_id = "2147696845"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 80 9c 00 00 00 30 75 00 00 8b 45 ec e8 ?? ?? ?? ?? 83 c0 54 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec e8 ?? ?? ?? ?? 83 c0 70 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b2 01}  //weight: 1, accuracy: Low
        $x_1_2 = {64 61 64 6f 73 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 72 61 76 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCY_2147697064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCY"
        threat_id = "2147697064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3}  //weight: 5, accuracy: High
        $x_1_2 = "\\z.zlib" ascii //weight: 1
        $x_1_3 = "\\abcdef.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BCY_2147697064_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BCY"
        threat_id = "2147697064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 55 f8 b8 1c 00 00 00 e8 ?? (fd|ff) ff ff 8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 7a 2e 7a 6c 69 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 7a 69 70 2e 7a 00}  //weight: 1, accuracy: High
        $x_1_4 = {eb f8 68 70 17 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {eb f8 68 b8 0b 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {eb f8 68 d0 07 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0}  //weight: 1, accuracy: Low
        $x_1_7 = {eb f8 68 58 1b 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0}  //weight: 1, accuracy: Low
        $x_1_8 = {eb f8 68 40 1f 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 84 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BDA_2147697083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDA"
        threat_id = "2147697083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b}  //weight: 1, accuracy: High
        $x_1_2 = {54 53 69 74 69 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDB_2147697132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDB"
        threat_id = "2147697132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C \"reg.exe ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers\" /v" ascii //weight: 1
        $x_1_2 = "RUNASADMIN WIN7RTM\" /f" wide //weight: 1
        $x_1_3 = "8592BB41A4BAA8B7C86DE9154CFA26D0799845F5144B8EA74786C057DE0232E31BDD6180D10335C86B93A8CF" wide //weight: 1
        $x_1_4 = "849DB6BF253D2D3243D776F9091F223CB2BF5CEC1D50A9B85897D37AF9192D382F294E93EC78" wide //weight: 1
        $x_1_5 = "8EBC6B9C3C373529A745F522A140FE3B5084BF7883D974B74C95C07AEC0633E745" wide //weight: 1
        $x_1_6 = "B1BEA2BD3FF033D77E9756DC0A3AD77D" wide //weight: 1
        $x_1_7 = "DA54D472F823C26AED2DF3165D924AF7649681E71D" wide //weight: 1
        $x_1_8 = "ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v  ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDH_2147697337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDH"
        threat_id = "2147697337"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "V3NjcmlwdC5leGUgIg==" wide //weight: 1
        $x_1_2 = "YWxsdXNlcnNwcm9maWxl" wide //weight: 1
        $x_1_3 = "d2lubWFuYWdlci52YnM" wide //weight: 1
        $x_1_4 = "aHR0cDovL" wide //weight: 1
        $x_1_5 = "U09GVFdBUkVcTWljcm9zb2Z0XE5FVCBGcmFtZXdvcmsgU2V0dXBcTkRQXHY" wide //weight: 1
        $x_1_6 = "Y29tcHV0ZXJuYW1l" wide //weight: 1
        $x_1_7 = "amF2YXUubg==" wide //weight: 1
        $x_1_8 = "TIdHTTPWhatsNext" ascii //weight: 1
        $x_1_9 = "hCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDO_2147697442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDO"
        threat_id = "2147697442"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\B3S.dat" ascii //weight: 1
        $x_1_2 = "\\DPR009.exe" ascii //weight: 1
        $x_1_3 = "/acessar.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDT_2147697740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDT"
        threat_id = "2147697740"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_2 = "Erro ao abrir o arquivo" ascii //weight: 1
        $x_1_3 = {45 6e 61 62 6c 65 4c 55 41 00 00 00 ff ff ff ff 23 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 f0 01 2e 72 61 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDT_2147697740_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDT"
        threat_id = "2147697740"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 5c 64 61 74 61 2e 7a 69 70 00 04 00 1c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 5c 6e 74 63 68 6b 33 32 2e 65 78 65 00 04 00 1f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6f 70 65 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 45 72 72 6f 72 20 39 30 30 34 35 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BZE_2147705550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BZE"
        threat_id = "2147705550"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6f 72 74 75 67 75 ea 73 20 28 42 72 61 73 69 6c 29 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 68 72 79 74 68 79 34 64 66 68 00}  //weight: 1, accuracy: High
        $x_1_3 = "TDownloader1" ascii //weight: 1
        $x_1_4 = "Salvar" ascii //weight: 1
        $x_1_5 = "A289A646E1" ascii //weight: 1
        $x_1_6 = "56DD1DDC08" ascii //weight: 1
        $x_1_7 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM4A4VZYW9KHJUI2347EJHJKDF3424" ascii //weight: 1
        $x_1_8 = {0f 8e 4d 01 00 00 89 45 dc c7 45 e4 01 00 00 00 8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDZ_2147705822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDZ"
        threat_id = "2147705822"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 17 32 55 10 88 17 81 fe ?? ?? ?? ?? 7d ?? be ?? ?? ?? ?? 40 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 5c 70 fe 33 5d ?? 3b fb 7c ?? 81 c3 ff 00 00 00 2b df eb 02}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 09 32 4d 10 8b 5d 08 03 da 88 0b 3b 45 ?? 7e 02 8b f0 3b f0 7d 03 89 75 ?? 42 ff 4d ?? 75 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BED_2147706044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BED"
        threat_id = "2147706044"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 7a 69 70 66 69 6c 65 [0-5] 26 [0-5] 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 50 72 6f 70 65 72 74 69 65 73 5c 64 61 74 61 2e 7a 69 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 50 72 6f 70 65 72 74 69 65 73 5c 75 70 64 63 6c 69 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6f 70 65 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 45 72 72 6f 72 20 39 30 30 34 35 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_Z_2147706187_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!Z"
        threat_id = "2147706187"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 05 be 01 00 00 00 a1 ?? ?? ?? ?? 33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3 e8}  //weight: 5, accuracy: Low
        $x_1_2 = {c6 00 01 b1 01 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 8b 00 c6 40 0f 01 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? eb 0a 68 e8 03 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 d8 ff 75 ec 8d 55 d4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 d4 8d 45 dc ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 dc e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 75 d8 8d 55 d4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 d4 8d 45 e0 ba 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 e0 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BEE_2147706188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEE"
        threat_id = "2147706188"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 44 50 52 30 30 39 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 54 4e 54 4c 4f 47 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 3a 5c 61 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 42 20 4e 41 4f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 42 20 53 49 4d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 67 62 70 73 76 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 70 6c 75 67 69 6e 73 2f 73 79 73 74 65 6d 2f 77 65 62 2f [0-16] 2f 6e 6f 74 69 66 79 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_6 = {69 70 2d 61 70 69 2e 63 6f 6d 2f 6a 73 6f 6e 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BEE_2147706188_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEE"
        threat_id = "2147706188"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6e 65 67 79 6d 75 73 6b 65 74 61 73 2e 68 75 2f 72 6f 63 6b 79 2f 6d 6f 64 75 6c 65 73 2f 77 65 62 32 30 31 35 2f 56 4f 4c 56 45 52 49 4e 45 2f 6e 6f 74 69 66 79 2e 70 68 70 00}  //weight: 3, accuracy: High
        $x_1_2 = {00 53 66 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 73 6e 78 68 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_4 = {00 43 3a 5c 61 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 73 73 6f 63 69 61 74 69 6f 6e 73 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 5c 00 44 00 50 00 52 00 30 00 30 00 [0-4] 2e 00 65 00 78 00 65 00 00}  //weight: 2, accuracy: Low
        $x_2_7 = {00 5c 44 50 52 30 30 [0-4] 2e 65 78 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZEV_2147706385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEV"
        threat_id = "2147706385"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 10, accuracy: High
        $x_1_2 = "3654A2F3528BC800110F4858B8D8C9CBCB3350B1EA2A6EAFFE15" ascii //weight: 1
        $x_1_3 = {31 35 31 36 30 31 30 31 31 35 30 31 30 31 31 36 30 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {30 38 37 38 38 41 38 36 38 45 38 43 38 44 38 42 38 41 38 39 38 46 00}  //weight: 1, accuracy: High
        $x_1_5 = "#VERSION-AG-2.0.0.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BEK_2147706419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEK"
        threat_id = "2147706419"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 2, accuracy: High
        $x_1_2 = "28A127AA2A55B5D53958B9D62168A7E92D57B4DC3F5F9D3C9136933294D372D978F45FBF" ascii //weight: 1
        $x_1_3 = "CA02478ACB3757B7D83859B6DE2665A7E8137090F214728ECC004481C10463E36BEB08B0EE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BEO_2147706596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEO"
        threat_id = "2147706596"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 01 00 00 00 8b 45 ec 33 db 8a 5c 30 ff 33 5d e4 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02}  //weight: 1, accuracy: High
        $x_1_2 = "DC6D83A0A91046E2" ascii //weight: 1
        $x_1_3 = "B57888AB5689C6B2A8E47AA249" ascii //weight: 1
        $x_1_4 = {31 7c 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 32 7c 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 33 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BEP_2147706625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEP"
        threat_id = "2147706625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 44 50 fe 33 45 e0 89 45 dc 8b 45 dc 3b 45 ec 7f 10}  //weight: 1, accuracy: High
        $x_1_2 = {3a 31 0d 0a 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 0d 0a 45 72 61 73 65 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 0d 0a 49 66 20 65 78 69 73 74 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 47 6f 74 6f 20 31 0d 0a 45 72 61 73 65 20 22 43 3a 5c 6d 79 61 70 70 2e 62 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BET_2147706865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BET"
        threat_id = "2147706865"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://51.254.128.35/fixsw/2109/va/win32.oc" wide //weight: 1
        $x_1_2 = "http://51.254.128.35/fixsw/2109/va/2.txt" wide //weight: 1
        $x_1_3 = "C:\\WINDOWS\\system32\\shutdown.exe -r -t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BEU_2147706868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEU"
        threat_id = "2147706868"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gbftinsj.sys &echo carai>> \"%PRO" ascii //weight: 1
        $x_1_2 = "%upvariable%" ascii //weight: 1
        $x_1_3 = "setx.exe UPLKVARIABLE \"http" ascii //weight: 1
        $x_1_4 = "&&bitsadmin /transfer a%RANDOM% /Download /PRIORITY HIGH http" ascii //weight: 1
        $x_1_5 = "GbPlugin\\gbftin32.sys\" &shutdown /r /t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BEW_2147706879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEW"
        threat_id = "2147706879"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 74 74 70 73 3a 2f 2f 73 74 6f 72 61 67 65 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d 2f 63 6f 6e 76 69 74 65 2d 32 30 31 35 2f}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 32 38 30 30 39 39 48 4a 36 36 36 33 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 52 75 6e 6e 69 6e 67 61 6d 65 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5c 74 6f 79 73 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {37 34 30 30 30 34 35 34 37 35 2e 6a 6b 39 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 61 4b 33 31 4d 41 53 54 45 52 30 [0-2] 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BEX_2147706899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BEX"
        threat_id = "2147706899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7d 03 46 eb 05 be 01 00 00 00 8b 45 f4 0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03}  //weight: 10, accuracy: High
        $x_1_2 = {64 89 20 c7 05 ?? ?? ?? 00 ?? 00 00 00 b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 fc 50 b9 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 55 fc b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 f8 50 b9 ?? ?? ?? 00 ba ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {64 89 20 c7 05 ?? ?? ?? 00 ?? 00 00 00 8d 45 fc ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 (f0|f4) 50 8d 45 (ec|f0) 8b 55 fc e8 ?? ?? ?? ff 8b 55 (ec|f0) b9 ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? fb ff ff 8b 55 (f0|f4) 8d 45 f8 e8 ?? ?? ?? ff 8d 45 (e4|e8) 50 b9 ?? ?? ?? 00 ba ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_4 = {64 89 20 c7 05 ?? ?? ?? 00 ?? 00 00 00 8d 55 e8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff ff 75 e8 68 ?? ?? ?? 00 8d 45 e4 50 e8 ?? ?? ?? ff 83 c4 f8 dd 1c 24 9b 8d 55 e0 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 e0 b9 ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff ff 75 e4 8d 45 ec ba 03 00 00 00 e8 ?? ?? ?? ff 8b 55 ec 8d 45 f0 e8 ?? ?? ?? ff 8d 45 fc ba ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_5 = {64 89 20 c7 05 ?? ?? ?? 00 ?? 00 00 00 b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 fc 50 8d 45 f8 8b 15 ?? ?? ?? 00 e8 ?? ?? ?? ?? 8b 55 f8 b9 ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 8d 45 f0 50 b9 ?? ?? ?? 00 ba ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BFA_2147706993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFA"
        threat_id = "2147706993"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" ascii //weight: 1
        $x_1_3 = "cmd.exe /c bitsadmin /transfer %RANDOM% /Download /PRIORITY HIGH" ascii //weight: 1
        $x_1_4 = "ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" ascii //weight: 1
        $x_1_5 = "cmd /c setx.exe UPLKVARIABLE" ascii //weight: 1
        $x_1_6 = "aHR5cDovL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFC_2147707061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFC"
        threat_id = "2147707061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 44 49 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {5c 61 4b 33 31 4d 41 53 54 45 52 30 ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "\\UPTools.exe" ascii //weight: 1
        $x_1_4 = "3D56B5B2A4D2107C95F61672838EE66398D954A4D959A8" ascii //weight: 1
        $x_1_5 = "/install /silent" ascii //weight: 1
        $x_1_6 = "\\jimgo.dat" ascii //weight: 1
        $x_1_7 = "Sf2.dll" ascii //weight: 1
        $x_1_8 = "snxhk.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFD_2147707067_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFD"
        threat_id = "2147707067"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7DEF52F869FB43933595379D3FAF16B52BBF1D4FF356" ascii //weight: 1
        $x_1_2 = "4590D273E86CD205469AC73A4DAE3A" ascii //weight: 1
        $x_1_3 = "0050F15386D67AEA" ascii //weight: 1
        $x_1_4 = "6895E0057CF00C6996E5" ascii //weight: 1
        $x_1_5 = "719CE90C659BD61261AE" ascii //weight: 1
        $x_1_6 = "EB196499D9007F8CFB" ascii //weight: 1
        $x_1_7 = "E02C59ACCA1350BFCC" ascii //weight: 1
        $x_1_8 = "2E5BA6CA2C49B6C5" ascii //weight: 1
        $x_1_9 = "7E8BF67DFE7A89F6" ascii //weight: 1
        $x_1_10 = "61BE0457FB" ascii //weight: 1
        $x_1_11 = "CE0F4E82C1" ascii //weight: 1
        $x_1_12 = "77FF62F4568ECF7592D40C409D3B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFF_2147707164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFF"
        threat_id = "2147707164"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 38 ff 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00 2b 5d ?? eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 81 78 fc f4 01 00 00 0f 8d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFH_2147707274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFH"
        threat_id = "2147707274"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 70 64 61 74 61 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 00 2e 00 2a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 f8 83 7d f8 00 75 0a 33 c0 89 45 fc e9 58 01 00 00 33 c0 55 68}  //weight: 1, accuracy: High
        $x_1_3 = {7d 03 47 eb 05 bf 01 00 00 00 8b 45 e8 33 db 8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff 84 c0 0f 84 ?? ?? 00 00 8d 55 fc b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 fc ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 fc 8b 83 fc 02 00 00 e8 ?? ?? ?? ff 8d 55 f8 8b 83 fc 02 00 00 e8 ?? ?? ?? ff 8d 45 f8 50 8d 55 f0 8b 83 ?? 03 00 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFJ_2147707473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFJ"
        threat_id = "2147707473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".google.com.br/" ascii //weight: 1
        $x_1_2 = "ASkyline.exe" ascii //weight: 1
        $x_1_3 = {5d 51 51 55 8b 96 96}  //weight: 1, accuracy: High
        $x_1_4 = {ff 83 c0 04 ba ?? ?? 69 00 e8 ?? ?? ?? ff 33 c0 55 68 ?? ?? 69 00 64 ff 30 64 89 20 8d 55 e4 b8 ?? ?? 69 00 e8 5a fa ff ff 8b 55 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFL_2147707492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFL"
        threat_id = "2147707492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n\\Policies\\Associations" wide //weight: 1
        $x_1_2 = "LowRiskFileTypes" wide //weight: 1
        $x_1_3 = "4shared.com/download/" wide //weight: 1
        $x_10_4 = "TFormulario_1" ascii //weight: 10
        $x_10_5 = "TimerBXTimer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFL_2147707492_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFL"
        threat_id = "2147707492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\aK31MASTER0" ascii //weight: 1
        $x_1_2 = {70 6b 62 61 63 6b 23 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 [0-16] 5c [0-7] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] (6a|4a) 61 76 61 [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 50 4c 55 47 42 4f 58 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 4a 61 76 61 62 6f 78 2e}  //weight: 1, accuracy: Low
        $x_1_7 = {2d 61 70 70 04 00 2f 64 69 73 6e 65 69 06 00 2e 7a 79 79}  //weight: 1, accuracy: Low
        $x_1_8 = "TwiterPlayes." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFL_2147707492_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFL"
        threat_id = "2147707492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 3a 00 5c 00 6f 00 6b 00 [0-2] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "pkback#" wide //weight: 1
        $x_1_3 = "snxhk64.dll" wide //weight: 1
        $x_1_4 = "/notify.php" wide //weight: 1
        $x_1_5 = "ULTRA77.BAK" wide //weight: 1
        $x_1_6 = "RESERVA.BAK" wide //weight: 1
        $x_1_7 = {50 00 6f 00 72 00 74 00 75 00 67 00 75 00 ea 00 73 00 20 00 28 00 42 00 72 00 61 00 73 00 69 00 6c 00 29 [0-18] 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00}  //weight: 1, accuracy: Low
        $x_1_8 = {b8 e8 03 00 00 e8 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 54 8d 55 f0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 f4 ba 03 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFL_2147707492_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFL"
        threat_id = "2147707492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ANUNBI0.BAK" wide //weight: 10
        $x_10_2 = "/install /silent" wide //weight: 10
        $x_10_3 = "\\TEMPACT0" wide //weight: 10
        $x_1_4 = {63 00 6f 00 6e 00 73 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00}  //weight: 1, accuracy: Low
        $x_1_5 = {74 00 65 00 6d 00 70 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 [0-16] 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00}  //weight: 1, accuracy: Low
        $x_1_6 = {74 00 65 00 6d 00 70 00 5f 00 64 00 69 00 6e 00 6f 00 [0-16] 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00}  //weight: 1, accuracy: Low
        $x_1_7 = {74 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 69 00 6f 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 [0-16] 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BFL_2147707492_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFL"
        threat_id = "2147707492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pkback#" wide //weight: 1
        $x_1_2 = "\\TEMPACT0" wide //weight: 1
        $x_1_3 = {5c 00 61 00 4b 00 33 00 31 00 4d 00 41 00 53 00 54 00 45 00 52 00 30 00 ?? ?? 2e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 5c 00 [0-22] 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = "TimerBXTimer" ascii //weight: 1
        $x_1_7 = "TimeracapaulcoTimer" ascii //weight: 1
        $x_1_8 = "TimerLUNATICOSTimer" ascii //weight: 1
        $x_1_9 = "TFormulario_1" ascii //weight: 1
        $x_1_10 = "n\\Policies\\Associations" wide //weight: 1
        $x_1_11 = "LowRiskFileTypes" wide //weight: 1
        $x_1_12 = {64 89 20 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff ff 75 f4 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 f8 ba 05 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFM_2147707497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFM"
        threat_id = "2147707497"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 65 73 74 4c 6f 61 64 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\TESTE.DAT" ascii //weight: 1
        $x_1_3 = {70 6b 62 61 63 6b 23 20 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\VBoxMiniRdrDN" ascii //weight: 1
        $x_1_5 = "Q7HqS3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFN_2147707549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFN"
        threat_id = "2147707549"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\GbPlugin\\" wide //weight: 1
        $x_1_2 = "c:\\windows\\mdi.net" wide //weight: 1
        $x_1_3 = "http://213.41.88.32:8080/" wide //weight: 1
        $x_1_4 = "http://23.108.10.137/nowplay" wide //weight: 1
        $x_1_5 = "c:\\Windows\\addins\\" wide //weight: 1
        $x_1_6 = "/newplay.dll" wide //weight: 1
        $x_1_7 = "/saveinf.php?idcli=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFO_2147707571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFO"
        threat_id = "2147707571"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 7a 6c 69 62 [0-16] 5c [0-16] 2e 65 78 65 [0-4] 6f 70 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 01 00 e8 3a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 68 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFP_2147707580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFP"
        threat_id = "2147707580"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 64 6f 62 65 50 6c 61 79 [0-16] 55 53 45 52 50 52 4f 46 49 4c 45}  //weight: 1, accuracy: Low
        $x_1_2 = "/notify.php" ascii //weight: 1
        $x_1_3 = {4d 69 63 72 6f 73 6f 66 74 53 51 4c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 7a 69 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 75 fc 8d 45 ?? ba 06 00 00 00 e8 24 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff ff 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_5 = {ba 0f 00 00 00 8b c3 e8 ?? ?? ff ff 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 55 ?? 8b 83 ?? 03 00 00 e8 ?? ?? ?? ff 8d 4d ?? ba 14 00 00 00 8b c3 e8 ?? ?? ff ff 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFQ_2147707649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFQ"
        threat_id = "2147707649"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "casioahfsavx1852731" ascii //weight: 10
        $x_10_2 = "afvcxoueriuvcx9834283" ascii //weight: 10
        $x_10_3 = "mziusd0983253475zzqe" ascii //weight: 10
        $x_1_4 = {84 c0 75 0a a1 ?? ?? ?? ?? e8 ?? ?? ?? ff b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ff b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ff b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_5 = {84 c0 75 07 8b 03 e8 ?? ?? ?? ff b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ff b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 13 e8 ?? ?? ?? ff b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 13 e8 ?? ?? ?? ff b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BFR_2147707731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFR"
        threat_id = "2147707731"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "177.54.147.91/hank/visual.php" ascii //weight: 3
        $x_1_2 = "Ativar Contador" ascii //weight: 1
        $x_1_3 = "ID_MAQUINA=" ascii //weight: 1
        $x_1_4 = "VERSAO=" ascii //weight: 1
        $x_1_5 = "NAVEGADOR=" ascii //weight: 1
        $x_1_6 = {26 00 41 00 56 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 76 00 69 00 73 00 75 00 61 00 6c 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {61 70 70 64 61 74 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 4d 65 64 69 61 58}  //weight: 1, accuracy: Low
        $x_1_8 = {61 70 70 64 61 74 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 50 6c 75 67 69 6e 50 6c 61 79 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BFS_2147707764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFS"
        threat_id = "2147707764"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "200.98.130.80/rco" ascii //weight: 10
        $x_1_2 = "\\Application Data\\id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFT_2147707838_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFT"
        threat_id = "2147707838"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "psyrico.zip" wide //weight: 1
        $x_1_2 = "snd64.zip" wide //weight: 1
        $x_1_3 = "snd32.exe" wide //weight: 1
        $x_1_4 = {2e 00 65 00 78 00 65 00 [0-8] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = "meudeus333" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFW_2147708104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFW"
        threat_id = "2147708104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb f8 68 70 17 00 00 e8 ?? ?? ?? ?? 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8 ?? ?? ?? ?? 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f0 8b 83 fc 02 00 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8d 55 ec 8b 83 f8 02 00 00 e8 ?? ?? ?? ?? ff 75 ec 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba 03 00 00 00 e8 ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFX_2147708200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFX"
        threat_id = "2147708200"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 61 62 4f 72 64 65 72 ?? ?? ?? 54 65 78 74 ?? ?? 68 74 74 70 [0-1] 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 50 e8 ?? ?? ?? ?? 6a 00 b9 bf 28 00 00 ba ?? ?? ?? ?? 8b 83 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 74 05 e8 ?? ?? ?? ?? e8 ?? ?? ff ff 33 c0 e8 ?? ?? ff ff 84 c0 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFY_2147708241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFY"
        threat_id = "2147708241"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tmrVerfTimer" ascii //weight: 1
        $x_1_2 = "tmrBaixaTimer" ascii //weight: 1
        $x_1_3 = "x.gif" ascii //weight: 1
        $x_1_4 = "uModAvs" ascii //weight: 1
        $x_1_5 = {b9 03 00 00 00 33 d2 e8 ?? ?? ?? ff ff 75 e8 68 ?? ?? 47 00 8b 45 fc 05 0c 03 00 00 ba 03 00 00 00 e8 ?? ?? f8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BFZ_2147708251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BFZ"
        threat_id = "2147708251"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 b9 bf 28 00 00 ba ?? ?? ?? ?? 8b 83 ?? ?? 00 00 e8 ?? ?? ?? ?? 8b 83 ?? ?? 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 75 6e 61 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGA_2147708407_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGA"
        threat_id = "2147708407"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b8 1a 00 00 00 e8 b3 fb ff ff 6a 00 8d 45 c8 50 8d 85 10 ff ff ff 33 d2 e8 ?? ?? f7 ff 8d 8d 10 ff ff ff 33 d2 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 85 0c ff ff ff e8 ?? ?? ff ff 8b 95 0c ff ff ff 8d 45 c4 b9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 25 01 00 00 8d 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 f8 33 d2 e8 ?? ?? ?? ff 8b 45 f4 85 c0 74 16 8b d0 83 ea 0a 66 83 3a 02 74 0b}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 4d d8 33 d2 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 6a 00 8d 45 f0 50 8d 45 c8 33 d2 e8 ?? ?? ?? ff 8d 4d c8 33 d2 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 4d ec 33 d2 b8 1a 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGB_2147708429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGB"
        threat_id = "2147708429"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A___r_q__uI__Co__pI_a" ascii //weight: 1
        $x_1_2 = "P__uxa__arqui__vos" ascii //weight: 1
        $x_1_3 = "...Intentando conectar" wide //weight: 1
        $x_1_4 = "compruebe la conexi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGC_2147708722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGC"
        threat_id = "2147708722"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "content-na.drive.amazonaws.com/cdproxy/templink/" wide //weight: 1
        $x_1_2 = {3a 00 2f 00 2f 00 63 00 6c 00 2e 00 6c 00 79 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "WshShell.Run chr(34) & \"" wide //weight: 1
        $x_1_4 = ".exe\" & Chr(34),0" wide //weight: 1
        $x_1_5 = {8b c3 8b 08 ff 51 38 68 ?? ?? ?? 00 8d 85 ?? ff ff ff e8 ?? ?? ff ff ff b5 ?? ff ff ff 8d 85 ?? ff ff ff e8 ?? ?? ff ff ff b5 ?? ff ff ff 68 ?? ?? ?? 00 [0-5] 8d 85 ?? ff ff ff ba (04|05) 00 00 00 e8 ?? ?? ?? ff 8b 95 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGD_2147708732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGD"
        threat_id = "2147708732"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc 59 e8 ?? ?? ?? ff 8d 55 f8 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 55 f4 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 55 f0 b8 ?? ?? ?? 00 e8 ?? ?? ff ff 0f b6 05 ?? ?? ?? 00 50 8d 45 c8 50 8d 55 c4 b8 ?? ?? ?? 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 75 ca 8d 95 6c ff ff ff b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 8d 6c ff ff ff 8d 45 e8 8b 55 e0 e8 ?? ?? ?? ff b2 01 a1 a0 85 48 00 e8 ?? ?? ?? ff 8b d8 8d 95 68 ff ff ff b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 95 68 ff ff ff 8b c3 8b 08 ff 51 3c 8d 95 60 ff ff ff b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGF_2147708793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGF"
        threat_id = "2147708793"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 73 23 b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? (fb|fc) ff b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? (fb|fc) ff e8 ?? ?? ff ff 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 44 70 fe e8 ?? ?? ff ff 5a 32 d0 88 55 ?? 8d 45 ?? e8 ?? ?? ?? ff 0f b6 55 ?? 66 89 54 70 fe 46 4f 0f 85 4a ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {25 01 00 00 80 79 05 48 83 c8 fe 40 99 52 50 8d 45 d0 e8 c0 fe ff ff 8b 45 d0 8d 55 ec e8 29 fd ff ff d1 fb 79 03 83 d3 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGG_2147708930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGG"
        threat_id = "2147708930"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/74.63.213.20/" wide //weight: 1
        $x_1_2 = {2e 00 7a 00 69 00 70 00 00 00 [0-2] 67 31 67 32 00 00 00 00 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0a 8d 52 01 88 08 8d 40 01 84 c9 75 f2 8b c6 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGH_2147709466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGH"
        threat_id = "2147709466"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\system32.exe" ascii //weight: 1
        $x_1_2 = {05 a8 00 00 00 ba ?? ?? ?? ?? e8 39 f1 f6 ff 8b ce ba ?? ?? ?? ?? 8b 83 f8 02 00 00 e8 97 c0 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGI_2147709494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGI"
        threat_id = "2147709494"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\GbPlugin" ascii //weight: 1
        $x_1_2 = "C:\\Arquivos de programas\\Scpad" ascii //weight: 1
        $x_1_3 = "C:\\Program Files (x86)\\Trusteer" ascii //weight: 1
        $x_1_4 = {62 72 61 73 69 6c [0-16] 70 6f 72 74 75 67 75 ea 73}  //weight: 1, accuracy: Low
        $x_1_5 = {7e 02 33 db 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7f 14 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AFG_2147709996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AFG"
        threat_id = "2147709996"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\arq.zip" wide //weight: 1
        $x_1_2 = "/Contact64.zip" wide //weight: 1
        $x_1_3 = "?directDownload=true" wide //weight: 1
        $x_1_4 = {74 0f 8d 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0d 8d 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 33 c9 b2 01}  //weight: 1, accuracy: Low
        $x_1_5 = {74 0f 8d 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0d 8d 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 33 c9 b2 01}  //weight: 1, accuracy: Low
        $x_1_6 = {74 0f 8d 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0d 8d 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 33 c9 b2 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARJ_2147710317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARJ"
        threat_id = "2147710317"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 61 62 4f 72 64 65 72 ?? ?? ?? 54 65 78 74 ?? ?? 68 74 74 70 [0-1] 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 84 c0 74 05 e8 ?? ?? ?? ff 68 ?? ?? 00 00 e8 ?? ?? ?? ff 8d 55 e8 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 05 bf 01 00 00 00 8b 45 e8 33 db 8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03}  //weight: 1, accuracy: High
        $x_1_4 = {83 c0 50 e8 ?? ?? ?? ff 6a 00 8d 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ARZ_2147710319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ARZ"
        threat_id = "2147710319"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CHAVE=[']" wide //weight: 1
        $x_1_2 = "/notify.php" wide //weight: 1
        $x_1_3 = "\\AVAST Software\\Avast\\setup" ascii //weight: 1
        $x_1_4 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-16] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGL_2147710663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGL"
        threat_id = "2147710663"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BAKA.BAK" wide //weight: 1
        $x_1_2 = "BUJU.BAK" wide //weight: 1
        $x_1_3 = "pkback#" wide //weight: 1
        $x_1_4 = ".googleapis.com/" wide //weight: 1
        $x_1_5 = "(Brasil)" wide //weight: 1
        $x_1_6 = {8b 45 94 50 8d 45 8c ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 8c 5a e8 ?? ?? ?? ?? 85 c0 7e 05 83 cb ff eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGM_2147710748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGM"
        threat_id = "2147710748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 7a 00 69 00 70 00 [0-16] 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_10_2 = {50 ff d6 6a 00 6a 00 8d 84 24 50 04 00 00 50 68 ?? ?? 41 00 6a 00 ff 15 ?? ?? 41 00 85 c0 0f 85 ?? ?? 00 00 83 ec 08 8d 8c 24 50 04 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGP_2147710758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGP"
        threat_id = "2147710758"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 00 70 00 65 00 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-6] 2e 00 76 00 62 00 73}  //weight: 1, accuracy: Low
        $x_10_2 = {68 70 11 01 00 e8 b7 ee f5 ff 6a 00 6a 00 6a 00 8d 45 8c e8 0d 8e ff ff ff 75 8c 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 8d 45 90 ba 09 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGN_2147710961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGN"
        threat_id = "2147710961"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OLD.BAK" wide //weight: 1
        $x_1_2 = "pkback#" wide //weight: 1
        $x_1_3 = "drdree" wide //weight: 1
        $x_1_4 = "\\*.exe" wide //weight: 1
        $x_1_5 = {64 89 20 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8 8d 4d f4 ba ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGQ_2147711041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGQ"
        threat_id = "2147711041"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\must.pig" wide //weight: 1
        $x_1_2 = {64 00 65 00 6e 00 74 00 6f 00 6f 00 6c 00 73 00 [0-16] 2e 00 37 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {59 00 44 00 44 00 40 00 0b 00 1f 00 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGQ_2147711041_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGQ"
        threat_id = "2147711041"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "abgaiul.tmp" wide //weight: 1
        $x_1_2 = "pkback#" wide //weight: 1
        $x_1_3 = "Bloku.BAK" wide //weight: 1
        $x_1_4 = "\\*.exe" wide //weight: 1
        $x_1_5 = "/notify.php" wide //weight: 1
        $x_1_6 = "/welgome.php" wide //weight: 1
        $x_1_7 = "\\CHUMG.ALERT" wide //weight: 1
        $x_1_8 = "\\mst8.ALERT" wide //weight: 1
        $x_1_9 = "\\mst11.ALERT" wide //weight: 1
        $x_2_10 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8 8b 45 f8 e8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4d f4 ba ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BGR_2147711709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGR"
        threat_id = "2147711709"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pkback#" wide //weight: 1
        $x_1_2 = "THackMemoryStreamG" ascii //weight: 1
        $x_1_3 = "ALASCADNS" wide //weight: 1
        $x_1_4 = "worksnet" wide //weight: 1
        $x_1_5 = "LOGSDARF" wide //weight: 1
        $x_10_6 = "SPARTAN.pig" wide //weight: 10
        $x_10_7 = "mago.pig" wide //weight: 10
        $x_10_8 = {2e 00 70 00 69 00 67 00 [0-16] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 65 00 74 00 2e 00 61 00 64 00 6f 00 62 00 65 00}  //weight: 10, accuracy: Low
        $x_10_9 = "lovemaz" wide //weight: 10
        $x_10_10 = {ba 05 00 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? 00 8b 00 e8 ?? ?? ?? ff 33 d2 55 68 ?? ?? ?? 00 64 ff 32 64 89 22 8d 4d ?? ba ?? ?? ?? 00 b8 ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BDI_2147712012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDI!bit"
        threat_id = "2147712012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "aHR0cDovLw==" wide //weight: 5
        $x_10_2 = "cXMuYmFpeGFyc25hcGNoYXRwYy5jb20=" wide //weight: 10
        $x_10_3 = "L3BhcmdlLmdpZg==" wide //weight: 10
        $x_5_4 = "L250ZjIvYy5waHA/dGlwPVswNy0yXS0=" wide //weight: 5
        $x_1_5 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\notepad.lnk" wide //weight: 1
        $x_1_6 = {64 00 6d 00 4a 00 7a 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {4c 00 6e 00 5a 00 69 00 63 00 77 00 3d 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "YWxsdXNlcnNwcm9maWxl" wide //weight: 1
        $x_1_9 = "Y29tcHV0ZXJuYW1l" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/arz.adkjah34.com/" ascii //weight: 2
        $x_1_2 = "istema.lnk" ascii //weight: 1
        $x_1_3 = "Aviso de Seguran" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mo0045946" wide //weight: 1
        $x_1_2 = "LISTAOSPORRADEARQUIVOS" ascii //weight: 1
        $x_3_3 = ".pig" wide //weight: 3
        $x_3_4 = "indysockets" wide //weight: 3
        $x_3_5 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cbr600rr" wide //weight: 1
        $x_1_2 = "AD8D82BFF739C0" wide //weight: 1
        $x_1_3 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 88 53 33 d2 89 55 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 32 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 00 70 00 30 00 34 00 33 00 35 00 33 00 34 00 30 00 30 00 37 00 [0-15] 5c 00 4b 00 49 00 4f 00 4c 00 2e 00 70 00 69 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 39 00 41 00 37 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-9] 46 00 46 00 38 00 39 00 35 00 31 00 37 00 33 00 39 00 39 00 35 00 36 00 39 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-159] 4b 00 49 00 4f 00 4c 00 2e 00 70 00 69 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 da 07 00 00 33 c9 8b 15 ?? ?? ?? 00 8b 45 b0 00 ff 75 f0 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 02 00 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba 05 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "List_Files_GetAppdataFolder" ascii //weight: 1
        $x_1_3 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 88 53 33 d2 89 55 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 32 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Up0956457" wide //weight: 1
        $x_1_2 = "UHSHU89459858" wide //weight: 1
        $x_1_3 = "\\Heysoul.ebay" wide //weight: 1
        $x_1_4 = "\\Joffrey.say" wide //weight: 1
        $x_1_5 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
        $x_1_6 = {83 c4 88 53 33 d2 89 55 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 [0-5] 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? [0-2] 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGS_2147712054_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGS"
        threat_id = "2147712054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Safada_russa" ascii //weight: 1
        $x_1_2 = "DesempacotarZIPZINHO" ascii //weight: 1
        $x_1_3 = "batman" ascii //weight: 1
        $x_1_4 = "List_Files_GetAppdataFolder" ascii //weight: 1
        $x_1_5 = "arrocha2016" ascii //weight: 1
        $x_1_6 = "Inicio_do_Processo" ascii //weight: 1
        $x_1_7 = "BAIXANDO_NO_PC" ascii //weight: 1
        $x_1_8 = "Iniciar_AividadeLD" ascii //weight: 1
        $x_1_9 = "IDIOMALOKO2" ascii //weight: 1
        $x_1_10 = "nomepasta" ascii //weight: 1
        $x_1_11 = "Zumper00938" wide //weight: 1
        $x_1_12 = "INIBIREXTRACAO" ascii //weight: 1
        $x_1_13 = "TSTOPJEANS" ascii //weight: 1
        $x_1_14 = {03 04 9e 03 84 9d ?? fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: Low
        $x_1_15 = {83 c4 88 53 33 d2 89 55 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 [0-5] 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? [0-2] 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8}  //weight: 1, accuracy: Low
        $x_1_16 = {8b d0 8d 45 e0 b9 00 00 00 00 e8 ?? ?? ?? ?? 8b 45 e0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BDJ_2147712130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BDJ!bit"
        threat_id = "2147712130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovLw==" wide //weight: 1
        $x_1_2 = "L3BhcmdlLmdpZg==" wide //weight: 1
        $x_1_3 = "YXJyb3MudmJz" wide //weight: 1
        $x_1_4 = "cXN0LmJhaXhhcnNuYXBjaGF0cGMuY29t" wide //weight: 1
        $x_1_5 = "L250ZjIvYy5waHA/dGlwPVsxN10t" wide //weight: 1
        $x_1_6 = "Y29tcHV0ZXJuYW1l" wide //weight: 1
        $x_1_7 = "YXBwZGF0YQ==" wide //weight: 1
        $x_1_8 = "YWxsdXNlcnNwcm9maWxl" wide //weight: 1
        $x_1_9 = "Yy50eHQ=" wide //weight: 1
        $x_1_10 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUG9saWNpZXNcU3lzdGVtXA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGT_2147712616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGT"
        threat_id = "2147712616"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "8GFF4XLB7WHM" ascii //weight: 1
        $x_1_2 = "4989BA699FED45" ascii //weight: 1
        $x_1_3 = {54 52 69 63 6f [0-16] 70 61 67 69 6e 61 30 31}  //weight: 1, accuracy: Low
        $x_1_4 = "Gerenciadordejanelas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEY_2147716111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEY!bit"
        threat_id = "2147716111"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Up0956457" wide //weight: 1
        $x_1_2 = "\\Heysoul.ebay" wide //weight: 1
        $x_1_3 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 88 53 33 d2 89 55 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 32 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZEZ_2147716529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZEZ!bit"
        threat_id = "2147716529"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 6d 6f 64 [0-16] 6c 6f 6a 61 62 69 67 69 6e 66 6f 72 6d 61 74 69 63 61 2e 69 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_3 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGU_2147716990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGU"
        threat_id = "2147716990"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thompson.sey" wide //weight: 1
        $x_1_2 = "BAIXANDO_NO_PC" ascii //weight: 1
        $x_1_3 = "90675655DF4" wide //weight: 1
        $x_1_4 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BGV_2147717302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BGV"
        threat_id = "2147717302"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "max2.tmp" wide //weight: 1
        $x_1_2 = "/track3.ttf" wide //weight: 1
        $x_1_3 = "/rex3.css" wide //weight: 1
        $x_1_4 = "DescerDaMontana" ascii //weight: 1
        $x_1_5 = "SubirMorro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFB_2147718011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFB!bit"
        threat_id = "2147718011"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "E33FDE2BC91A90B217B4550BBAFB5B054884F1D242" wide //weight: 2
        $x_2_2 = "\\thompson.sey" wide //weight: 2
        $x_2_3 = "4309064340646903463" wide //weight: 2
        $x_1_4 = "SO!#LINKKL" ascii //weight: 1
        $x_1_5 = "#LINKKLSO!" ascii //weight: 1
        $x_1_6 = "adoberwebEO!#NOMEPASTA" ascii //weight: 1
        $x_2_7 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 89 45 ?? 8d 85 ?? ?? ?? ?? 8b 55 ?? 8b 94 95 ?? ?? ?? ?? 33 55 ?? e8 ?? ?? ?? ff 8b 95 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ff 8b 45 ?? 83 c7 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZFE_2147718558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFE!bit"
        threat_id = "2147718558"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 f0 8b 55 fc 0f b7 54 5a fe e8 ?? ?? ?? ff ff 75 f0 8d 45 ec 8b 55 fc 0f b7 14 5a e8 ?? ?? ?? ff ff 75 ec 8d 45 f4 ba 03 00 00 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 2a 05 ?? ?? ?? 00 8b 55 f8 88 04 32 83 c3 02 46 3b fb 7f ad}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 53 6a 00 e8 ?? ?? ?? ff 8b f0 85 f6 74 78 8b cb 8b d6 8b 45 fc e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 00 00 00 00 e8 ?? ?? ?? ff 8b 45 d8 e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFG_2147720061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFG!bit"
        threat_id = "2147720061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f4 e8 ?? ?? ?? ff 8d 45 e8 50 b9 02 00 00 00 8b d6 8b c7 e8 ?? ?? ?? ff 8b 4d e8 8d 45 ec ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 ec e8 ?? ?? ?? ff 8b d0 8b 45 fc 0f ?? ?? ?? ff 33 d0 8d 45 f0 e8 ?? ?? ?? ff 8b 55 f0 8d 45 f4 e8 ?? ?? ?? ff 43 83 c6 02 8b 45 fc e8 ?? ?? ?? ff 3b d8 7e 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4d f8 ba ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f8 e8 ?? ?? ?? ff 50 8d 4d f4 ba ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff 8b d8 6a 01 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 6a 00 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFH_2147720218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFH!bit"
        threat_id = "2147720218"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "132"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 100
        $x_10_2 = "C:\\program Files\\AVAST Software\\" wide //weight: 10
        $x_10_3 = {00 00 77 00 70 00 69 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 00 62 00 61 00 74 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_1_5 = {00 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t RE" wide //weight: 1
        $x_1_8 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZFI_2147721260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFI!bit"
        threat_id = "2147721260"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 6f 64 65 5b 30 30 31 5d 67 33 70 72 6f 5b 30 30 31 5d 63 6f 6d 5b 30 30 31 5d 62 72 2f [0-31] 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "Cabakae" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFK_2147723957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFK!bit"
        threat_id = "2147723957"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_2_2 = {7d 03 46 eb 02 33 f6 8b 45 f8 8a 44 30 ff 88 45 ?? 8a 45 ?? 30 45 ?? 8b c7 03 c3 89 45 ?? 8d 55 ?? b9 ?? ?? ?? 00 8b 45 ?? e8 ?? ?? ?? ff 43 3b 5d fc 7c b2}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 55 e4 58 e8 ?? ?? ?? ff 8b 4d ec b8 ?? ?? ?? 00 8b d3 e8 ?? ?? ?? ff b8 ?? ?? ?? 00 8b d3 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFL_2147723958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFL!bit"
        threat_id = "2147723958"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "122"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 100
        $x_10_2 = {62 61 74 65 72 69 61 73 74 69 74 75 6c 61 72 [0-32] 63 6f 6d [0-32] 62 72}  //weight: 10, accuracy: Low
        $x_10_3 = {6d 6f 64 65 72 6e 2d 63 6f 6c 6c 65 67 65 [0-32] 61 6d 69 77 6f 72 6b 73}  //weight: 10, accuracy: Low
        $x_1_4 = "Flion123" ascii //weight: 1
        $x_1_5 = "JUJUBA03" ascii //weight: 1
        $x_2_6 = {8d 45 d0 e8 ?? ?? ?? ff ff 75 d0 8d 45 cc e8 ?? ?? ?? ff ff 75 cc 8d 45 c8 e8 ?? ?? ?? ff ff 75 c8 8d 45 f8 ba 0c 00 00 00 e8 ?? ?? ?? ff 8b 45 f8 8d 55 fc e8 ?? ?? ?? ff 8b 55 fc 8b c6 e8 ?? ?? ?? ff b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZFM_2147723960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFM!bit"
        threat_id = "2147723960"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_3_2 = "remansohoteldeserra" ascii //weight: 3
        $x_1_3 = {62 6c 6f 67 [0-48] 77 70 2d 69 6e 63 6c 75 64 65 73}  //weight: 1, accuracy: Low
        $x_1_4 = {00 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 7a 69 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 68 74 74 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 6e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 4a 55 4a 55 42 41 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZFO_2147723961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFO!bit"
        threat_id = "2147723961"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-4] 75 72 6c 6d 6f 6e 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 [0-32] 5c 6c 6f 67 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {00 6e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {3a 2f 2f 00 [0-64] 68 74 74 70 00 [0-48] 7a 69 70 00 [0-48] 70 68 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_2147723962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!bit"
        threat_id = "2147723962"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-16] 75 72 6c 6d 6f 6e 2e 64 6c 6c [0-48] 41 50 50 44 41 54 41}  //weight: 1, accuracy: Low
        $x_1_3 = {00 70 68 70 00 [0-64] 00 6e 6f 74 69 66 79 00 [0-64] 00 3a 2f 2f 00 [0-73] 00 7a 69 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\log.txt" ascii //weight: 1
        $x_1_5 = {53 8b d8 8b d3 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_2147723962_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.gen!bit"
        threat_id = "2147723962"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 fc b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 fc 8d 83 ?? ?? ?? ?? e8 ?? ?? ?? ff e8 ?? ?? ?? ff 8d 55 f8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8 8d 83 ?? ?? ?? ?? e8 ?? ?? ?? ff 68 ?? ?? ?? ?? e8 ?? ?? ?? ff e8 ?? ?? ?? ff 8d 55 e8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 8b 55 ?? 8a 44 10 ff 3a 45 ?? 74 1b 3a 07 74 17 25 ff 00 00 00 8a 80 ?? ?? ?? 00 33 d2 8a 17 3a 82 ?? ?? ?? 00 75 0d ff 4d ?? 4f 3b 75 ?? 7e cd}  //weight: 1, accuracy: Low
        $x_1_3 = {00 41 50 50 44 41 54 41 00 [0-48] 5c 6c 6f 67 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {5f 63 6f 6d [0-64] 5f 62 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFP_2147723964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFP"
        threat_id = "2147723964"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.gynfit2019.com.br/fotos.jpg" wide //weight: 1
        $x_1_2 = "Microsoft.XMLHTTP" wide //weight: 1
        $x_1_3 = "Adodb.Stream" wide //weight: 1
        $x_1_4 = "ShellExecute" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFS_2147732330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFS!bit"
        threat_id = "2147732330"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_2 = "-ExecutionPolicy bypass -noprofile -windowstyle hidden (New-Object System.Net.WebClient).DownloadFile" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-80] 2e 6f 6e 69 6f 6e 2e 6c 69 6e 6b 2f [0-32] 2e 63 73 73}  //weight: 1, accuracy: Low
        $x_1_4 = {25 54 45 4d 50 25 5c [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZFT_2147732473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFT!bit"
        threat_id = "2147732473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "216.250.99.5/tongji.php?uid=" ascii //weight: 1
        $x_1_2 = {64 6c 2e 65 6e 68 6b 6e 71 71 6c 2e 6c 69 76 65 2f 6d 2f [0-32] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = "sysupdate.log" ascii //weight: 1
        $x_1_4 = "RunTongJi.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZGA_2147732479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZGA!bit"
        threat_id = "2147732479"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 e7 b9 01 00 00 00 8b c6 8b 38 ff 57 0c 8b 4d e8 0f b7 45 e4 d3 e8 f6 d0 30 45 e7 8d 55 e7 b9 01 00 00 00 8b 45 ec 8b 38 ff 57 10 ff 45 e8 4b 75 cd}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 20 00 00 8b 85 10 ff ff ff 50 8b 85 f4 fe ff ff 50 e8 ?? ?? ?? ff 8b d8 85 db 75 17 6a 04 68 00 20 00 00 8b 85 10 ff ff ff 50 6a 00 e8 ?? ?? ?? ff 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZGJ_2147732492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZGJ!bit"
        threat_id = "2147732492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 10
        $x_2_2 = {0f b6 54 5f fe 0f b7 ce c1 e9 08 66 33 d1 66 89 54 58 fe 0f b6 44 5f fe 66 03 f0 66 69 c6 ff c9 66 05 38 5e 8b f0 43 4d 75 ce}  //weight: 2, accuracy: High
        $x_1_3 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZGG_2147732987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZGG!bit"
        threat_id = "2147732987"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 49 00 52 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2d 00 66 00 75 00 6c 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 53 00 54 00 41 00 52 00 54 00 55 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZGH_2147732995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZGH!bit"
        threat_id = "2147732995"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "113"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 100
        $x_10_2 = {8b f0 85 f6 7e 59 bb 01 00 00 00 8b c3 25 01 00 00 80 79 05 48 83 c8 fe 40 48 75 3f 8d 45 f0 50 b9 02 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ff 8b 4d f0 8d 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 8b d0 8d 45 f8 e8 ?? ?? ?? ff 8b 55 f8 8b c7 e8 ?? ?? ?? ff 43 4e 75 ac}  //weight: 10, accuracy: Low
        $x_1_3 = {00 36 43 36 33 36 31 37 33 37 33 36 44 32 45 36 35 37 38 36 35 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 35 35 37 30 36 34 36 31 37 34 36 35 35 33 37 32 37 36 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 36 33 36 44 36 34 32 45 36 35 37 38 36 35 32 30 32 46 36 33 32 30 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 35 33 35 34 34 35 34 44 34 39 34 45 34 36 34 46 32 30 32 36 32 30 35 34 34 31 35 33 34 42 34 43 34 39 35 33 35 34 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 34 44 36 46 37 41 36 39 36 43 36 43 36 31 32 30 37 36 33 35 32 45 33 31 32 30 32 38 35 37 36 39 36 45 36 34 36 46 37 37 37 33 32 30 34 45 35 34 32 30 33 36 32 45 33 31 33 42 32 30 00}  //weight: 1, accuracy: High
        $x_1_8 = {32 45 37 30 36 38 37 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banload_ZFZ_2147733104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZFZ!bit"
        threat_id = "2147733104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 54 24 10 b9 01 00 00 00 8b c6 8b 28 ff 55 0c 8b cf 0f b7 44 24 12 d3 e8 f6 d0 30 44 24 10 8d 54 24 10 b9 01 00 00 00 8b 44 24 0c 8b 28 ff 55 10 47 4b 75 cb}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 10 00 00 8b 85 10 ff ff ff 50 53 e8 ?? ?? ?? ff 6a 04 68 00 10 00 00 8b 85 14 ff ff ff 50 53 e8 ?? ?? ?? ff 8b f8 8b 4d f4 03 8d 14 ff ff ff 8b 16 8b c7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_ZHA_2147733134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.ZHA!bit"
        threat_id = "2147733134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 01 00 00 00 8b c6 8b 38 ff 57 0c 8b 4d ec 0f b7 45 e8 d3 e8 f6 d0 30 45 eb 8d 55 eb b9 01 00 00 00 8b 45 f0 8b 38 ff 57 10 ff 45 ec 4b 75 cd}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 10 00 00 8b 45 fc 50 8b 45 f8 03 43 0c 50 e8 ?? ?? ?? ?? 8b f0 89 73 08 8b 55 fc 8b c6 [0-32] 6a 04 68 00 10 00 00 8b 43 10 50 8b 45 f8 03 43 0c 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_BHZ_2147733148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.BHZ"
        threat_id = "2147733148"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://185.35.139.190/X/4/index3.php" wide //weight: 1
        $x_1_2 = "C:\\Documents and Settings\\JohnDoe\\Application Data\\OkZY6Wx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_AD_2147742873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.AD!MTB"
        threat_id = "2147742873"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 10 8a 02 a2 ?? ?? ?? ?? 8b 4d 10 83 c1 01 89 4d 10 8b 55 0c 89 55 fc b8 ?? ?? ?? ?? 03 45 08 8b 4d 0c 03 4d 08 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 30 88 04 11 8b 4d 08 0f be 91 ?? ?? ?? ?? 85 d2 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 03 45 08 8b 0d ?? ?? ?? ?? 8a 14 08 32 15 ?? ?? ?? ?? 8b 45 0c 03 45 08 8b 0d ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_SQ_2147783580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.SQ!MTB"
        threat_id = "2147783580"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If exist \"%s\" Goto 1" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\traymgr1.exe" ascii //weight: 1
        $x_1_4 = "http://bit.ly/WpcWKf" ascii //weight: 1
        $x_1_5 = "c:\\ProgramData\\outlook.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Banload_SP_2147783581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banload.SP!MTB"
        threat_id = "2147783581"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%appdata%\\windll.exe" ascii //weight: 1
        $x_1_2 = "tcp.ngrok.io" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

