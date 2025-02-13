rule TrojanDownloader_Win32_Delf_KL_2147514122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KL"
        threat_id = "2147514122"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "User-agent: Mozilla/4.0" ascii //weight: 1
        $x_1_2 = "dowload sucessfull" ascii //weight: 1
        $x_1_3 = "loading sucessfull" ascii //weight: 1
        $x_1_4 = {43 61 70 74 69 6f 6e [0-16] 4d 53 73 65 63 75 72 69 74 79 33 32}  //weight: 1, accuracy: Low
        $x_1_5 = "tyming load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Delf_GC_2147582896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GC"
        threat_id = "2147582896"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winlogon" ascii //weight: 1
        $x_1_2 = "down_1_file" ascii //weight: 1
        $x_1_3 = "down conf:" ascii //weight: 1
        $x_1_4 = "WACLEventLogon" ascii //weight: 1
        $x_1_5 = "protect second:" ascii //weight: 1
        $x_1_6 = "down filez" ascii //weight: 1
        $x_1_7 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_8 = "Content-Type:" ascii //weight: 1
        $x_1_9 = "spisok ok" ascii //weight: 1
        $x_1_10 = {50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_CCA_2147583443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.CCA"
        threat_id = "2147583443"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://mail.8u8y.com/ad/pic/123.txt" ascii //weight: 1
        $x_1_2 = "cmd /c del /a autorun.inf" ascii //weight: 1
        $x_1_3 = "\\kaspersky.exe /i" ascii //weight: 1
        $x_1_4 = "\\winlog.txt" ascii //weight: 1
        $x_1_5 = "\\0405.txt" ascii //weight: 1
        $x_1_6 = "shellexecute=GameSetup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_CCA_2147583443_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.CCA"
        threat_id = "2147583443"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {ac fe c8 eb 01 ?? c0 c0 98 eb 01 ?? 2a c1 f9 34 08 eb 01 ?? f9 02 c1 eb 01 ?? f9 f8 eb 01 ?? c0 c0 72 fe c8 34 01 f8 2a c1 f8 eb 01 ?? 02 c1 2c 70 aa e2 cc}  //weight: 20, accuracy: Low
        $x_10_2 = "shellexecute=GameSetup.exe" ascii //weight: 10
        $x_10_3 = "\\kaspersky.exe /i" ascii //weight: 10
        $x_10_4 = "cmd /c del /a autorun.inf" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_2147594504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147594504"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FPUMaskValue" ascii //weight: 10
        $x_10_3 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_4 = "WinExec" ascii //weight: 10
        $x_5_5 = "C:\\dwnSetup\\" ascii //weight: 5
        $x_5_6 = "wxpSetup" ascii //weight: 5
        $x_1_7 = "http://www.goads.cn/setup/setup.asp?id=%s&pcid=%s" ascii //weight: 1
        $x_1_8 = "http://www.softuu.cn/setup/setup.asp?id=%s&pcid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_TG_2147594940_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TG"
        threat_id = "2147594940"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "http://cpk.easy78.cn/count/count.asp?mac=" ascii //weight: 10
        $x_10_3 = "TMESSSANGER" wide //weight: 10
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3" ascii //weight: 1
        $x_1_6 = "AppEvents\\Schemes\\Apps\\Explorer\\Navigating\\.Current" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_TB_2147596401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TB"
        threat_id = "2147596401"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\mprf101.ini" ascii //weight: 1
        $x_1_2 = "mp_filedownf1.php?sn=" ascii //weight: 1
        $x_1_3 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 69 72 65 63 74 58 5c 62 69 6e 5c 76 ?? ?? 5c 64 69 72 65 63 74 78 ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 47 52 45 54 45 43 48 5c 45 6e 67 69 6e 65 5c 76 ?? ?? 5c 67 72 65 74 65 63 68 ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 6c 5c 76 ?? ?? 5c 65 6e 67 69 6e 65 2e 65 78 65 20 2f 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_6 = "Software\\Borland\\Delphi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_TH_2147596437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TH"
        threat_id = "2147596437"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 1
        $x_1_2 = "Common Files\\Macromedia\\nvdiavb.exe" ascii //weight: 1
        $x_1_3 = "Common Files\\InstallShield\\Engine\\2\\iexplore.exe" ascii //weight: 1
        $x_1_4 = "microsoft frontpage\\version2.0\\bin\\lsass.exe" ascii //weight: 1
        $x_1_5 = "mp_filedownf1.php?sn=" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "urlmon.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_AY_2147596523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.AY"
        threat_id = "2147596523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 c4 f4 f7 ff ff 89 55 f8 89 45 fc 8b 45 fc e8 05 bb ff ff 8b 45 f8 e8 fd ba ff ff 33 c0 55 68 a3 7e 40 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 b9 d7 ff ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 ab d7 ff ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a ?? e8 e0 c7 ff ff 33 c0 5a 59 59 64 89 10 68 aa 7e 40 00 8d 45 f8 ba 02 00 00 00 e8 76 b7 ff ff c3 e9 74 b1 ff ff eb eb 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 00 00 b0 7e 40 00 55 8b ec 83 c4 f0 b8 d8 7e 40 00 e8 ec c4 ff ff 33 d2 b8 ?? 7f 40 00 e8 d0 fe ff ff ba ?? 7f 40 00 b8 ?? ?? 40 00 e8 21 fe ff ff 84 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_AZ_2147596524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.AZ"
        threat_id = "2147596524"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 07 b9 ff ff 8b 55 f0 8d 45 f4 e8 ac b9 ff ff 46 4b 75 da}  //weight: 1, accuracy: High
        $x_1_2 = {38 49 40 00 4c 7d 40 00 cc 7b 40 00 00 00 00 00 04 7f 40 00 55 8b ec b9}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff 6a 00 6a 00 8d 4d ?? 66 ba ?? ?? ?? ?? ?? 40 00 e8 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff 50 a1 ?? a8 40 00 e8 ?? ?? ff ff 50 6a 00 e8 ?? ?? ff ff 8d 4d ?? 66 ba ?? ?? ?? ?? ?? 40 00 e8 ?? ?? ff ff 8b 45 ?? 50 8d 4d ?? 66 ba ?? ?? ?? ?? ?? 40 00 e8 ?? ?? ff ff 8b 45 ?? 5a e8 ?? ?? ff ff 8d 4d ?? 66 ba ?? ?? ?? ?? ?? 40 00 e8 ?? fd ff ff 8b 45 ?? 33 d2 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZZ_2147596933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.gen!ZZ"
        threat_id = "2147596933"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "down filez: pora kachatj file #" ascii //weight: 1
        $x_1_2 = "down conf: pora kachatj!" ascii //weight: 1
        $x_1_3 = "dconf.info/hk/getc2.php" ascii //weight: 1
        $x_1_4 = "down conf: vrode ok =" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 1
        $x_1_6 = "kzlw625" ascii //weight: 1
        $x_1_7 = "hk1.0.0.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_TJ_2147597036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TJ"
        threat_id = "2147597036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {e8 81 ef ff ff e9 80 00 00 00 8d 45 f8 50 8b 55 fc b8 98 31 00 10 e8 73 eb ff ff 8b c8 49 ba 01 00 00 00 8b 45 fc e8 db ea ff ff 8d 45 f0 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 f8 e8 c5 ea ff ff 8b 45 f0 e8 61 ea ff ff 50 e8 17 ef ff ff 83 f8 03 75 24 8b 45 f8 e8 4e ea ff ff 8d 55 f4 52 6a 00 50 68 40 30 00 10 6a 00 6a 00 e8 c5 ee ff ff 6a 0a e8 6e ef ff ff}  //weight: 4, accuracy: High
        $x_2_2 = {00 00 48 74 6d 6c 41 64 64 00 55 8b}  //weight: 2, accuracy: High
        $x_3_3 = {6e 74 73 6f 6b 65 6c 65 2e 65 78 65 00 00 00 00 52 65 6d 6f 74 65 20 48 65 6c 70 20 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 00 ff ff ff ff 08 00 00 00 52 61 73 61 75 74 6f 6c}  //weight: 3, accuracy: High
        $x_1_4 = {ba 9c 31 00 10 b8 54 39 00 10 e8 bd fe ff ff c3 ff ff ff ff 0b 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 6d 73 70 65 63 00 ff ff ff ff 09 00 00 00 20 2f 63 20 64 65 6c}  //weight: 1, accuracy: High
        $x_1_6 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_TL_2147597201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TL"
        threat_id = "2147597201"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "andamiro_ini.ini" ascii //weight: 1
        $x_1_3 = "run.imgserver.kr/config.php" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Software\\registry_admi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_RAE_2147597873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAE"
        threat_id = "2147597873"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ram32xp.inf" ascii //weight: 1
        $x_1_2 = "ram64xp.inf" ascii //weight: 1
        $x_1_3 = "\\inf\\" ascii //weight: 1
        $x_1_4 = "install.exe" ascii //weight: 1
        $x_1_5 = "csrss.exe" ascii //weight: 1
        $x_1_6 = "svchost.exe" ascii //weight: 1
        $x_1_7 = "explorer.exe" ascii //weight: 1
        $x_1_8 = "tmpdown32.dll" ascii //weight: 1
        $x_1_9 = "tmpdown33.dll" ascii //weight: 1
        $x_1_10 = "tmpdown34.dll" ascii //weight: 1
        $x_1_11 = "evo_pf_3d" ascii //weight: 1
        $x_1_12 = "evo_pf_boa" ascii //weight: 1
        $x_1_13 = "evo_pf_ebay" ascii //weight: 1
        $x_1_14 = "ukit.zip.dat" ascii //weight: 1
        $x_1_15 = "ukit.dat.zip" ascii //weight: 1
        $x_1_16 = "Windows Management Licence Service" ascii //weight: 1
        $x_1_17 = "REG DELETE \"HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\IntelliForms\\SPW\" /f" ascii //weight: 1
        $x_1_18 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoComplete\" /v \"AutoComplete\" /t REG_DWORD /f /d \"1\"" ascii //weight: 1
        $x_1_19 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoComplete\" /v \"Append Completion\" /t REG_SZ /f /d \"yes\"" ascii //weight: 1
        $x_1_20 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoComplete\" /v \"Append Completion String\" /t REG_SZ /f /d \"yes\"" ascii //weight: 1
        $x_1_21 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\" /v \"FormSuggest PW Ask\" /t REG_SZ /f /d \"no\"" ascii //weight: 1
        $x_1_22 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel\" /v \"FormSuggest Passwords\" /t REG_DWORD /f /d \"1\"" ascii //weight: 1
        $x_1_23 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel\" /v \"FormSuggest\" /t REG_DWORD /f /d \"1\"" ascii //weight: 1
        $x_1_24 = "REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\" /v \"Use FormSuggest\" /t REG_SZ /f /d \"no\"" ascii //weight: 1
        $x_1_25 = "http://romica-puceanu.com" ascii //weight: 1
        $x_1_26 = "http://ro-member1.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_DA_2147597875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.DA"
        threat_id = "2147597875"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{4EC8E3CD-2DEB-4BA2-A6F4-14DA772FB82C}" ascii //weight: 1
        $x_1_2 = "{6C6A9D97-F4B8-40BB-A67D-BA824395FEB2}" ascii //weight: 1
        $x_2_3 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 2
        $x_2_4 = "SOFTware\\Microsoft\\WinDOWS\\CurRENTVersion\\ExpLORER\\SHELLExecuteHOOKs" ascii //weight: 2
        $x_2_5 = "cmd /c del /f /a" ascii //weight: 2
        $x_2_6 = {56 65 72 43 6c 73 69 64 2e 65 78 65 00 00 00 00 77 69 6e 64 6f 77 78 00 53 74 61 72 74 48 6f 6f 6b 32 00 00 53 74 6f 70 48 6f 6f 6b 32}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_TN_2147598475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TN"
        threat_id = "2147598475"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "114"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\1.inf" ascii //weight: 1
        $x_1_2 = "\\dream.exe" ascii //weight: 1
        $x_1_3 = "melove" ascii //weight: 1
        $x_1_4 = "\\autorun.inf\\" ascii //weight: 1
        $x_1_5 = "OPEN=sbl.exe" ascii //weight: 1
        $x_1_6 = "shellexecute=sbl.exe" ascii //weight: 1
        $x_1_7 = "shell\\Auto\\command=sbl.exe" ascii //weight: 1
        $x_1_8 = "cmd.exe /c net stop sharedaccess" ascii //weight: 1
        $x_1_9 = "\\plmmsbl.dll" ascii //weight: 1
        $x_1_10 = "\\AnHao\\antiautorun" ascii //weight: 1
        $x_1_11 = "mylovegirlsbl" ascii //weight: 1
        $x_1_12 = "c:\\a.exe" ascii //weight: 1
        $x_1_13 = "c:\\b.exe" ascii //weight: 1
        $x_1_14 = "c:\\c.exe" ascii //weight: 1
        $x_100_15 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_BA_2147598549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.BA"
        threat_id = "2147598549"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "125"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_1_2 = "\\http\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "trojan" ascii //weight: 1
        $x_1_4 = "spyware" ascii //weight: 1
        $x_1_5 = "hijack" ascii //weight: 1
        $x_1_6 = "killbox" ascii //weight: 1
        $x_1_7 = "win32delfkil" ascii //weight: 1
        $x_1_8 = "combofix" ascii //weight: 1
        $x_1_9 = "win32delf" ascii //weight: 1
        $x_1_10 = "googlebot" ascii //weight: 1
        $x_1_11 = "down filez: pora kachatj file #" ascii //weight: 1
        $x_1_12 = "t_work_proca; timer2_work_timeout=" ascii //weight: 1
        $x_1_13 = "\\system32\\regsvr32.exe" ascii //weight: 1
        $x_1_14 = "down conf: pora kachatj!" ascii //weight: 1
        $x_1_15 = {68 74 74 70 3a 2f 2f [0-32] 2f 68 6b 2f 67 65 74 63 [0-4] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_16 = "down conf: vrode ok =" ascii //weight: 1
        $x_1_17 = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 1
        $x_1_18 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" ascii //weight: 1
        $x_1_19 = "\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" ascii //weight: 1
        $x_1_20 = "PendingFileRenameOperations" ascii //weight: 1
        $x_1_21 = "hk1.0.0.1" ascii //weight: 1
        $x_1_22 = "double_hooka.dll" ascii //weight: 1
        $x_1_23 = "HTTP/1.0" ascii //weight: 1
        $x_1_24 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_25 = {b3 01 6a 00 6a 00 6a 00 6a 03 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e4 8b 45 f4 ba ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 6a 00 6a 00 6a 03 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 50 8b 45 d4 e8 ?? ?? ?? ?? 50 8b 45 e4 50 e8 ?? ?? ?? ?? 89 45 e8 6a 00 68 00 00 00 80 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 45 d0 e8 ?? ?? ?? ?? 50 8b 45 f4 e8 ?? ?? ?? ?? 50 8b 45 e8 50 e8 ?? ?? ?? ?? 8b f0 8d 45 d8}  //weight: 1, accuracy: Low
        $x_1_26 = {8b 45 cc 50 8d 45 e8 50 8d 45 c4 e8 ?? ?? ?? ?? ff 75 c4 68 ?? ?? ?? ?? ff 75 f0 8d 45 c8 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 55 c8 b9 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff 30 68 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 8d 45 c0 ba 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 c0 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_KB_2147598799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KB"
        threat_id = "2147598799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "SAzm10\\ddder.exe" ascii //weight: 1
        $x_1_3 = "SAzm10\\adslog.txt" ascii //weight: 1
        $x_1_4 = "Logical Disk Manager Amdinistrative SerSAzm10" ascii //weight: 1
        $x_1_5 = "CreateServiceA" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_KA_2147599408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KA"
        threat_id = "2147599408"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "e-jok.cn/cnfg/_popwzw.txt" ascii //weight: 1
        $x_1_3 = "e-jok.cn/count/updatedata.aspx?id=" ascii //weight: 1
        $x_1_4 = "canview.txt" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_TU_2147599471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TU"
        threat_id = "2147599471"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Setting Service AutoRun Done!" ascii //weight: 1
        $x_1_2 = {62 65 69 7a 68 75 78 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 65 74 75 70}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = "Anskya&simen" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Delf_TV_2147599852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TV"
        threat_id = "2147599852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "e-jok.cn/count/updatedata.aspx?id=" ascii //weight: 1
        $x_1_3 = "e-jok.cn/cnfg/canview.txt" ascii //weight: 1
        $x_1_4 = "e-jok.cn/cnfg/_popchs" ascii //weight: 1
        $x_1_5 = "TIEBHOFactory" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
        $x_1_8 = "URLDownloadToFile" ascii //weight: 1
        $x_1_9 = "IEBHO.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HA_2147599928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HA"
        threat_id = "2147599928"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TMySafeListU" ascii //weight: 1
        $x_1_2 = "strLastDate=" ascii //weight: 1
        $x_1_3 = ",MTC:" ascii //weight: 1
        $x_1_4 = "127.0.0.1" ascii //weight: 1
        $x_1_5 = "perfs.txt" ascii //weight: 1
        $x_1_6 = "-------start date(" ascii //weight: 1
        $x_1_7 = "ClientIP:" ascii //weight: 1
        $x_1_8 = "total:" ascii //weight: 1
        $x_1_9 = "hh:nn:ss" ascii //weight: 1
        $x_1_10 = "OsStartDays:" ascii //weight: 1
        $x_1_11 = "bfkq.com" ascii //weight: 1
        $x_1_12 = "error :CreateMutex" ascii //weight: 1
        $x_1_13 = "rtl60.bpl" ascii //weight: 1
        $x_1_14 = "@System@@StartExe$qqrp23System@PackageInfoTablep17System@TLibModule" ascii //weight: 1
        $x_1_15 = "SetApiDeclare" ascii //weight: 1
        $x_1_16 = "SetSecurityInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HA_2147599928_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HA"
        threat_id = "2147599928"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "perfmonss_rtl.bin" ascii //weight: 1
        $x_1_2 = "perfmonss.bin" ascii //weight: 1
        $x_1_3 = "perfs.exe" ascii //weight: 1
        $x_1_4 = "fOsStartDays=" ascii //weight: 1
        $x_1_5 = "/install /silent" ascii //weight: 1
        $x_1_6 = "start perfmons" ascii //weight: 1
        $x_1_7 = "UpdateOldServiceToNewService:" ascii //weight: 1
        $x_1_8 = "sleep(nRandomSleep):ok:nowtime=" ascii //weight: 1
        $x_1_9 = "127.0.0.1" ascii //weight: 1
        $x_1_10 = "perfs.txt" ascii //weight: 1
        $x_1_11 = "downer.exe.txt" ascii //weight: 1
        $x_1_12 = "perfmonss.exe.txt" ascii //weight: 1
        $x_1_13 = "routing.txt" ascii //weight: 1
        $x_1_14 = "rtl60.bpl" ascii //weight: 1
        $x_1_15 = "@Classes@TThread@Terminate$qqrv" ascii //weight: 1
        $x_1_16 = "SetEntriesInAclA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_TX_2147599937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TX"
        threat_id = "2147599937"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 68 74 74 70 3a 2f 2f [0-64] 2f 66 6f 74 6f 73 2e 68 74 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {63 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 68 74 74 70 3a 2f 2f [0-64] 2f 76 69 64 65 6f 2e 68 74 6d}  //weight: 1, accuracy: Low
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = {68 74 74 70 3a 2f 2f [0-64] 2f 69 67 73 67 61 74 65 73 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 61 74 [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_6 = {33 c0 55 68 ?? ?? 40 00 ff 30 89 20 e8 ?? ?? ff ff 6a 01 68 ?? ?? 40 00 e8 ?? ?? ff ff b8 ?? ?? 40 00 ba ?? ?? 40 00 e8 ?? ?? ff ff b8 ?? ?? 40 00 ba ?? ?? 40 00 e8 ?? ?? ff ff b8 01 00 00 00 e8 ?? ?? ff ff 8b 04 85 ?? ?? 40 00 ba ?? ?? 40 00 e8 ?? ?? ff ff 84 c0 74 e1 6a 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 40 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_GD_2147600117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GD"
        threat_id = "2147600117"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-32] 2f [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "\\svch1st.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\explorer\\advanced\\folder\\hidden\\showall" ascii //weight: 1
        $x_1_4 = "\\snow.exe" ascii //weight: 1
        $x_1_5 = "cmd.exe /c date 2002-08-28" ascii //weight: 1
        $x_1_6 = "\\winss.sys" ascii //weight: 1
        $x_1_7 = "ravmon.exe" ascii //weight: 1
        $x_1_8 = "ravmond.exe" ascii //weight: 1
        $x_1_9 = "avp.exe" ascii //weight: 1
        $x_1_10 = "avp.com" ascii //weight: 1
        $x_1_11 = "ccenter.exe" ascii //weight: 1
        $x_1_12 = "360Safe.exe" ascii //weight: 1
        $x_1_13 = "360tray.exe" ascii //weight: 1
        $x_1_14 = "VsTskMgr.exe" ascii //weight: 1
        $x_1_15 = "AST.EXE" ascii //weight: 1
        $x_1_16 = "kvsrvxp.exe" ascii //weight: 1
        $x_1_17 = "scan32.exe" ascii //weight: 1
        $x_1_18 = "AvMonitor.exe" ascii //weight: 1
        $x_1_19 = "ANTIARP.exe" ascii //weight: 1
        $x_1_20 = "yahoomessenger" ascii //weight: 1
        $x_1_21 = "trillian.exe" ascii //weight: 1
        $x_1_22 = "skype." ascii //weight: 1
        $x_1_23 = "googletalk." ascii //weight: 1
        $x_1_24 = "URLLWINSS" wide //weight: 1
        $x_1_25 = {6a 00 6a 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 6a 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 6a 00 6a 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 6a 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 6a 00 6a 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 6a 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 6a 00}  //weight: 1, accuracy: Low
        $x_1_26 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_KD_2147600321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KD"
        threat_id = "2147600321"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_3 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "serv1.alwaysproxy2.info" ascii //weight: 1
        $x_1_6 = "eMule v0.48a" ascii //weight: 1
        $x_1_7 = "NvGraphicsInterface" ascii //weight: 1
        $x_1_8 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_KC_2147600322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KC"
        threat_id = "2147600322"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "g.info3344.cn/mypop" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
        $x_1_6 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_UB_2147601111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.UB"
        threat_id = "2147601111"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 1
        $x_1_2 = "FastMM Borland Edition" ascii //weight: 1
        $x_1_3 = "tmpdown32.dll" ascii //weight: 1
        $x_1_4 = "http://www." ascii //weight: 1
        $x_1_5 = "/pdf.pdf" ascii //weight: 1
        $x_1_6 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en;) Gecko/30060309 Firefox/1.5.0.7" ascii //weight: 1
        $x_1_7 = "ed0350CE3494EBD45B2AE8A" ascii //weight: 1
        $x_1_8 = "SystemRoot" ascii //weight: 1
        $x_1_9 = "svchost.exe" ascii //weight: 1
        $x_1_10 = "$(,048<@DHLLPPTTXX\\\\``ddhhllppttttxxxx||||" ascii //weight: 1
        $x_1_11 = "CreateMutexA" ascii //weight: 1
        $x_1_12 = "WinExec" ascii //weight: 1
        $x_1_13 = "EnumCalendarInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_BCJ_2147601307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.BCJ"
        threat_id = "2147601307"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 63 6b 73 65 6e 2e 63 6f 6d 2f 7a 62 2f 75 72 6c [0-1] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {77 65 62 3d 00 00 00 00 ff ff ff ff 04 00 00 00 75 72 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 65 72 76 69 63 65 73 00 00 00 ff ff ff ff 04 00 00 00 73 72 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_RAP_2147601537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAP"
        threat_id = "2147601537"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c [0-8] 2e 6a 70 67}  //weight: 10, accuracy: Low
        $x_10_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6a 61 76 61 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_3 = "URLDownloadToFileA" ascii //weight: 10
        $x_5_4 = ".com/Orkut" ascii //weight: 5
        $x_5_5 = "c:\\windows\\system32\\ork.exe" ascii //weight: 5
        $x_5_6 = "c:\\windows\\system32\\windowsupdate.scr" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_RAP_2147601537_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAP"
        threat_id = "2147601537"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Manages the system Component Object Model (COM). If the service is stopped, most system components will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start" ascii //weight: 1
        $x_1_2 = {26 52 4b 69 74 56 65 72 3d 00 00 00 ff ff ff ff 09 00 00 00 26 52 4b 69 74 52 75 6e 3d 00 00 00 ff ff ff ff 0a 00 00 00 26 56 42 72 6f 77 73 65 72 3d 00 00 ff ff ff ff 09 00 00 00 26 46 69 78 65 64 49 50 3d 00 00 00 ff ff ff ff 06 00 00 00 26 50 6f 72 74 3d}  //weight: 1, accuracy: High
        $x_1_3 = {7c 44 6f 77 6e 6c 6f 61 64 44 69 72 7c 00 00 00 ff ff ff ff 0a 00 00 00 7c 53 65 74 75 70 44 69 72 7c 00 00 ff ff ff ff 09 00 00 00 7c 52 4b 69 74 44 69 72 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_GE_2147602325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GE"
        threat_id = "2147602325"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "Macromedia Flash Player Instalado com sucesso" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\windosremote.exe" ascii //weight: 1
        $x_1_6 = "C:\\Windows\\GbpServer32.exe" ascii //weight: 1
        $x_1_7 = "C:\\Windows\\sistemas.exe" ascii //weight: 1
        $x_1_8 = "C:\\Windows\\WinUpdatedata.exe" ascii //weight: 1
        $x_1_9 = {68 74 74 70 3a 2f 2f [0-32] 63 6f 6d 2e 62 72 2f 77 69 6e 64 6f 73 72 65 6d 6f 74 65 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_10 = {68 74 74 70 3a 2f 2f [0-32] 63 6f 6d 2e 62 72 2f 47 62 70 53 65 72 76 65 72 33 32 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_11 = {68 74 74 70 3a 2f 2f [0-32] 63 6f 6d 2e 62 72 2f 57 69 6e 55 70 64 61 74 65 64 61 74 61 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_12 = "Aplicaivo do MS-DOS" ascii //weight: 1
        $x_1_13 = {33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 ?? ?? ?? ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 ?? ?? ?? ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 ?? ?? ?? ff 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_14 = {33 d2 33 c0 e8 ?? ?? ff ff ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 45 00 e8 ?? ?? ff ff ba ?? ?? 45 00 b8 ?? ?? 45 00 e8 ?? ?? ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_RAS_2147602398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAS"
        threat_id = "2147602398"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {84 c0 74 0c 6a 00 68 ?? ?? 44 00 e8 ?? ?? fb ff e8 ?? ?? fb ff 43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 50 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_RAW_2147602656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAW"
        threat_id = "2147602656"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nnyhomb.7/3!+blls`whamf:#LPHF!5/3:#Vjogntr#OW!6/2:#dm(#Nsdq`#9-4" ascii //weight: 1
        $x_1_2 = "F-StopW.exe" ascii //weight: 1
        $x_1_3 = "bdoesrv.exe" ascii //weight: 1
        $x_1_4 = "bdmcon.exe" ascii //weight: 1
        $x_1_5 = {89 45 f8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 00 8b ?? e8 ?? ?? ?? ?? 50 8b 45 f8 50 e8 ?? ?? ?? ?? 89 45 f4 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 56 68 00 04 00 00 8d 85 f0 fb ff ff 50 8b 45 f4 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_RAY_2147602783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAY"
        threat_id = "2147602783"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?adv=" ascii //weight: 1
        $x_1_2 = "internat.dll,LoadKeyboardProfile" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_10_4 = {88 58 03 8d 45 ?? 8b 15 ?? ?? ?? ?? 8a 52 03 e8 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff bb 73 00 00 00 2b d8 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 88 58 06 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_5 = {55 8b ec 81 c4 a8 fa ff ff 53 56 57 8b fa 8b d8 8d 75 f4 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 68 00 00 00 80 6a 00 6a 00 8b c3 e8 ?? ?? ff ff 50 8b 45 fc 50 e8 ?? ?? ff ff 89 45 f8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8b d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_ZBA_2147603276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZBA"
        threat_id = "2147603276"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 ff 8b e5 5d c3 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 43 6f 6e 74 65 6e 74 20 53 65 72 76 69 63 65 00 55 8b ec 33 c9 51 51 51}  //weight: 1, accuracy: High
        $x_1_2 = {6c 6f 67 2e 64 61 74 00 ff ff ff ff 01 00 00 00 40 00 00 00 ff ff ff ff 17 00 00 00 6d 65 75 73 63 6f 6e 74 61 74 6f 73 2e 66 69 7a 77 69 67 2e 63 6f 6d 00 ff ff ff ff 0c 00 00 00 6d 65 75 73 63 6f 6e 74 61 74 6f 73 00 00 00 00 ff ff ff ff 06 00 00 00 6c 65 67 69 61 6f 00 00 ff ff ff ff 04 00 00 00 2e 74 78 74 00 00 00 00 55 8b ec 33}  //weight: 1, accuracy: High
        $x_1_3 = {45 00 00 00 ff ff ff ff 5e 00 00 00 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 42 2f 30 2f 31 2f 42 30 31 38 31 31 41 46 2d 38 33 44 31 2d 34 38 34 41 2d 38 36 36 42 2d 41 45 34 31 34 41 39 34 38 42 35 46 2f 6d 6d}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 73 73 ?? 2e 62 79 65 74 68 6f 73 74 31 33 2e 63 6f 6d 2f 43 6f 6e 66 69 67 75 72 61 63 6f 65 73 2e 69 6e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZBB_2147603506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZBB"
        threat_id = "2147603506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\winsys.bat" ascii //weight: 1
        $x_1_2 = "\\active_url.dll" ascii //weight: 1
        $x_1_3 = "taskmrg.exe" ascii //weight: 1
        $x_1_4 = "taskimg.exe" ascii //weight: 1
        $x_1_5 = "MysampleAppMutex_1" ascii //weight: 1
        $x_5_6 = {8d 44 24 04 50 e8 ?? ?? ?? ?? 8b c3 8b d4 b9 00 01 00 00 e8 ?? ?? ?? ?? 81 c4 00 01 00 00 5b c3 8b c0 55 8b ec 6a 00 6a 00 53 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? b2 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_ZDE_2147604747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZDE"
        threat_id = "2147604747"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3f 00 00 6d 6d 6d 6d 20 64 2c 20 79 79 79 79 00 00 00 00 04 a6 40 00 04 a6 40 00 60 3f 00 00 61 6d 00 00 04 a6 40 00 04 a6 40 00 50 3f 00 00 70 6d 00 00 04 a6 40 00 04 a6 40 00 40 3f 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 65 78 65 30 00 00 00 1b 00 00 00 00 00 00 00 09 00 00 00 68 3a 6d 6d 20 41 4d 50 4d 00 00 00 04 a6 40 00 04 a6 40 00 f8 3e 00 00 68 3a 6d 6d 3a 73 73 20 41 4d 50 4d 00 00 00 00 04 a6 40 00 04 a6 40 00 dc}  //weight: 2, accuracy: High
        $x_2_2 = {3e 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 20 00 00 00 27 00 00 00 00 00 00 00 14 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 00 00 00 00 64 01 81 00 64 01 81 00 58 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 6d 64 2e 65 78 65 00 3c 00 81 00 bc 00 81 00 30 00 00 00 43 3a 5c 57 49 4e 44 4f 18 00 00 00 1b 00 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 00 0b 00 00 00 43 3a 5c 57 49 4e 44 4f 9c 00 00 00 27 00 00 00 00 00 00 00 14 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 6d 66 63 34 32 2e 65 78 65 00 00 40 00 04 a6 40 00 04 a6 40 00 1c 3e 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 6d 64 2e 65 78 65 00 04 a6 40 00 04 a6 40 00 f4 3d 00 00 04 a6 40 00 ec 3d 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 6b 65 72 6e 6c 33 32 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_4 = "GetStartupInfoA" ascii //weight: 1
        $x_1_5 = "RegOpenKeyExA" ascii //weight: 1
        $x_1_6 = "StartServiceA" ascii //weight: 1
        $x_1_7 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_UD_2147604846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.UD"
        threat_id = "2147604846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 45 76 65 72 79 6f 6e 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 65 6c 65 74 65 64 6c 6c 2e 62 61 74 00 00 00 ff ff ff ff 04 00 00 00 3a 74 72 79 00 00 00 00 ff ff ff ff 05 00 00 00 64 65 6c 20 22}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 68 d8 70 40 00 68 e4 70 40 00 6a 00 e8 05 ff ff ff 68 d8 70 40 00 e8 03 ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZA_2147605145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZA"
        threat_id = "2147605145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 72 00 61 00 7a 00 65 00 72 00 5a 00 00 00 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {0d 4c e3 5c c9 0d 1f 4c 89 7c da a1 b7 8c ee 7c}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 00 53 e8 ?? ?? ff ff 83 e8 04 69 15 ?? ?? 40 00 0b 02 00 00 2b c2 50 53 e8 ?? ?? ff ff a1 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZDG_2147605625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZDG"
        threat_id = "2147605625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{8F537E2A-0173-46AA-BB1B-1E5EA47DE644}" ascii //weight: 1
        $x_1_2 = "TimeDll\\zluExpTools.pas" ascii //weight: 1
        $x_2_3 = {64 ff 30 64 89 20 8d 45 ?? e8 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? 8d 55 ?? b8 04 00 00 00 e8 ?? ?? ?? ?? ff 75 ?? 8d 45 f8 ba 03 00 00 00 e8 ?? ?? ?? ?? a0 ?? ?? ?? ?? 50 8d 45 ?? 50 33 c9 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f8 8b 55 f0 e8 ?? ?? ?? ?? ba ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 eb 14}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 45 f4 50 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 45 ?? 8b 18 ff 53 0c 8b 45 e4 50 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 45 ?? 8b 18 ff 53 04 83 7d e0 00 74 ?? 6a 00 8b 45 e0 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb 0c b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_CG_2147605631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.CG"
        threat_id = "2147605631"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "c:\\windows\\system\\system.exe" ascii //weight: 1
        $x_1_3 = "http://www.apburo.ru/classes/fds/smash.exe" ascii //weight: 1
        $x_1_4 = "c:\\windows\\system\\comands2.exe" ascii //weight: 1
        $x_1_5 = "http://sakang.net/bbs/icon/pic2222.jpg" ascii //weight: 1
        $x_1_6 = {84 c0 74 0c 6a 00 68 ?? ?? 44 00 e8 ?? ?? fb ff 68 c4 09 00 00 e8 ?? ?? fb ff ba ?? ?? 44 00 b8 ?? ?? 44 00 e8 ?? ?? ff ff 84 c0 74 0c 6a 00 68 ?? ?? 44 00 e8 ?? ?? fb ff 6a 00 68 ?? ?? 44 00 e8 ?? ?? fb ff e8 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_AV_2147605810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.AV"
        threat_id = "2147605810"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "pc37/tan3.php" ascii //weight: 1
        $x_1_3 = "\\flashplay.dll" ascii //weight: 1
        $x_1_4 = "\\ms_start.exe" ascii //weight: 1
        $x_1_5 = {54 46 6f 72 6d 33 00}  //weight: 1, accuracy: High
        $x_1_6 = "OnDownloadBegin\\YA" ascii //weight: 1
        $x_1_7 = "shell\\open\\Command=" ascii //weight: 1
        $x_1_8 = "if_p.click();" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_UH_2147605989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.UH"
        threat_id = "2147605989"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 e0 68 d4 3a 47 00 8d 45 f8 ba 04 00 00 00 e8 af 0b f9 ff 8b 45 f4 e8 8f 51 f9 ff 84 c0 74 08 8b 45 f4 e8 a7 51 f9 ff 8d 45 fc ba f8 3a 47 00 e8 a6 08 f9 ff 8b 45 f8 e8 6e 51 f9 ff 84 c0 75 3b 8d 55 dc 8b 45 fc e8 ef fd ff ff 8b 55 dc 8d 45 fc e8 84 08 f9 ff 83 7d fc 00 74 1f 6a 00 6a 00 8b 45 f8 e8 9a 0c f9 ff 50 8b 45 fc e8 91 0c f9 ff 50 6a 00 e8 3d 84 fb ff 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 63 61 73 68 62 61 63 6b 2e 6a 2d 6e 61 76 65 72 32 2e 63 6f 6d 2f 65 78 65 2f 75 72 6c 32 2e 68 74 6d 6c 00 00 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Delf_BL_2147609315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.BL"
        threat_id = "2147609315"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "530"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "DllRegisterServer" ascii //weight: 100
        $x_100_3 = "explorerbar" wide //weight: 100
        $x_100_4 = "Microsoft Inc." wide //weight: 100
        $x_100_5 = "windows-update" wide //weight: 100
        $x_10_6 = "WSAConnect" ascii //weight: 10
        $x_10_7 = "TransmitFile" ascii //weight: 10
        $x_10_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects\\" ascii //weight: 10
        $x_1_9 = "adionalcoo.ini" ascii //weight: 1
        $x_1_10 = "Regsvr32.exe /s " ascii //weight: 1
        $x_1_11 = "http://www.oh2345.cn" ascii //weight: 1
        $x_1_12 = "http://www.info3344.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_BN_2147609455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.BN"
        threat_id = "2147609455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Locales" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "WriteProcessMemory" ascii //weight: 10
        $x_10_4 = "Microsoft Corporation" wide //weight: 10
        $x_10_5 = "%SystemRoot%\\System32\\svchost.exe -k wnttech" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_CN_2147610992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.CN"
        threat_id = "2147610992"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 [0-3] ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f [0-48] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_CT_2147612689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.CT"
        threat_id = "2147612689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://free-service.kir.jp/exexe/" ascii //weight: 10
        $x_10_2 = "MeePlayer" ascii //weight: 10
        $x_10_3 = "ServicePack.exe" ascii //weight: 10
        $x_1_4 = "http://natural9-2nd.com/SWF/" ascii //weight: 1
        $x_1_5 = "software\\borland\\delphi\\rtl" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "shellexecutea" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_EC_2147614115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.EC"
        threat_id = "2147614115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.google.com/bot.html)" ascii //weight: 1
        $x_1_2 = "WriteFile" ascii //weight: 1
        $x_1_3 = "HttpSendRequestA" ascii //weight: 1
        $x_4_4 = {97 8b 8b 8f c5 d0 d0 97 8a 92 9d 9a 8d 8b 90 9c 90 8c 8b 9e d1 8e 8a 90 8b 9e 93 9a 8c 8c d1 9c 90 92 d0 86 d1 8b 87 8b}  //weight: 4, accuracy: High
        $x_4_5 = {97 8b 8b 8f c5 d0 d0 8c 96 93 89 9e 91 9e 8c 85 cb cd d1 98 90 90 98 93 9a 8f 9e 98 9a 8c d1 9c 90 92 d0 86 d1 8b 87 8b}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_ED_2147614116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ED"
        threat_id = "2147614116"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "WriteFile" ascii //weight: 1
        $x_1_3 = "HttpSendRequestA" ascii //weight: 1
        $x_1_4 = "DADOS=" ascii //weight: 1
        $x_1_5 = "7095143859B9626D75C612B5AB7D16C0D112DF5847A44F482555DC2728B3F8801" ascii //weight: 1
        $x_1_6 = "54A4312941F3AD8223663582F5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Delf_DE_2147616617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.DE"
        threat_id = "2147616617"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ExeMutex_hacker" ascii //weight: 10
        $x_10_2 = "DllMutex_hacker" ascii //weight: 10
        $x_1_3 = "JumpHook" ascii //weight: 1
        $x_1_4 = "system\\ini.ini" ascii //weight: 1
        $x_1_5 = "cmd /c sc.exe delete" ascii //weight: 1
        $x_1_6 = "%systemroot%\\system\\svchost.exe" ascii //weight: 1
        $x_1_7 = "\\system\\svchost.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_DI_2147616814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.DI"
        threat_id = "2147616814"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 00 00 00 63 3a 5c 70 61 67 65 66 69 6c 65 2e 49 4e 46}  //weight: 1, accuracy: High
        $x_1_2 = {0f 00 00 00 63 3a 5c 70 61 67 65 66 69 6c 65 2e 6c 6f 67}  //weight: 1, accuracy: High
        $x_1_3 = {19 00 00 00 22 20 7c 20 66 69 6e 64 20 22 20 30 20 62 79 74 65 73 22 20 3e 20 4e 55 4c}  //weight: 1, accuracy: High
        $x_1_4 = {08 00 00 00 5f 75 6e 6b 6e 6f 77 5f}  //weight: 1, accuracy: High
        $x_1_5 = {09 00 00 00 67 6f 74 6f 20 73 61 69 72}  //weight: 1, accuracy: High
        $x_3_6 = {2c 01 72 08 74 15 fe c8 74 20 eb 2b}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_DP_2147616897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.DP"
        threat_id = "2147616897"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "bak\\hjob123\\com" ascii //weight: 6
        $x_6_2 = ".rrads.cn/ins/" ascii //weight: 6
        $x_6_3 = "$$30689.bat" ascii //weight: 6
        $x_4_4 = "msger" ascii //weight: 4
        $x_4_5 = "GetdNew.exe" ascii //weight: 4
        $x_2_6 = "del " ascii //weight: 2
        $x_2_7 = "if exist" ascii //weight: 2
        $x_2_8 = "del /q /f" ascii //weight: 2
        $x_2_9 = "%s\" -p\"%s\" -o- -s -d\"%s" ascii //weight: 2
        $x_1_10 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_6_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 4 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 2 of ($x_4_*))) or
            ((3 of ($x_6_*) and 1 of ($x_1_*))) or
            ((3 of ($x_6_*) and 1 of ($x_2_*))) or
            ((3 of ($x_6_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_DS_2147618083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.DS"
        threat_id = "2147618083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_2 = {2e 6e 65 6f 70 6f 69 6e 74 2e 63 6f 2e 6b 72 00 5c 50 72 6f 67 72 61 6d 46 69 6c 65 73}  //weight: 2, accuracy: High
        $x_1_3 = {41 30 30 30 30 30 30 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {4f 6e 65 4c 6f 61 64 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 65 6f 50 6f 69 6e 74 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {54 77 6f 4c 6f 61 64 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_DT_2147618157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.DT"
        threat_id = "2147618157"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 6a 00 8b ?? ?? 50 e8 ?? ?? ?? ?? 6a 00 8d ?? ?? 50 68 03 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 00 73 69 74 65 3a 00 00 00 53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 64 6f 77 6e 3a 00 00 00 ff ff ff ff 04 00 00 00 54 65 6d 70 00 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_UP_2147618441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.UP"
        threat_id = "2147618441"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "http://www.coolmelife.com/download" ascii //weight: 10
        $x_1_3 = "drivers\\vplose.exe" ascii //weight: 1
        $x_1_4 = "NPMIS.EXE" ascii //weight: 1
        $x_1_5 = "Xiaoyezi_CoolMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_EF_2147619166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.EF"
        threat_id = "2147619166"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 6e 4a 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 ff ff ff ff 09 00 00 00 5c 79 62 7f}  //weight: 1, accuracy: High
        $x_1_2 = {58 63 6e 67 67 4e 73 6e 68 7e 7f 6e 4a 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_GG_2147621227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GG"
        threat_id = "2147621227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 70 65 6e 20 77 77 77 2e 61 73 30 38 2e 63 6f 6d 0d 0a 61 73 30 38 0d 0a 38 38 38 0d 0a 67 65 74 20 63 61 6c 63 2e 6a 70 67 0d 0a 62 79 65 00 ff d8 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {66 74 70 20 2d 73 3a 51 2e 64 61 74 0d 0a 63 6c 73 0d 0a 63 61 6c 63 2e 6a 70 67 0d 0a 64 65 6c 20 51 2e 64 61 74 0d 0a 64 65 6c 20 25 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_FC_2147621419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.FC"
        threat_id = "2147621419"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FUCK....FUCK....FUCK....FUCK...." ascii //weight: 10
        $x_10_3 = "http://s31.cnzz.com/stat.php?id=" ascii //weight: 10
        $x_2_4 = {73 76 63 68 6f 73 74 2e 65 78 65 [0-9] 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 70 6f 6f 6c 65 72 5c 53 74 61 72 74}  //weight: 2, accuracy: Low
        $x_1_5 = {63 6c 61 73 73 65 73 2e 73 79 73 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {57 69 6e 53 76 63 45 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_GI_2147622139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GI"
        threat_id = "2147622139"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Setting Service AutoRun Done!" ascii //weight: 1
        $x_1_2 = "BITS" ascii //weight: 1
        $x_1_3 = {43 6c 69 6e 65 74 30 30 31 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {69 6e 65 74 5f 61 64 64 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_GJ_2147622141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GJ"
        threat_id = "2147622141"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "ShellExecute" ascii //weight: 1
        $x_1_3 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_4 = {2f 6d 79 6c 69 73 74 2e 61 73 70 3f 76 65 72 3d [0-8] 26 74 67 69 64 3d [0-8] 26 61 64 64 72 65 73 73 3d 30 30 2d 30 30 2d 30 30 2d 30 30}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 00 00 00 ff ff ff ff ?? 00 00 00 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73}  //weight: 1, accuracy: Low
        $x_1_6 = {64 65 6c 61 79 [0-15] 72 75 6e [0-48] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_GL_2147624070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GL"
        threat_id = "2147624070"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "1.hiv" ascii //weight: 1
        $x_1_2 = "del %0" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "ieproloader.exe" ascii //weight: 1
        $x_1_5 = "Software\\mmtest" ascii //weight: 1
        $x_1_6 = {52 50 8d 46 48 50 e8 ?? ?? ff ff 83 f8 ff 0f 84 ?? ?? 00 00 89 06 66 81 7e 04 b3 d7 0f 85 ?? ?? 00 00 66 ff 4e 04 6a 00 ff 36 e8 ?? ?? ff ff 40 0f 84 ?? ?? 00 00 2d 81 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_GM_2147624073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.GM"
        threat_id = "2147624073"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.libraryk.com/yy" ascii //weight: 1
        $x_1_2 = "advpacck.dll" ascii //weight: 1
        $x_1_3 = "del %0" ascii //weight: 1
        $x_1_4 = "FNTemper.exe" ascii //weight: 1
        $x_1_5 = {dd 5c 24 10 9b a1 ?? ?? ?? 00 e8 ?? ?? ?? ff dc 44 24 10 83 c4 f8 dd 1c 24 9b 8d 44 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HE_2147626548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HE"
        threat_id = "2147626548"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 30 37 35 30 63 61 72 2e 6e 65 74 2e 63 6e 2f 63 72 61 63 6b 73 61 66 65 2f [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_4 = "CreateFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HH_2147626719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HH"
        threat_id = "2147626719"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cript.dll" ascii //weight: 1
        $x_1_2 = "wind.ini" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Winlogon\\Notify\\ aGbPlugin" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HJ_2147626988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HJ"
        threat_id = "2147626988"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 74 2e 65 78 65 00 00 00 55 8b ec 33 c0 55 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HT_2147627071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HT"
        threat_id = "2147627071"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 73 65 6c 65 63 74 74 68 6f 72 6f 75 67 68 62 72 65 64 73 2e 63 6f 6d 2f 6d 65 64 69 61 2f 6b 6c 2e 67 69 66 00 43 3a 5c 52 75 6e 64 64 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 72 66 77 70 2e 6f 72 67 2f 69 6d 61 67 65 73 2f 64 6c 6b 31 2e 67 69 66 00 00 00 00 43 3a 5c 57 69 6e 6d 73 67 72 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HM_2147627511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HM"
        threat_id = "2147627511"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 00 00 00 47 45 54 20 2f 73 68 6f 77 2e 61 73 70 78 3f 66 69 6c 65 3d 39 39 39 39 26 68 61 73 68 3d 30}  //weight: 1, accuracy: High
        $x_1_2 = {5c 53 59 53 54 45 4d 33 32 5c 6d 73 76 66 77 36 34 2e 75 73 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 89 20 68 c0 77 43 67 6a ff 6a 00 e8 07 db ff ff a3 58 bb 43 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_UZ_2147627611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.UZ"
        threat_id = "2147627611"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "netsh.exe firewall add allowedprogram \"C:\\myapp.exe\" ANTTT ENABLE" ascii //weight: 10
        $x_1_3 = "USER %s@%s@%s" ascii //weight: 1
        $x_1_4 = "www.srpe.org.br" ascii //weight: 1
        $x_1_5 = "srpe7415" ascii //weight: 1
        $x_1_6 = "imgcartaz2.jpg" ascii //weight: 1
        $x_1_7 = "c:\\msn.bck" ascii //weight: 1
        $x_1_8 = "msn.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_ZDH_2147627810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZDH"
        threat_id = "2147627810"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "7A034938-EBD6-4F25-912D-C265F0BBD305" ascii //weight: 1
        $x_1_2 = {4e 65 77 5f 73 74 61 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 [0-12] 5c 49 6e 74 65 6c 5c 57 69 72 65 6c 65 73 73 5c 57 4c 41 4e 50 72 6f 66 69 6c 65 73 5c}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_KW_2147627835_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KW"
        threat_id = "2147627835"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]" ascii //weight: 1
        $x_1_2 = "sharedapp.reg" ascii //weight: 1
        $x_1_3 = "regedit /s " ascii //weight: 1
        $x_1_4 = "\"SharedAPPs\"=\"" ascii //weight: 1
        $x_1_5 = "SVCHOST" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_HW_2147628209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HW"
        threat_id = "2147628209"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\plusbag" ascii //weight: 3
        $x_3_2 = "\\App Management\\ARPCache\\plusbag" ascii //weight: 3
        $x_5_3 = "http://www.plusbag.net/count/install_count.php?pid=" ascii //weight: 5
        $x_5_4 = "windows plusbag" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_HY_2147628225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.HY"
        threat_id = "2147628225"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "WriteFile" ascii //weight: 1
        $x_1_3 = {63 6d 64 20 2f 6b 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 74 77 61 69 6e 5f 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6d 64 20 2f 6b 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 4d 65 73 73 65 6e 67 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {24 37 33 38 37 33 35 37 34 34 37 34 31 37 35 38 38 30 38 37 39 30 37 38 39 38 31 32 37 33 36 37 35 34 37 33 36 00 00 05 54 45 64 69 74 08 55 72 6c 5f 6c 69 6e 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_IE_2147629900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.IE"
        threat_id = "2147629900"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 38 ff 80 fb 30 75 8b 45 fc 80 fb 7a 75}  //weight: 1, accuracy: Low
        $x_1_2 = "2W1P1StG2Y1E1Q1T2Z1P1CtF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_IL_2147630866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.IL"
        threat_id = "2147630866"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\" ascii //weight: 1
        $x_1_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 22 63 64 20 25 [0-160] 26 26 20 64 65 6c 20 72 65 61 64 65 72 5f 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "http://216.6.235.235/ndis/" ascii //weight: 1
        $x_1_4 = "net stop \"System Restore Service\"" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_IR_2147631504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.IR"
        threat_id = "2147631504"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 40 00 85 d2 74 ?? 66 83 7a f6 02 74 ?? e9 ?? ?? ?? ?? 8b 4a f8 41 7e ?? f0 ff 42 f8 87 10 85 d2 74 ?? 8b 4a f8 49 7c ?? f0 ff 4a f8 75 ?? 8d 42 f4 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = ".exe -runservice" wide //weight: 1
        $x_1_4 = "/filtect.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_IU_2147631709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.IU"
        threat_id = "2147631709"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "NTkrnl Secure Suite" wide //weight: 10
        $x_10_3 = "edsonzuandotudo.info/20" ascii //weight: 10
        $x_1_4 = "sent009.hpg.com.br/hunter.jpg" ascii //weight: 1
        $x_1_5 = "sent009.hpg.com.br/willkill.jpg" ascii //weight: 1
        $x_1_6 = "sent009.hpg.com.br/msnloge.jpg" ascii //weight: 1
        $x_1_7 = "sent009.hpg.com.br/msnsend.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_IY_2147632100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.IY"
        threat_id = "2147632100"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.bobozim.hpg.com.br/nohot.jpg" ascii //weight: 1
        $x_1_2 = "avatar.jpg" ascii //weight: 1
        $x_1_3 = "satplg.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LJ_2147632894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LJ"
        threat_id = "2147632894"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Carregando ..." ascii //weight: 10
        $x_10_3 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_4 = "GetKeyNameTextA" ascii //weight: 10
        $x_2_5 = {68 74 74 70 3a 2f 2f [0-15] 2e 74 68 61 69 65 61 73 79 64 6e 73 2e 63 6f 6d 2f [0-21] 6d 61 73 74 65 72 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-15] 2e 73 65 72 76 65 66 74 70 2e 63 6f 6d 2f [0-21] 6d 61 73 74 65 72 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 3a 2f 2f [0-15] 2e 73 65 72 76 65 66 74 70 2e 63 6f 6d 2f [0-32] 63 6f 6e 74 61 64 6f 72 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_8 = "C:\\windows\\winhelp32.ini" ascii //weight: 1
        $x_1_9 = {5c 4d 65 64 69 61 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = {5c 4d 65 64 69 61 5c [0-8] 2e 63 70 6c}  //weight: 1, accuracy: Low
        $x_1_11 = "\\Media\\smss.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_LK_2147632895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LK"
        threat_id = "2147632895"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Erro.. Arquivo corrompido" ascii //weight: 10
        $x_2_3 = {68 74 74 70 3a 2f 2f [0-32] 2e 63 6f 6d 2e 62 72 2f [0-8] 2e 6a 70 67}  //weight: 2, accuracy: Low
        $x_1_4 = {00 73 69 73 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 6d 73 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 74 75 72 62 6f 5f 64 62 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_JO_2147633646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.JO"
        threat_id = "2147633646"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start \"programm\"" ascii //weight: 1
        $x_1_2 = "mynewspages.com" ascii //weight: 1
        $x_1_3 = "dw0.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_JP_2147633672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.JP"
        threat_id = "2147633672"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 6c 43 6c 69 65 6e 74 0d 4c 69 6e 65 73 2e 53 74 72 69 6e 67 73 [0-16] 2e 65 78 65 [0-4] 68 74 74 70 3a 2f 2f 72 65 70 6f 72 74 65 73 32 30 31 2e 63 6f 6d 2f [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {48 6c 69 6e 6b 4e 61 76 69 67 61 74 65 53 74 72 69 6e 67 00 ?? 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_JR_2147633728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.JR"
        threat_id = "2147633728"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Projeto Legacy 2010" ascii //weight: 2
        $x_1_2 = "\\Downloader\\Classes.pas" ascii //weight: 1
        $x_3_3 = "natalfeliz2010.wiki.br/hylex1.swf" ascii //weight: 3
        $x_3_4 = "fantasia2010.com.br/hylex1.swf" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_RAF_2147634349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RAF"
        threat_id = "2147634349"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KuoDouSetup.exe" ascii //weight: 1
        $x_1_2 = ".xz19.com:21000/avtv/" ascii //weight: 1
        $x_1_3 = "/myie/CnNuoIE.exe" ascii //weight: 1
        $x_1_4 = "/yxku/setups.exe" ascii //weight: 1
        $x_1_5 = ".down.xz19.com:21000/backup/" ascii //weight: 1
        $x_1_6 = "c.jf52.com/code/LL_count.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Delf_JX_2147635836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.JX"
        threat_id = "2147635836"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HTTP/1.0 200 OK" ascii //weight: 1
        $x_1_2 = "If exist \"%s\" Goto 1" ascii //weight: 1
        $x_2_3 = "Gtfxinstall" ascii //weight: 2
        $x_2_4 = {68 d0 07 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 cf 09 00 00 e8 ?? ?? ?? ?? 6a 00 ff 36 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_VC_2147635923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.VC"
        threat_id = "2147635923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WINDOWS\\Help\\svchost.e" ascii //weight: 2
        $x_1_2 = "kkill /f /t /im" ascii //weight: 1
        $x_2_3 = "windows\\help\\csrs.e" ascii //weight: 2
        $x_1_4 = "/c sc config rdsessmgr" ascii //weight: 1
        $x_2_5 = "ys-f.ys168.com/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_KK_2147636792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KK"
        threat_id = "2147636792"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{A8F777CC-C6AF-447B-A611-10A9BA15A229}" ascii //weight: 1
        $x_10_2 = "\\Windows\\Reload.dll" ascii //weight: 10
        $x_10_3 = "\\AVG\\AVG9\\avgupd.dll" ascii //weight: 10
        $x_1_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 65 62 2d 65 73 74 2e 63 6f 6d 2f [0-8] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_VD_2147637246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.VD"
        threat_id = "2147637246"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 42 1c 8d 0c b0 8b 04 39 03 c7 89 45 ?? e9}  //weight: 1, accuracy: Low
        $x_3_2 = {66 c7 40 24 60 00 89 ?? 28 64 a1 30 00 00 00 8b 40 10}  //weight: 3, accuracy: Low
        $x_3_3 = "8pines.com/down.txt" ascii //weight: 3
        $x_1_4 = "%s\\s%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_KY_2147637626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.KY"
        threat_id = "2147637626"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 85 db 74 ?? 53 8b 45 f0 50 e8 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = ".xz19.com" ascii //weight: 1
        $x_1_3 = {6d 79 69 65 [0-8] 43 6e 4e 75 6f 49 45 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "/VERYSILENT" ascii //weight: 1
        $x_1_5 = "KuoDouSetup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LM_2147637711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LM"
        threat_id = "2147637711"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = {25 64 00 00 64 6b 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 78 7a 7a 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {63 74 66 6d 6f 6e 5f [0-49] 71 72 6e 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {43 6e 49 45 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6e 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6e 2e 65 78 65 ?? ?? ?? 64 6f 77 6e 32 ?? ?? ?? 6d 79 69 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LN_2147637719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LN"
        threat_id = "2147637719"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = {6c 6d 30 32 ?? ?? ?? ?? 6d 79 69 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {43 6e 4e 75 6f 49 45 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LO_2147637758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LO"
        threat_id = "2147637758"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = "c.7toot.cn" ascii //weight: 1
        $x_1_3 = {63 6e 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 65 78 65 ?? ?? 6c 6d 30 32 ?? ?? ?? ?? 6d 79 69 65}  //weight: 1, accuracy: Low
        $x_1_4 = {25 64 00 00 64 6b 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 78 7a 7a 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 74 66 6d 6f 6e 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LP_2147637759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LP"
        threat_id = "2147637759"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = {64 6f 77 6e 32 ?? ?? ?? 2f 6d 79 69 65 2f ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6e 73 65 74 75 70 73 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 49 45 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 49 45 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LQ_2147637850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LQ"
        threat_id = "2147637850"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = {64 6f 77 6e 32 ?? ?? ?? 2f 6d 79 69 65 2f 70 61 79 75 73 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6e 69 65 73 65 74 75 70 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 4e 75 49 45 73 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 4e 49 45 73 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LR_2147637921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LR"
        threat_id = "2147637921"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 eb 0b cb 89 0a 8b 08 33 0a 81 e1 aa aa aa aa}  //weight: 1, accuracy: High
        $x_1_2 = "My Dropbox\\Projetos\\Javan\\start\\pumanew_2\\pumax.dpr" ascii //weight: 1
        $x_1_3 = {43 41 50 41 2d 43 45 4c 55 4c 41 52 00 00 00 00 55 8b ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LR_2147637921_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LR"
        threat_id = "2147637921"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = ".haoye123.net" ascii //weight: 1
        $x_1_3 = {4b 75 6f 44 6f 75 53 65 74 75 70 73 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4b 75 6f 44 6f 75 53 65 74 75 70 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {63 6e 69 65 73 65 74 75 70 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 4e 75 6f 49 45 73 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 4e 75 6f 49 45 73 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LS_2147637968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LS"
        threat_id = "2147637968"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = {78 7a 7a 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 74 66 6d 6f 6e 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f ?? ?? 73 6b 79 ?? 6a 65 65 70 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 6e 49 45 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 25 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 65 78 65 ?? ?? 6c 6d 30 32 ?? ?? ?? ?? 6d 79 69 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LT_2147638066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LT"
        threat_id = "2147638066"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://211.33.123.40/tdox/install.php?mac=%s&partner=%s" ascii //weight: 1
        $x_1_2 = {16 00 00 00 53 6f 66 74 77 61 72 65 5c 69 63 6f 6e 20 61 63 74 69 76 65 78 78 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 ec c1 e0 06 03 d8 89 5d ec 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d ec d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 ec 5a 8b ca 99 f7 f9 89 55 ec 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LT_2147638066_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LT"
        threat_id = "2147638066"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "temp1%d.txt" ascii //weight: 1
        $x_1_2 = "{9FC5779D-3B58-4D5F-BA2A-9BAC64EC46AE}" ascii //weight: 1
        $x_1_3 = {74 65 73 74 2e 35 32 63 6f 6d 6e 65 74 63 6e 2e 63 6f 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f 25 73 2f 74 6f 6f 6c 73 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_LU_2147638598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.LU"
        threat_id = "2147638598"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".173pf.cn/?" ascii //weight: 1
        $x_1_2 = "98.126.208.83/get.asp?" ascii //weight: 1
        $x_2_3 = "}aae/::&!&,&;v{:m|tz;pmp" ascii //weight: 2
        $x_2_4 = "0TYY@FPGFEGZS\\YP0Im|tz;pmp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_MI_2147640293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.MI"
        threat_id = "2147640293"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t1.zip" wide //weight: 1
        $x_1_2 = "schost.exe -runserivce" wide //weight: 1
        $x_1_3 = "sfservice.exe -runserivce" wide //weight: 1
        $x_1_4 = "Cara de Pau" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Delf_MS_2147640980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.MS"
        threat_id = "2147640980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Debugs\\lsass00.exe" ascii //weight: 3
        $x_2_2 = "752745744745745789812746752752" ascii //weight: 2
        $x_1_3 = "HTTP/1.0 200 OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZST_2147642137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZST"
        threat_id = "2147642137"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "f.1.eastforti.cn/d6/" ascii //weight: 1
        $x_1_2 = {00 73 2e 62 61 74 00 23 00 22 20 67 6f 74 6f 20 61 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 65 6c 20 25 30}  //weight: 1, accuracy: Low
        $x_1_3 = {3f 74 74 6c 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 76 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 73 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 6e 3d 10 00 78 2e 61 73 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_NB_2147642448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NB"
        threat_id = "2147642448"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "re@**@g a*dd \"HK@EY_C@*UR@*R*EN@T_US*ER" ascii //weight: 5
        $x_5_2 = "R@*#u*@*n**DL*L3@#*2.|e*x@e* S*hell*|*3#2.D*@L*@L, Co*nt|*r@*ol#_R@*u*|n*@D#*LL" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZSA_2147642536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZSA"
        threat_id = "2147642536"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".xz19.com" ascii //weight: 1
        $x_1_2 = {63 74 66 6d 6f 6e 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 71 72 6e 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {43 6e 49 45 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 2e 65 78 65 ?? ?? 6c 6d 30 32 ?? ?? ?? ?? 6d 79 69 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_AXZ_2147642700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.AXZ"
        threat_id = "2147642700"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "58.221.31.22:802/ftdata/" ascii //weight: 1
        $x_1_2 = {00 64 6e 66 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {00 5c 6e 76 62 61 63 6b 75 70 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = "\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ND_2147642811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ND"
        threat_id = "2147642811"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "%d: cmd=%s hour=%s:%s:%s SystemTime.wHour= %d:%d:%d param= %s install=%d Download=%d HaveExecute=%d" ascii //weight: 5
        $x_4_2 = "=========new install atom,write registery and write back log ============" ascii //weight: 4
        $x_4_3 = "http://333.e26.cn/admin/writelog.aspx?Action=%s&Owner=%s&IP=%s&Username=%s&ComputerName=%s&Os=%s&LogDate=%s&Memo=%s" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_NH_2147643225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NH"
        threat_id = "2147643225"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b d8 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 11 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_NJ_2147643368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NJ"
        threat_id = "2147643368"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 78 64 74 69 63 2e 74 78 74 00 00 ff ff ff ff 0b 00 00 00 64 74 69 63 69 73 61 62 2e 6e 77 00 ff ff ff ff 0b 00 00 00 64 74 69 63 69 73 61 62 2e 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {24 64 65 6c 69 6d 6f 6c 65 30 2e 62 61 74 00 00 ff ff ff ff 04 00 00 00 3a 74 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZWH_2147643506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZWH"
        threat_id = "2147643506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\exe.exe" wide //weight: 1
        $x_1_2 = "c:\\result.vbs" wide //weight: 1
        $x_1_3 = "c : \\ e x e . e x e" ascii //weight: 1
        $x_1_4 = "/ d l . d r o p b o x . c o m / u / 2 0 2 0 6 2 0 / f i n e p r o x y . e x e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_NK_2147643508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NK"
        threat_id = "2147643508"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "60.191.254.253" ascii //weight: 1
        $x_1_2 = "std3322.com" ascii //weight: 1
        $x_1_3 = "glad123.com" ascii //weight: 1
        $x_1_4 = "clud33.com" ascii //weight: 1
        $x_10_5 = "\\setop3010.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_NK_2147643508_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NK"
        threat_id = "2147643508"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aiyayumne" wide //weight: 1
        $x_1_2 = ".downxia.net" wide //weight: 1
        $x_1_3 = {8b 14 98 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7f 16 a1 ?? ?? ?? ?? 8b 14 98 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7e 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_NO_2147644406_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NO"
        threat_id = "2147644406"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cvssrv.exe -runserivce" wide //weight: 2
        $x_2_2 = {00 00 53 00 74 00 61 00 62 00 69 00 6c 00 69 00 7a 00 65 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "/d1.zip" wide //weight: 1
        $x_1_4 = "wdb.dll" wide //weight: 1
        $x_1_5 = "wdc.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_ZWR_2147644697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZWR"
        threat_id = "2147644697"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 6e 65 77 ?? 73 2e 34 68 64 6e 2e 63 6f 6d 3a 35 30 30 31 2f 63 6f 6d 6d 64 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {14 00 00 00 5c 73 74 61 72 74 5c 44 4e 46 63 68 69 6e 61 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {17 00 00 00 5c 73 74 61 72 74 5c 44 4e 46 43 6f 6d 70 6f 6e 65 6e 74 2e 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZXC_2147645095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZXC"
        threat_id = "2147645095"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c 00 [0-16] 00 68 74 74 70 3a 2f 2f [0-32] 2e 6a 70 67 00 [0-16] 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 65 73 5c [0-16] 2e 65 78 65 00}  //weight: 4, accuracy: Low
        $x_1_2 = "cmd /k C:\\ProgramDates\\ManageWin.exe" ascii //weight: 1
        $x_1_3 = "cmd /k C:\\ProgramDates\\SystemOpera.exe" ascii //weight: 1
        $x_1_4 = "cmd /k C:\\ProgramDates\\sysuptad.exe" ascii //weight: 1
        $x_1_5 = "http://firestweb.com/loja/social/1.jpg" ascii //weight: 1
        $x_1_6 = "http://www.nerddogueto.com.br" ascii //weight: 1
        $x_1_7 = "http://firestweb.com/loja/social/2.jpg" ascii //weight: 1
        $x_1_8 = "http://firestweb.com/loja/social/3.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_NT_2147645116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NT"
        threat_id = "2147645116"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 10
        $x_10_2 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 10
        $x_10_3 = "jpdesk" wide //weight: 10
        $x_1_4 = "58.253.235.8" wide //weight: 1
        $x_1_5 = "dl_dir2.qq.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_NY_2147645388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NY"
        threat_id = "2147645388"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://www.bvleo.blogger.com.br/Galera%20da%20Facu%20em%20Pirapora.jpg" ascii //weight: 3
        $x_2_2 = "/install /silent" ascii //weight: 2
        $x_2_3 = "http://dl.dropbox.com/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_NZ_2147645491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.NZ"
        threat_id = "2147645491"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = {77 2e 32 73 68 61 72 65 64 2e 63 6f 6d 2f 66 69 6c 65 2f [0-8] 2f [0-8] 2e 68 74 6d 6c}  //weight: 10, accuracy: Low
        $x_10_3 = "regnow.exe C:\\WINDOWS\\msapps\\msinfo\\santa06.dll /s" ascii //weight: 10
        $x_1_4 = "C:\\WINDOWS\\security\\Database\\" ascii //weight: 1
        $x_1_5 = "count1.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_OA_2147645578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.OA"
        threat_id = "2147645578"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 33 00 2e 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 61 00 77 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 6f 00 73 00 31 00 2f 00 [0-8] 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: Low
        $x_1_2 = "\\kidk.exe" wide //weight: 1
        $x_1_3 = "\\mata.exe" wide //weight: 1
        $x_1_4 = "\\msn.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_OK_2147646467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.OK"
        threat_id = "2147646467"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windowupdate.dll" ascii //weight: 1
        $x_1_2 = "IExploreupdate" ascii //weight: 1
        $x_1_3 = "webcam_plugin" ascii //weight: 1
        $x_1_4 = "4')O9W)A;49I;&5S" ascii //weight: 1
        $x_1_5 = "7$-O;6UO;B!&:6QE<UP" ascii //weight: 1
        $x_1_6 = "7$EN=&5R;F5T($5X<&QO<F5R7&ES97)V:6-E<UP" ascii //weight: 1
        $x_1_7 = "\\iservices\\" ascii //weight: 1
        $x_1_8 = "=V5B8V%M7W!L=6=I;BYE>&4" ascii //weight: 1
        $x_1_9 = ";&EV975P9&%T92YE>&4" ascii //weight: 1
        $x_1_10 = "<W!O=&QI9VAT+F5X90" ascii //weight: 1
        $x_1_11 = ":F%V869E960N97AE" ascii //weight: 1
        $x_1_12 = "4V]F='=A<F5<36EC<F]S;V9T7%=I;F1O=W" ascii //weight: 1
        $x_1_13 = "861V87!I,S(N9&QL" ascii //weight: 1
        $x_1_14 = "4F5G0W)E871E2V5Y17A!" ascii //weight: 1
        $x_1_15 = "4F5G4V5T5F%L=65%>$$" ascii //weight: 1
        $x_1_16 = ":'1T<#HO+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanDownloader_Win32_Delf_PN_2147649109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.PN"
        threat_id = "2147649109"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 2e 00 65 00 78 00 65 00 00 [0-16] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6f 00 72 00 69 00 6f 00 6e 00 6c 00 6f 00 64 00 7a 00 2e 00 70 00 6c 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 62 00 61 00 6e 00 6e 00 65 00 72 00 73 00 2f 00 [0-4] 2e 00 67 00 69 00 66 00 [0-4] 6f 00 70 00 65 00 6e 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 00 2e 00 65 00 78 00 65 00 00 [0-16] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6f 00 72 00 69 00 6f 00 6e 00 6c 00 6f 00 64 00 7a 00 2e 00 70 00 6c 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 62 00 61 00 6e 00 6e 00 65 00 72 00 73 00 2f 00 [0-4] 2e 00 67 00 69 00 66 00 [0-4] 6f 00 70 00 65 00 6e 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Delf_PP_2147649516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.PP"
        threat_id = "2147649516"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s3.amazonaws.com/jobs01/compilados.zip" wide //weight: 1
        $x_1_2 = "sys32\\compilados.zip" wide //weight: 1
        $x_1_3 = "sys32\\sobe.exe" ascii //weight: 1
        $x_1_4 = "sys32\\Msn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Delf_QC_2147651886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QC"
        threat_id = "2147651886"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EnableLUA /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_2 = "google.com.br" ascii //weight: 1
        $x_1_3 = "Timer_RegistroTimer" ascii //weight: 1
        $x_1_4 = "Timer_DownloadTimer" ascii //weight: 1
        $x_1_5 = "$(,048<@DHLLPPTTXX\\\\``ddhhllppttttxxxx||||" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "EnumCalendarInfoA" ascii //weight: 1
        $x_1_9 = "63E475F57E869FA5BC4DD66DF8080309010203031C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_Delf_QE_2147652156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QE"
        threat_id = "2147652156"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 6d 6f 6e 74 61 67 65 2e 6a 70 67 50 00 ff ff ff ff 09 00 00 00 73 65 74 75 70 2e 65 78 65 00 00 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_QG_2147652962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QG"
        threat_id = "2147652962"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 55 f8 ff 34 90 8d 45 e4 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 e4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 8b 0c 90 8d 45 e8 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e8 e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 55 f8 8b 04 90}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8 ?? ?? ?? ?? 8b 83 ?? ?? 00 00 66 be eb ff e8 ?? ?? ?? ?? eb 30 80 bb ?? ?? 00 00 00 75 ?? c6 83 ?? ?? 00 00 01}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 eb ?? e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 e8 03 00 00 e8 ?? ?? ?? ?? 8b 45 fc 8b 80 18 03 00 00 66 be eb ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Delf_QL_2147653478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QL"
        threat_id = "2147653478"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 01 00 00 00 8d 85 98 fa ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 68 00 04 00 00 8d 85 e4 fb ff ff 50 8b 45 ec 50 e8 ?? ?? ?? ?? 6a 00 8d 95 e4 fb ff ff 8b 0b 8d 85 98 fa ff ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = "svhosts.exe" ascii //weight: 1
        $x_1_3 = {2f 61 72 71 75 69 76 6f [0-5] 2e 7a 69 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_QM_2147653483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QM"
        threat_id = "2147653483"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 24 6a 00 6a 23 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? b9 00 01 00 00 e8 ?? ?? ?? ?? 8d 4d e4 ba 01 00 00 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 d8 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_QS_2147653861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QS"
        threat_id = "2147653861"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d f8 8b 55 fc e8 ?? ?? ff ff 84 c0 74 20 33 d2 8b 45 f8 e8 ?? ?? ff ff b8 88 13 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {79 00 c5 92 7a 00 d9 a6 72 00 e9 b8 68 00 fb bc 63 00 e0 a8 7b 00 e9 b5 74 00 b7 c8 7e 00 ff c1 4f 00 ff c7 5d 00 db cb 65 00 fd c3 64 00 f9 ca 76 00 e9 d1 71 00 fd d6 7b 00 00 00 00 00 5c bc 86 00 6e ca}  //weight: 1, accuracy: High
        $x_1_4 = {d9 8b 00 ff ce 85 00 f9 d2 86 00 ed c1 92 00 f2 cc 9a 00 fa d9 94 00 e9 e2 9b 00 fe e6 9a 00 c6 c0 aa 00 c3 d8 ad 00 db c3 b4 00 e8 c5 a7 00 f3 c8 aa 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_QU_2147653918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QU"
        threat_id = "2147653918"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system\\F.exe" ascii //weight: 1
        $x_1_2 = {8d 45 f8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8 8b 83 0c 03 00 00 8b ce e8 ?? ?? ?? ff 8b c6 e8 ?? ?? ?? ff 8b 83 ?? 03 00 00 b2 01 e8 ?? ?? ?? ff 6a 05 68 ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_QW_2147654728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QW"
        threat_id = "2147654728"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 78 65 00 ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00 ff ff ff ff 01 00 00 00 2f 00 00 00 ff ff ff ff 0e 00 00 00 64 31 2e 64 6f 77 6e 78 69 61 2e 6e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = {e8 6e 5b fd ff 83 f8 01 1b db 43 c6 45 d7 00 84 db 75 3c 8b 55 ec b8 28 fe 44 00 e8 83 53 fb ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_QX_2147654796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QX"
        threat_id = "2147654796"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "down.winbk2cl.com/bhon/winbk2cl2.dll" ascii //weight: 1
        $x_1_2 = "down.winsoft1.com/setup/p003_bk2/setup.exe" ascii //weight: 1
        $x_1_3 = "down.winbk2cl.com/Install_freezone_search_180_B.exe" ascii //weight: 1
        $x_1_4 = "win.winbk2cl.com/md/ch.html?MAC=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Delf_QZ_2147655231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.QZ"
        threat_id = "2147655231"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N/EZTGhcSBx4VUURcVXxtWtM25P" ascii //weight: 1
        $x_1_2 = "hWdgveR3Xmm8wJ/tHp006ZoD4iwr9p2+2tGdq1Vk11im+" ascii //weight: 1
        $x_1_3 = "DecryptMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Delf_TE_2147664549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.TE"
        threat_id = "2147664549"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 40 30 50 e8 ?? ?? ?? ?? 8d 55 fc b8 20 00 00 00 e8 ?? ?? ?? ?? 8b 55 fc 8d 83 ?? 03 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 ?? 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 00 8b 40 30 50 e8 ?? ?? ?? ?? 8d 55 fc b8 20 00 00 00 e8 ?? ?? ?? ?? ff 75 fc 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 83 28 03 00 00 ba 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/VERYSILENT /SP-" ascii //weight: 1
        $x_1_4 = "filenolja.com/spon" ascii //weight: 1
        $x_1_5 = "Code: %d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZXX_2147708754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZXX!bit"
        threat_id = "2147708754"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 22 bb 01 00 00 00 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 0f b7 54 5a fe 66 83 f2 ?? 66 89 54 58 fe 43 4e 75 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZXZ_2147708773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZXZ!bit"
        threat_id = "2147708773"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 2d ?? ?? ?? ?? d1 e8 8b 4d ?? 8b 55 ?? 66 8b 04 45 ?? ?? ?? ?? 66 89 04 4a 8b 45 ?? 40 89 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = "msiexec /q /i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_ZYA_2147717383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.ZYA!bit"
        threat_id = "2147717383"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 fc 0f b7 54 7a fe 66 3b 10 75 25 8d 85 ?? ?? ?? ff 0f b7 13 e8 ?? ?? ?? ff 8b 95 ?? ?? ?? ff 8b 45 f8 e8 ?? ?? ?? ff 8b 45 f8 c6 45 ?? 01 eb 09 83 c3 02 83 c0 02 4e 75 c5}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 05 6a 00 6a 00 a1 ?? ?? ?? 00 e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 6a 00 e8 ?? ?? ?? ff 8d 55 d8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_2147800053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147800053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "delallmonitorfile.exe" ascii //weight: 1
        $x_1_3 = "Nthost.exe" ascii //weight: 1
        $x_1_4 = "222.122.163.9/install_count.html?id=Nthost&MAC=" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_2147800053_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147800053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba cc 03 45 00 e8 ?? ?? ?? ff b8 20 ea 45 00 ba 00 04 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 18 04 45 00 e8 ?? ?? ?? ff b8 20 ea 45 00 ba 54 04 45 00}  //weight: 1, accuracy: Low
        $x_1_3 = "vidsxxxvids.com" ascii //weight: 1
        $x_1_4 = "sellbuytraff.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_2147800053_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147800053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b d8 b8 a4 35 45 00 e8 5b 53 fb ff 84 c0 74 0e a1 c0 4e 45 00 8b 00 e8 e7 c7 ff ff 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = "winup.jpg" ascii //weight: 1
        $x_1_3 = "Outlooks.jpg" ascii //weight: 1
        $x_1_4 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 4d 53 4e 20 4d 65 73 73 65 6e 67 65 72 5c 44 65 76 69 63 65 20 4d 61 6e 61 67 65 72 5c 6d 73 6e 67 72 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Delf_2147800053_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147800053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6e 64 65 78 2e 61 73 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 6e 64 65 78 2e 68 74 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 6e 64 65 78 2e 68 74 6d 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 6e 64 65 78 2e 70 68 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 44 65 66 61 75 6c 74 2e 61 73 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? 44 65 66 61 75 6c 74 2e 68 74 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? 44 65 66 61 75 6c 74 2e 68 74 6d 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 44 65 66 61 75 6c 74 2e 50 48 50}  //weight: 1, accuracy: Low
        $x_1_2 = "SYSTEM\\ControlSet001\\Services\\W3SVC\\Parameters\\Virtual Roots" ascii //weight: 1
        $x_1_3 = {6d 79 64 6f 77 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 74 67 69 64 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 61 64 64 72 65 73 73 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "zsmsdf32.ini" ascii //weight: 1
        $x_1_5 = "zhqbdf16.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Delf_2147800053_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147800053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 00 00 00 43 00 00 00 68 74 74 70 3a 2f 2f 63 61 72 6e 61 76 61 6c 32 30 30 38 66 6f 74 6f 73 2e 63 6f 6d 2e 64 69 73 68 35 30 33 31 2e 6e 65 74 2e 69 62 69 7a 64 6e 73 2e 63 6f 6d 2f 53 4f 55 52 43 45 5f 48 34 43 4b 33 52 00 dc 03 81 00 dc 03 81 00 80 01 00 00 65 00 00 00 ec 03 81 00 ec 03 81 00 10 00 00 00 20 00 00 00 1b 00 00 00 00 00 00 00 09 00 00 00 77 69 6e 64 73 2e 65 78 38 00 00 00 2f 00 00 00 00 00 00 00 1d 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 77 69 6e 64 73 2e 65 78 65 00 2f 8b}  //weight: 10, accuracy: High
        $x_5_2 = "C:\\WINDOWS\\SYSTEM32\\rundlll.exe" ascii //weight: 5
        $x_5_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RuD" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_2147800053_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf"
        threat_id = "2147800053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3110"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = "TWindowClassTUpdaterApplication" ascii //weight: 1000
        $x_1000_2 = {68 74 74 70 3a 2f 2f 38 30 2e 36 39 2e 31 36 30 2e [0-30] 2f}  //weight: 1000, accuracy: Low
        $x_1000_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1000
        $x_5_4 = "2BBD7C14-F0A8-23C2-9009-0F0EE3726AB4" ascii //weight: 5
        $x_5_5 = "30958118-4645-4064-85B1-B53D76313672" ascii //weight: 5
        $x_5_6 = "safe-updates.txt" ascii //weight: 5
        $x_5_7 = "&request=list&type=" ascii //weight: 5
        $x_100_8 = "HP Update Assistant" ascii //weight: 100
        $x_100_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1000_*) and 1 of ($x_100_*) and 2 of ($x_5_*))) or
            ((3 of ($x_1000_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Delf_RK_2147804287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.RK"
        threat_id = "2147804287"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 00 68 00 6f 00 75 00 75 00 73 00 68 00 61 00 33 00 33 00 2e 00 69 00 63 00 75 00 00 00 2f 00 6a 00 71 00 75 00 65 00 72 00 79 00 2f 00 6a 00 71 00 75 00 65 00 72 00 79 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "fjiisiis33.icu" wide //weight: 1
        $x_1_3 = "powershell -nop -ep bypass -f %temp%\\enu.ps1" wide //weight: 1
        $x_1_4 = "opera_r774h4f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Delf_PAFJ_2147918849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delf.PAFJ!MTB"
        threat_id = "2147918849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "processhacker.exe" ascii //weight: 1
        $x_1_2 = "taskmgr.exe" ascii //weight: 1
        $x_1_3 = "regsvr32.exe /s" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii //weight: 1
        $x_1_6 = "://%s/gate/download_exec" ascii //weight: 1
        $x_1_7 = "://%s/gate/update_exec" ascii //weight: 1
        $x_1_8 = "procexp.exe" ascii //weight: 1
        $x_1_9 = "procmon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

