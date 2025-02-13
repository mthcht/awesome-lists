rule PWS_Win32_Delf_A_2147583577_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.gen!A"
        threat_id = "2147583577"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".Upack" ascii //weight: 10
        $x_6_2 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 6
        $x_1_3 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_5 = "StartHook" ascii //weight: 1
        $x_1_6 = "if exist \"" ascii //weight: 1
        $x_1_7 = "goto try" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_MM_2147596349_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.MM"
        threat_id = "2147596349"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Tencent\\Ie" ascii //weight: 1
        $x_1_2 = "bla145" ascii //weight: 1
        $x_1_3 = "ListBox" ascii //weight: 1
        $x_1_4 = "bg5dx8e" ascii //weight: 1
        $x_1_5 = "First" ascii //weight: 1
        $x_1_6 = "DXown" ascii //weight: 1
        $x_1_7 = "Name=" ascii //weight: 1
        $x_1_8 = "&Pass=" ascii //weight: 1
        $x_1_9 = "&Mac=" ascii //weight: 1
        $x_1_10 = "Down.dll" ascii //weight: 1
        $x_1_11 = "HookCl" ascii //weight: 1
        $x_1_12 = "HookOn" ascii //weight: 1
        $x_1_13 = "C:\\Windows\\iexplore.$" ascii //weight: 1
        $x_1_14 = "ExplOrer.exe" ascii //weight: 1
        $x_1_15 = "GetComputerNameA" ascii //weight: 1
        $x_1_16 = "CreateWindowExA" ascii //weight: 1
        $x_1_17 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_18 = "PostMessageA" ascii //weight: 1
        $x_1_19 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_20 = "CallNextHookEx" ascii //weight: 1
        $x_1_21 = "HttpSendRequestA" ascii //weight: 1
        $x_1_22 = "HttpQueryInfoA" ascii //weight: 1
        $x_1_23 = "HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_KI_2147596350_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.KI"
        threat_id = "2147596350"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "StrikeOut" ascii //weight: 1
        $x_1_2 = "HotLight" ascii //weight: 1
        $x_2_3 = "gsmtp185.google.com" ascii //weight: 2
        $x_2_4 = "%0%2%4%6%8%:%<%>%@%B%E%G%I%" ascii //weight: 2
        $x_2_5 = "msnlist.txt" ascii //weight: 2
        $x_3_6 = {8b 80 00 03 00 00 05 90 00 00 00 ba 03 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 45 fc 8b 80 00 03 00 00 8b 48 6c b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc 8b 80 fc 02 00 00 ba}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_EF_2147598154_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EF"
        threat_id = "2147598154"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1418"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1000
        $x_100_2 = "SHADUXX" ascii //weight: 100
        $x_100_3 = "KVXP_Monitor" ascii //weight: 100
        $x_100_4 = "Q360SafeMonClass" ascii //weight: 100
        $x_100_5 = "VERCLSID.EXE" ascii //weight: 100
        $x_10_6 = "{3495D328-661A-4FB0-BA67-8ACDD1704D1E}" ascii //weight: 10
        $x_5_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 5
        $x_1_8 = "del %0" ascii //weight: 1
        $x_1_9 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_10 = "CreateProcessA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_EF_2147598154_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EF"
        threat_id = "2147598154"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "Zlodziej GG v1.1 [LOG]" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\kill.bat" ascii //weight: 1
        $x_1_4 = "if exist" ascii //weight: 1
        $x_1_5 = "goto kill" ascii //weight: 1
        $x_1_6 = "nazwa_kontrolowanego_programu" ascii //weight: 1
        $x_1_7 = "c:\\plik.exe" ascii //weight: 1
        $x_1_8 = "multipart/related; type=\"multipart/alternative\"; boundary=\"=_MoreStuf_2relzzzsadvnq1234w3nerasdf" ascii //weight: 1
        $x_1_9 = "multipart/alternative; boundary=\"=_MoreStuf_2zzz1234sadvnqw3nerasdf" ascii //weight: 1
        $x_1_10 = "application/octet-stream" ascii //weight: 1
        $x_1_11 = {8b 8d f4 fd ff ff 8d 85 f8 fd ff ff ba ?? ?? 46 00 e8 ?? ?? f9 ff 8b 95 f8 fd ff ff 8d 85 28 fe ff ff e8 ?? ?? f9 ff e8 ?? ?? f9 ff e8 ?? ?? f9 ff 68 ?? ?? 46 00 8d 95 e4 fd ff ff 33 c0 e8 ?? ?? f9 ff 8b 85 e4 fd ff ff 8d 95 e8 fd ff ff e8 ?? ?? f9 ff ff b5 e8 fd ff ff 68 ?? ?? 46 00 8d 85 ec fd ff ff ba 03 00 00 00 e8 ?? ?? f9 ff 8b 95 ec fd ff ff 8d 85 28 fe ff ff e8 ?? ?? f9 ff e8 ?? ?? f9 ff e8 ?? ?? f9 ff 8d 85 28 fe ff ff e8 ?? ?? f9 ff e8 ?? ?? f9 ff 6a 00 68 ?? ?? 46 00 e8 ?? ?? f9 ff a1 ?? ?? 47 00 e8 ?? ?? fe ff c3}  //weight: 1, accuracy: Low
        $x_1_12 = {33 c9 51 51 51 51 51 51 51 53 8b d8 33 c0 55 68 ?? ?? 46 00 64 ff 30 64 89 20 33 d2 8b 83 24 03 00 00 e8 ?? ?? fb ff 6a ff 68 ?? ?? 46 00 8d 55 fc 33 c0 e8 ?? ?? f9 ff 8b 45 fc e8 ?? ?? f9 ff 50}  //weight: 1, accuracy: Low
        $x_1_13 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_EF_2147598155_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EF"
        threat_id = "2147598155"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "581"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 100
        $x_100_2 = "MSWINDOWSXPSP2009" ascii //weight: 100
        $x_100_3 = "Yulgang_File_Update" ascii //weight: 100
        $x_10_4 = "yb_key.dll" ascii //weight: 10
        $x_10_5 = "WriteProcessMemory" ascii //weight: 10
        $x_10_6 = "GetWindowsDirectoryA" ascii //weight: 10
        $x_10_7 = "CreateMutexA" ascii //weight: 10
        $x_10_8 = "WSAStartup" ascii //weight: 10
        $x_10_9 = "gethostbyname" ascii //weight: 10
        $x_10_10 = "htons" ascii //weight: 10
        $x_10_11 = "#32770" ascii //weight: 10
        $x_1_12 = "txtCard" ascii //weight: 1
        $x_1_13 = "&txtUser" ascii //weight: 1
        $x_1_14 = "&sys=Windows&pc=" ascii //weight: 1
        $x_1_15 = "Connection: Close" ascii //weight: 1
        $x_200_16 = {8d 45 bc ba ?? ?? 40 00 e8 ?? ?? ff ff 8b 55 bc 58 e8 ?? ?? ff ff 84 c0 0f [0-32] 8d 45 b8 e8 ?? ?? ff ff 8b 45 b8 ba ?? ?? 40 00 e8 ?? ?? ff ff 8d 45 b0 50 8d 45 ac ba ?? ?? 40 00 e8 ?? ?? ff ff 8b 45 ac b9 03 00 00 00 66 ba 82 4d e8 ?? ?? ff ff 8b 45 b0 8d 55 b4}  //weight: 200, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 3 of ($x_100_*) and 8 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_RAG_2147600584_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.RAG"
        threat_id = "2147600584"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec b9 5c 00 00 00 6a 00 6a 00 49 75 f9 53 56 57 89 45 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 33 d2 55 68 ?? ?? ?? ?? 64 ff 32 64 89 22 8d 45 e0 50 e8 ?? ?? ?? ?? ff 75 e4 ff 75 e0 e8 ?? ?? ?? ?? 8b d8 68 ff 00 00 00 8d 85 a0 fe ff ff 50 53 e8 ?? ?? ?? ?? 8d 85 9c fe ff ff 8d 95 a0 fe ff ff b9 00 01 00 00 e8 ?? ?? ?? ?? 8b 85 9c fe ff ff ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f 85 a9 0d 00 00 8d 55 f0 8b c3 e8 ?? ?? ?? ?? 8d 85 98 fe ff ff e8 ?? ?? ?? ?? 50 8b 45 f0 50 8b 00 ff 50 48 e8 ?? ?? ?? ?? 8b 95 98 fe ff ff 8d 45 f4 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 ec e8 ?? ?? ?? ?? 50 8b 45 f4 50 8b 00 ff 50 20 e8 ?? ?? ?? ?? 8d 85 94 fe ff ff e8 ?? ?? ?? ?? 50 8d 85 84 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_3 = "input" ascii //weight: 1
        $x_1_4 = "password" ascii //weight: 1
        $x_1_5 = "ielog" ascii //weight: 1
        $x_1_6 = "ResellerID" wide //weight: 1
        $x_1_7 = "ESBPassword" wide //weight: 1
        $x_1_8 = "SalerID" wide //weight: 1
        $x_1_9 = "EGRndPassword" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_ALD_2147601717_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.ALD"
        threat_id = "2147601717"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 5
        $x_5_3 = "POP3 Password2" ascii //weight: 5
        $x_5_4 = "POP3 User Name: " ascii //weight: 5
        $x_5_5 = "ShellServiceObjectDelayLoad" ascii //weight: 5
        $x_5_6 = "{C145CF11-124F-3562-44AC-E685D962C63C}" ascii //weight: 5
        $x_5_7 = "Computer Information:" ascii //weight: 5
        $x_5_8 = "I am Installed" ascii //weight: 5
        $x_1_9 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 31 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_5_*) and 1 of ($x_1_*))) or
            ((8 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_EG_2147602088_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EG"
        threat_id = "2147602088"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\TEMP\\win32.dll" ascii //weight: 10
        $x_10_2 = "WriteProcessMemory" ascii //weight: 10
        $x_10_3 = "https\\shell\\open\\command" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 10
        $x_1_6 = "ActiveXUrl" ascii //weight: 1
        $x_1_7 = "ActiveXPw" ascii //weight: 1
        $x_1_8 = "Steam PW - Cracker" ascii //weight: 1
        $x_1_9 = "Game Key - Stealer" ascii //weight: 1
        $x_1_10 = "UnLimited PW - Stealer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_A_2147612963_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.A"
        threat_id = "2147612963"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ":Pass(" ascii //weight: 10
        $x_10_2 = "OutlookDecrypt" ascii //weight: 10
        $x_10_3 = "system32.exe ENABLE" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_5 = "127.0.0.1 updates.symantec.com" ascii //weight: 10
        $x_1_6 = "brian210" ascii //weight: 1
        $x_1_7 = "meyete504" ascii //weight: 1
        $x_1_8 = "84.252.148.18" ascii //weight: 1
        $x_1_9 = "ftp.nikavonejalko.co.uk" ascii //weight: 1
        $x_1_10 = "{DEDFF624-3CCB-11D9-90EE-666577660030}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_EJ_2147632249_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EJ"
        threat_id = "2147632249"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "im-cheater.steal@" ascii //weight: 1
        $x_1_2 = {73 6d 74 70 2e 79 61 6e 64 65 78 2e 72 75 [0-10] 67 72 61 62 62 65 72 20 70 61 73 73 77 6f 72 64 [0-12] 76 69 72 75 73 20 6c 6f 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_EK_2147632279_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EK"
        threat_id = "2147632279"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "email=iksr0xsp@gmail.com" ascii //weight: 10
        $x_10_2 = "email=iks.exe@hotmail.com" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = "GetKeyNameTextA" ascii //weight: 10
        $x_10_5 = "Mozilla/3.0 (compatible; Indy Library)" ascii //weight: 10
        $x_10_6 = "/envia.php" ascii //weight: 10
        $x_2_7 = "Falha na conex" ascii //weight: 2
        $x_1_8 = "subject=" ascii //weight: 1
        $x_1_9 = "message=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_2_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_EM_2147641871_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.EM"
        threat_id = "2147641871"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 83 78 ?? 00 74 ?? 8b 45 fc 83 78 ?? 00 74}  //weight: 2, accuracy: Low
        $x_2_2 = "malware" ascii //weight: 2
        $x_2_3 = "SelfDel.bat" ascii //weight: 2
        $x_2_4 = "prellerstay.co.za" ascii //weight: 2
        $x_1_5 = "wcx_ftp.ini" ascii //weight: 1
        $x_1_6 = "History.dat" ascii //weight: 1
        $x_1_7 = "sitemanager.xml" ascii //weight: 1
        $x_1_8 = "Server.Pass" ascii //weight: 1
        $x_1_9 = "addrbk.dat" ascii //weight: 1
        $x_1_10 = "signons.txt" ascii //weight: 1
        $x_1_11 = "ftplist.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Delf_BP_2147649665_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.BP"
        threat_id = "2147649665"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PK11_GetInternalKeySlot Failed!" ascii //weight: 1
        $x_4_2 = {2d 2d 2d 44 65 73 76 61 6c 69 6a 61 64 6f 72 20 76 31 2e (30|2d|39) 20 62 79 20 74 61 6b 65 64 6f 77 6e 2d 2d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_CN_2147653890_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.CN"
        threat_id = "2147653890"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Windows Live Hotmail - Windows Internet Explorer" ascii //weight: 1
        $x_1_2 = "Entre no Yahoo! - Windows Internet Explorer" ascii //weight: 1
        $x_1_3 = "Gmail: Email do Google - Windows Internet Explorer" ascii //weight: 1
        $x_1_4 = {5c 67 6d 2e 74 78 74 ?? ?? ?? ?? ?? 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 2f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4c 00 6f 00 67 00 69 00 6e 00 3f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 3d 00 6d 00 61 00 69 00 6c 00 26 00 70 00 61 00 73 00 73 00 69 00 76 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 50 61 73 73 77 64 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 45 6d 61 69 6c 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delf_CR_2147718651_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delf.CR!bit"
        threat_id = "2147718651"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d f4 8a 54 0a ff e8 ?? ?? ?? ff 8b 45 ?? 8b 55 ?? e8 ?? ?? ?? ff 8b d8 4b 85 db 7c 65 8b 45 ?? c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 ?? 5a 8b ca 99 f7 f9 89 55 ?? 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 10, accuracy: Low
        $x_10_2 = "----WebKitFormBoundaryAyFLe1eF4NAHbJq0" ascii //weight: 10
        $x_10_3 = "875fXSrdXxXfYQAL8z4dY0NdYp4P6v4GY6jrCzYHY0MdX0Hh" ascii //weight: 10
        $x_1_4 = "\\.purple\\accounts.xml" wide //weight: 1
        $x_1_5 = "\\Programms.txt" wide //weight: 1
        $x_1_6 = "\\filezilla\\recentservers.xml" wide //weight: 1
        $x_1_7 = "\\Thunderbird\\Profiles\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

