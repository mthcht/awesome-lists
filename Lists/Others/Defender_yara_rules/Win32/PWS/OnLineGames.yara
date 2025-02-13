rule PWS_Win32_OnLineGames_2147574537_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames"
        threat_id = "2147574537"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0e f3 ab 66 ab aa 59 33 c0 8d bd ?? ff ff ff 88 9d ?? ff ff ff f3 ab 66 ab c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 31 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 31 c6 05 ?? ?? ?? ?? 32}  //weight: 1, accuracy: Low
        $x_1_2 = "/data/count.asp?u=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_2147574537_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames"
        threat_id = "2147574537"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 e4 fb ff ff 50 e8 ?? ?? ff ff 68 00 02 00 00 8d 85 ec fd ff ff 50 e8 ?? ?? ff ff 68 04 01 00 00 8d 85 e8 fc ff ff 50 e8 ?? ?? ff ff 6a 05 68}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\knlExt.dll" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\Drivers\\usbKeyInit.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_2147574537_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames"
        threat_id = "2147574537"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9c fb 12 00 a4 fc 12 00 89 10 40 00 00 00 e4 77 b8 ff 12 00 95 7b 41 00 00 00 00 00 bf 7b 41 00 26 00 00 00 b8 ff 12 00 c8 7b 41 00 a4 fd 12 00 00 00 00 00 00 00 00 00 00 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 72 69 76 65 72 73 5c 75 73 62 4b 65 79 49 6e 69 74 2e 73 79 73 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\knlExt.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_BJK_2147596323_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BJK"
        threat_id = "2147596323"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetOpenUrl" ascii //weight: 1
        $x_1_2 = "CallNextHookEx" ascii //weight: 1
        $x_1_3 = "GetKeyState" ascii //weight: 1
        $x_1_4 = "SendGameData" ascii //weight: 1
        $x_1_5 = "562452F-FA36-BA4F-892A-FF5FBBAC531" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_BLP_2147596403_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BLP"
        threat_id = "2147596403"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\DFD" ascii //weight: 1
        $x_1_2 = ":Loop" ascii //weight: 1
        $x_1_3 = "del %0" ascii //weight: 1
        $x_1_4 = "SendGameData" ascii //weight: 1
        $x_1_5 = "Url%d" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\NetMeeting\\*.cfg" ascii //weight: 1
        $x_1_7 = "myhpri.dll" ascii //weight: 1
        $x_1_8 = "rsmyapm.dll" ascii //weight: 1
        $x_1_9 = "{1E32FA58-3453-FA2D-BC49-F340348ACCE1}" ascii //weight: 1
        $x_1_10 = "play.exe" ascii //weight: 1
        $x_1_11 = "soul.exe" ascii //weight: 1
        $x_1_12 = "EnHookWindow" ascii //weight: 1
        $x_1_13 = "SkipFireWall" ascii //weight: 1
        $x_1_14 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_15 = "MapVirtualKeyA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_COK_2147596476_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.COK"
        threat_id = "2147596476"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InternetRead" ascii //weight: 1
        $x_1_2 = "CallNextHookEx" ascii //weight: 1
        $x_4_3 = {78 79 32 2e 65 78 65 00 71 71 67 61 6d 65 2e 65 78 65 00 00 71 71 2e 65 78 65 00}  //weight: 4, accuracy: High
        $x_4_4 = "%s?ks=sb9&id=%s&p=%s&q=%s&lck=%s&srv=%s&js1=%s&id1=%s&dj1=%s&pc=%s" ascii //weight: 4
        $x_4_5 = {c7 45 f0 6c 69 6e 6b 50 8d 85 0c ff ff ff 50 c7 45 f4 2e 00 00 00 ff 15 ?? ?? ?? ?? 59 59 5f 5e 5b 85 c0 74 2f 8b 40 05 c7 45 ec 77 6f 72 00 25 ff ff ff 00 c7 45 f0 77 32 69 00 c7 45 f4 7a 68 75 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_B_2147596479_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.B"
        threat_id = "2147596479"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Cn911\\Explorer\\Run" ascii //weight: 1
        $x_1_2 = "RUNJUSkCE.BAT" ascii //weight: 1
        $x_1_3 = "&GamePassCard=" ascii //weight: 1
        $x_1_4 = "Money" ascii //weight: 1
        $x_1_5 = "ElementClient Window" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "InternetOpenA" ascii //weight: 1
        $x_1_8 = "scrnsave.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPD_2147597270_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPD"
        threat_id = "2147597270"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 3a 5c 66 66 31 ?? 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_10_2 = "StartHook" ascii //weight: 10
        $x_10_3 = "StopHook" ascii //weight: 10
        $x_10_4 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_5 = "SetWindowsHookExA" ascii //weight: 10
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_1_7 = "?passmem=" ascii //weight: 1
        $x_1_8 = "&binfile=" ascii //weight: 1
        $x_1_9 = "&bindata=" ascii //weight: 1
        $x_1_10 = "F:\\work\\ff11" ascii //weight: 1
        $x_1_11 = "\\iuoiuo\\sysutils.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_E_2147597426_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.E"
        threat_id = "2147597426"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "Woool.dat" ascii //weight: 1
        $x_1_3 = "WL.DLL" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\swchost.exe" ascii //weight: 1
        $x_1_5 = "IGW.exe" ascii //weight: 1
        $x_1_6 = "kav.X" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_E_2147597427_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.E"
        threat_id = "2147597427"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "g_UserPwdAddr:" ascii //weight: 1
        $x_1_4 = "LibMBEIV" ascii //weight: 1
        $x_1_5 = "WL.DLL" ascii //weight: 1
        $x_1_6 = "avpcc.ex" ascii //weight: 1
        $x_1_7 = "antivirus.ex" ascii //weight: 1
        $x_1_8 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPF_2147597470_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPF"
        threat_id = "2147597470"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winchat32.dll" ascii //weight: 10
        $x_10_2 = {00 4a 75 6d 70 4f 6e}  //weight: 10, accuracy: High
        $x_10_3 = "OpenProcess" ascii //weight: 10
        $x_10_4 = "HM_POSTWOWDLL" ascii //weight: 10
        $x_1_5 = "HM_POSTWINDOWDLL" ascii //weight: 1
        $x_1_6 = "HM_POSTWINDOWEXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPG_2147597471_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPG"
        threat_id = "2147597471"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "msplay32.dll" ascii //weight: 10
        $x_10_2 = "OpenProcess" ascii //weight: 10
        $x_10_3 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_4 = {00 4a 75 6d 70 4f 6e}  //weight: 1, accuracy: High
        $x_1_5 = {00 4a 75 6d 70 4f 66 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_G_2147597740_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.G"
        threat_id = "2147597740"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kill.sys" ascii //weight: 1
        $x_1_2 = "group.ini" ascii //weight: 1
        $x_1_3 = "csrss.exe" ascii //weight: 1
        $x_1_4 = "mir1.dat" ascii //weight: 1
        $x_1_5 = "WriteFile" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_10_7 = {55 8b ec 8b 45 0c 53 83 f8 01 0f 85 b9 01 00 00 90 8b d2 8b c0 90 8b d2 90 8b db 90 8b c9 90 90 8b d2 8b c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_G_2147597742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.G"
        threat_id = "2147597742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "addr%shelp" ascii //weight: 1
        $x_1_2 = "qdshm.dll" ascii //weight: 1
        $x_1_3 = "UuidCreate" ascii //weight: 1
        $x_1_4 = "WSCWriteProviderOrder" ascii //weight: 1
        $x_10_5 = {55 8b ec 81 ec 3c 06 00 00 53 90 8b d2 8b c0 90 8b d2 90 8b db 90 8b c9 90 90 8b d2 8b c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPJ_2147598029_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPJ"
        threat_id = "2147598029"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetOpenA" ascii //weight: 10
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_3 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_4 = {00 73 74 72 72 63 68 72}  //weight: 10, accuracy: High
        $x_1_5 = {00 47 61 6d 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "?a=%s&s=%s&u=%s&p=%s&pin=%s&r=%s&l=%s&m=%s" ascii //weight: 1
        $x_1_7 = "TianLongBaBu" ascii //weight: 1
        $x_1_8 = {00 48 4f 4f 4b 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPJ_2147598029_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPJ"
        threat_id = "2147598029"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "strrchr" ascii //weight: 10
        $x_10_2 = "ReadProcessMemory" ascii //weight: 10
        $x_10_3 = "InternetOpenA" ascii //weight: 10
        $x_10_4 = "SetWindowsHookExA" ascii //weight: 10
        $x_5_5 = {52 61 76 4d c7 45 ?? 6f 6e 2e 65 c7 45 ?? 78 65 00 00}  //weight: 5, accuracy: Low
        $x_3_6 = {67 61 6d 65 ?? c7 45 ?? 63 6c 69 65 ff 75 ?? c7 45 ?? 6e 74 2e 65 c7 45 ?? 78 65 00 00}  //weight: 3, accuracy: Low
        $x_3_7 = {63 61 62 61 ?? c7 45 ?? 6c 6d 61 69 ff 75 ?? c7 45 ?? 6e 2e 65 78 c7 45 ?? 65 00 00 00}  //weight: 3, accuracy: Low
        $x_3_8 = {41 75 74 6f ?? c7 45 ?? 4c 6f 67 69 c7 45 ?? 6e 2e 64 61 c7 45 ?? 74 00 00 00 c7 45 ?? 72 62 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPK_2147598036_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPK"
        threat_id = "2147598036"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "122"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "strrchr" ascii //weight: 20
        $x_20_2 = "CreateToolhelp32Snapshot" ascii //weight: 20
        $x_20_3 = {8d bd d4 fd ff ff 83 c9 ff 33 c0 8d 95 cc fb ff ff f2 ae f7 d1 2b f9 6a 2e 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 8d cc fb ff ff 51 ff 15 ?? ?? ?? 00 c6 40 01 00}  //weight: 20, accuracy: Low
        $x_20_4 = "Sleep" ascii //weight: 20
        $x_20_5 = "WriteFile" ascii //weight: 20
        $x_20_6 = "WinExec" ascii //weight: 20
        $x_1_7 = {90 90 90 8b c9 90}  //weight: 1, accuracy: High
        $x_1_8 = {90 8b c9 8b d2 90}  //weight: 1, accuracy: High
        $x_1_9 = {90 8b d2 8b d2 90}  //weight: 1, accuracy: High
        $x_1_10 = {90 90 8b d2 90 90}  //weight: 1, accuracy: High
        $x_1_11 = {40 00 ff 15 ?? ?? ?? 00 90 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_12 = {6a 00 ff 15 ?? ?? ?? 00 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_13 = {57 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_14 = {90 8b c9 90 8b c9 90}  //weight: 1, accuracy: High
        $x_1_15 = {8b d2 8b d2 8b d2 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPL_2147598228_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPL"
        threat_id = "2147598228"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 61 76 70 2e 65 78 65}  //weight: 10, accuracy: High
        $x_1_2 = "JumpOn" ascii //weight: 1
        $x_1_3 = "ThreadPro" ascii //weight: 1
        $x_1_4 = "game.exe" ascii //weight: 1
        $x_10_5 = "Huai_Huai" ascii //weight: 10
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_8 = "OpenProcessToken" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "OpenProcess" ascii //weight: 1
        $x_1_12 = "CreateRemoteThread" ascii //weight: 1
        $x_1_13 = "InternetOpenA" ascii //weight: 1
        $x_1_14 = "HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPM_2147598229_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPM"
        threat_id = "2147598229"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "map\\88X600.nmp" ascii //weight: 10
        $x_10_2 = "/c del C:\\" ascii //weight: 10
        $x_10_3 = {00 57 69 6e 53 79 73 57 00}  //weight: 10, accuracy: High
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_5 = "WL.DLL" ascii //weight: 10
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "CreateRemoteThread" ascii //weight: 1
        $x_1_8 = "OpenProcess" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "OpenProcessToken" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPN_2147598231_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPN"
        threat_id = "2147598231"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 85 db 74 ?? 68 ?? ?? ?? 00 53 e8 ?? ?? ff ff 89 c6 68 ?? ?? ?? 00 53 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = {4e 76 53 79 73 5f (30|2d|39) (30|2d|39) 2e 54 61 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 76 53 79 73 5f (30|2d|39) (30|2d|39) 2e 53 79 73}  //weight: 1, accuracy: Low
        $x_1_4 = "MsgHookOp" ascii //weight: 1
        $x_1_5 = "MsgHookif" ascii //weight: 1
        $x_1_6 = {4e 76 57 69 6e 5f (30|2d|39) 2e 4c 73 74}  //weight: 1, accuracy: Low
        $x_1_7 = {4e 76 57 69 6e 5f (30|2d|39) 2e 4a 6d 70}  //weight: 1, accuracy: Low
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_9 = "DeleteFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPS_2147598287_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPS"
        threat_id = "2147598287"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ElementClient.exe" ascii //weight: 1
        $x_1_2 = "CurrentServerAddress" ascii //weight: 1
        $x_1_3 = "userdata\\currentserver.ini" ascii //weight: 1
        $x_1_4 = "CRACKING" ascii //weight: 1
        $x_1_5 = "%s?action=getpos&u=%s" ascii //weight: 1
        $x_1_6 = "%s?action=postmb&u=%s&mb=%s" ascii //weight: 1
        $x_1_7 = "?s=%s&u=%s&p=%s&pin=%s&r=%s&l=%s&m=%s&mb=%s" ascii //weight: 1
        $x_1_8 = "confirm" ascii //weight: 1
        $x_1_9 = "mibao.asp" ascii //weight: 1
        $x_1_10 = "HOOK.dll" ascii //weight: 1
        $x_1_11 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPH_2147598465_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPH"
        threat_id = "2147598465"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "avp.exe" ascii //weight: 1
        $x_1_2 = "wow.exe" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "OpenProcess" ascii //weight: 1
        $x_3_5 = {55 8b ec 81 ec ?? ?? 00 00 53 8b d2 8b c0 90 8b d2 90 8b db 90}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_J_2147598504_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.J!dll"
        threat_id = "2147598504"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3f 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 3d 25 64 26 73 70 3d 25 73 00 00 6c 69 76 65 75 70 64 61 74 65 2e 65}  //weight: 1, accuracy: High
        $x_1_2 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_3 = "dll.dat" ascii //weight: 1
        $x_1_4 = "qqffo.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPL_2147598561_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPL!dr"
        threat_id = "2147598561"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "108"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "JumpOn" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "WriteFile" ascii //weight: 1
        $x_1_5 = "FindWindow" ascii //weight: 1
        $x_1_6 = "GetKeyboardType" ascii //weight: 1
        $x_1_7 = "HMXIEBJC" ascii //weight: 1
        $x_1_8 = "HM_TCLWOWSJ_INFO" ascii //weight: 1
        $x_100_9 = {0b 00 00 00 77 73 6d 73 63 7a 78 2e 64 6c 6c 00 48 4d 5f 4d 45 53 53 57 4f 57 41 47 45 57 5a 48 55 5a 48 55 57 44 4c 4c 00 00 00 00 48 4d 5f 4d 45 53 53 57 4f 57 5a 48 55 5a 48 55 44 4c 4c 00 ff ff ff ff 32 00 00 00}  //weight: 100, accuracy: High
        $x_1_10 = "HM_TCLDAOJIANSJ_INFO" ascii //weight: 1
        $x_100_11 = {0b 00 00 00 67 64 64 6a 69 33 32 2e 64 6c 6c 00 48 4d 5f 4d 45 53 53 44 41 4f 4a 41 47 45 57 4c 49 55 4c 49 55 57 44 4c 4c 00 00 00 48 4d 5f 4d 45 53 53 44 41 4f 4a 4c 49 55 4c 49 55 44 4c 4c 00 00 00 00 ff ff ff ff 32 00 00 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 8 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPT_2147598638_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPT"
        threat_id = "2147598638"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 c7 45 ?? 3a 2f 2f 77 c7 45 ?? 77 77 2e 6e c7 45 ?? 69 75 64 76 c7 45 ?? 64 2e 63 6f c7 45 ?? 6d 2f 78 69 c7 45 ?? 6e 70 6f 74 c7 45 ?? 69 61 6e 2f c7 45 ?? 6c 69 6e 2e c7 45 ?? 61 73 70 3f c7 45 ?? 61 63 3d 31 c7 45 ?? 26 61 3d 25 c7 45 ?? 73 26 73 3d}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "InternetOpenA" ascii //weight: 1
        $x_1_4 = "strrchr" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPV_2147598700_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPV"
        threat_id = "2147598700"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "OpenProcess" ascii //weight: 10
        $x_10_3 = "WriteFile" ascii //weight: 10
        $x_1_4 = {00 4a 75 6d 70 4f 6e}  //weight: 1, accuracy: High
        $x_1_5 = {00 4a 75 6d 70 4f 66 66}  //weight: 1, accuracy: High
        $x_1_6 = "HM_TCLWOWSJ_INFO" ascii //weight: 1
        $x_1_7 = "HM_MESSWOWAGEWZHUZHUWDLL" ascii //weight: 1
        $x_1_8 = "HM_MESSWOWZHUZHUDLL" ascii //weight: 1
        $x_1_9 = "asvliuliu32.dll" ascii //weight: 1
        $x_1_10 = "wsdgcax.exe" ascii //weight: 1
        $x_1_11 = "wsmscax.exe" ascii //weight: 1
        $x_1_12 = "gdmsi32.dll" ascii //weight: 1
        $x_1_13 = "wsmsczx.dll" ascii //weight: 1
        $x_1_14 = "asvzhuzhu32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPW_2147598701_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPW"
        threat_id = "2147598701"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vb6chs.dll" ascii //weight: 10
        $x_10_2 = ".vbp" ascii //weight: 10
        $x_10_3 = "Recycled.exe" ascii //weight: 10
        $x_10_4 = "msvci.exe" ascii //weight: 10
        $x_10_5 = "Gavps" ascii //weight: 10
        $x_10_6 = "FindWindowA" ascii //weight: 10
        $x_10_7 = "SetWindowLongA" ascii //weight: 10
        $x_1_8 = {63 68 61 74 72 72 00 00 74 6f 61 74 72 72 00 00 64 65 6c 66 69 6c 65 00 63 6f 70 79}  //weight: 1, accuracy: High
        $x_1_9 = "legend of mir2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPX_2147598748_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPX"
        threat_id = "2147598748"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "122"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "strrchr" ascii //weight: 20
        $x_20_2 = "CreateToolhelp32Snapshot" ascii //weight: 20
        $x_20_3 = {8d bd e0 fe ff ff 83 c9 ff 33 c0 8d 95 d8 fc ff ff f2 ae f7 d1 2b f9 6a 2e 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 8d d8 fc ff ff 51 ff 15 ?? ?? ?? 00 c6 40 01 00}  //weight: 20, accuracy: Low
        $x_20_4 = "Sleep" ascii //weight: 20
        $x_20_5 = "WriteFile" ascii //weight: 20
        $x_20_6 = "WinExec" ascii //weight: 20
        $x_1_7 = {90 90 90 8b c9 90}  //weight: 1, accuracy: High
        $x_1_8 = {90 8b c9 8b d2 90}  //weight: 1, accuracy: High
        $x_1_9 = {90 8b d2 8b d2 90}  //weight: 1, accuracy: High
        $x_1_10 = {90 90 8b d2 90 90}  //weight: 1, accuracy: High
        $x_1_11 = {40 00 ff 15 ?? ?? ?? 00 90 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_12 = {6a 00 ff 15 ?? ?? ?? 00 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_13 = {57 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_14 = {90 8b c9 90 8b c9 90}  //weight: 1, accuracy: High
        $x_1_15 = {8b d2 8b d2 8b d2 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPY_2147598749_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPY"
        threat_id = "2147598749"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 4a 75 6d 70 4f 6e}  //weight: 10, accuracy: High
        $x_10_2 = {00 4a 75 6d 70 4f 66 66}  //weight: 10, accuracy: High
        $x_10_3 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_2_4 = "HM_TCLDAOJIANSJ_INFO" ascii //weight: 2
        $x_2_5 = "HM_MESSAGEDAOJIANDLL" ascii //weight: 2
        $x_2_6 = "HM_MESSDAOJIANDLL" ascii //weight: 2
        $x_1_7 = "mshmdj32.dll" ascii //weight: 1
        $x_1_8 = "avdaojian32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CPZ_2147598843_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPZ"
        threat_id = "2147598843"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "openprocess" ascii //weight: 10
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_3 = {00 77 6f 6f 6f 6c}  //weight: 10, accuracy: High
        $x_10_4 = "mir1.dat" ascii //weight: 10
        $x_1_5 = "mm.dll" ascii //weight: 1
        $x_1_6 = "mir.exe" ascii //weight: 1
        $n_40_7 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4a 00 41 00 56 00 41 00 7b 76 46 96 68 56 00}  //weight: -40, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CQC_2147599226_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CQC"
        threat_id = "2147599226"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_2 = "addr%shelp" ascii //weight: 1
        $x_1_3 = {00 67 61 6d 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "qdshm.dll" ascii //weight: 1
        $x_2_5 = {b0 65 c6 45 ?? 61 88 45 ?? 88 45 ?? 8d 45 ?? c6 45 ?? 76 50 c6 45 ?? 70 c6 45 ?? 2e c6 45 ?? 78 c6 45 ?? 00}  //weight: 2, accuracy: Low
        $x_2_6 = {03 2f c6 45 ?? 63 c6 45 ?? 64 c6 45 ?? 65 c6 45 ?? 6c}  //weight: 2, accuracy: Low
        $x_1_7 = {8b d2 90 8b d2 90 8b d2 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CQD_2147599257_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CQD"
        threat_id = "2147599257"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "urldownloadtofilea" ascii //weight: 10
        $x_3_3 = {00 77 6f 6f 6f 6c}  //weight: 3, accuracy: High
        $x_2_4 = "wow.exe" ascii //weight: 2
        $x_1_5 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_6 = "avpcc.ex" ascii //weight: 1
        $x_1_7 = "_avpm.ex" ascii //weight: 1
        $x_1_8 = "avp32.ex" ascii //weight: 1
        $x_1_9 = "norton.e" ascii //weight: 1
        $n_20_10 = "Heuristics engine" wide //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CQE_2147599280_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CQE"
        threat_id = "2147599280"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 4d 4d 2e 44 4c 4c}  //weight: 10, accuracy: High
        $x_10_2 = {00 4d 2e 65 78 65}  //weight: 10, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "/c del" ascii //weight: 1
        $x_1_5 = ".nmp" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = "OpenProcess" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CQI_2147599306_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CQI"
        threat_id = "2147599306"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "CreateToolhelp32Snapshot" ascii //weight: 20
        $x_2_2 = "HM_TCLWOW" ascii //weight: 2
        $x_2_3 = "HM_MESSWOW" ascii //weight: 2
        $x_2_4 = {00 4a 75 6d 70 4f 6e}  //weight: 2, accuracy: High
        $x_2_5 = {00 4a 75 6d 70 4f 66 66}  //weight: 2, accuracy: High
        $x_1_6 = "Explorer.exe" ascii //weight: 1
        $x_1_7 = "asvzhuzhu32.dll" ascii //weight: 1
        $x_1_8 = "gdmsi32.dll" ascii //weight: 1
        $x_1_9 = "FTCCompress.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_K_2147599980_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.K"
        threat_id = "2147599980"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "InternetShortcut" ascii //weight: 1
        $x_1_3 = "Der Herr der Ringe Online" ascii //weight: 1
        $x_1_4 = "The Lord of the Rings Online" ascii //weight: 1
        $x_1_5 = "WindowsForms10.SysListView32.app" ascii //weight: 1
        $x_1_6 = "WindowsForms10.EDIT.app" ascii //weight: 1
        $x_1_7 = "launcher1.url" ascii //weight: 1
        $x_1_8 = "secretQuestionAnswer" ascii //weight: 1
        $x_1_9 = "accountName" ascii //weight: 1
        $x_1_10 = "password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CRP_2147600329_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CRP"
        threat_id = "2147600329"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff ff 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? 00 8d 8d ?? ?? ff ff 6a 5c 51 ff 15 ?? ?? ?? 00 83 c4 08 8b d8}  //weight: 10, accuracy: Low
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_3 = "InternetOpenA" ascii //weight: 1
        $x_1_4 = "DownloadNetFile" ascii //weight: 1
        $x_1_5 = "URLDownloadToCacheFileA" ascii //weight: 1
        $x_1_6 = "#32770" ascii //weight: 1
        $x_1_7 = {39 39 39 39 39 39 39 00}  //weight: 1, accuracy: High
        $x_1_8 = "dllcache\\explorer.exe" ascii //weight: 1
        $x_1_9 = "dllcache\\conime.exe" ascii //weight: 1
        $x_1_10 = "dllcache\\ctfmon.exe" ascii //weight: 1
        $x_1_11 = "dllcache\\internat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CRQ_2147600442_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CRQ!sys"
        threat_id = "2147600442"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GameHack\\RegDriver\\objfre\\i386\\Reg.pdb" ascii //weight: 2
        $x_2_2 = "\\DosDevices\\c:\\name.log" wide //weight: 2
        $x_2_3 = "gnaixnauhqq.dll" ascii //weight: 2
        $x_2_4 = "niluw.dll" ascii //weight: 2
        $x_2_5 = "naixuhz.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_CRS_2147600473_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CRS!sys"
        threat_id = "2147600473"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_2_2 = "GameHack\\HookDllDriver\\objfre\\i386\\hookdll.pdb" ascii //weight: 2
        $x_2_3 = {00 67 6e 61 69 78 6e 61 75 68 71 71 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 6e 61 69 78 75 68 7a 00}  //weight: 2, accuracy: High
        $x_1_5 = {00 6e 69 6c 75 77 00}  //weight: 1, accuracy: High
        $x_2_6 = {8b c0 8b c0 8b c0 8b c0 90 90 90 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CRT_2147600475_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CRT!sys"
        threat_id = "2147600475"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GameHack\\Driver\\bin\\i386\\mssock.pdb" ascii //weight: 2
        $x_2_2 = "\\??\\maspi" wide //weight: 2
        $x_2_3 = "IoDeleteDevice" ascii //weight: 2
        $x_2_4 = {8b c0 8b c0 8b c0 90 90 90 90}  //weight: 2, accuracy: High
        $x_1_5 = "\\Device\\KeyboardClass0" wide //weight: 1
        $x_1_6 = "\\Device\\maspi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CRZ_2147600538_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CRZ"
        threat_id = "2147600538"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 a1 ?? ?? ?? 00 50 6a 00 b9 ?? ?? ?? 00 ba ?? ?? ?? 00 33 c0 e8 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
        $x_10_2 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_3 = "MsgHookOn" ascii //weight: 10
        $x_1_4 = {6c 6f 72 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 2e 45 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "DE6CBE17-8690-487F-AA5D-B6B8C93EE38A" ascii //weight: 1
        $x_1_7 = "=zhengdaqian=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CRU_2147600652_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CRU!sys"
        threat_id = "2147600652"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec b0 01 00 00 80 65 f0 00 80 65 e0 00 80 65 ff 00 53 56 be ?? ?? ?? ?? 57 c6 45 e4 69 c6 45 e5 65 c6 45 e6 78 c6 45 e7 70 c6 45 e8 6c c6 45 e9 6f c6 45 ea 72 c6 45 eb 65 c6 45 ec 2e c6 45 ed 65 c6 45 ee 78 c6 45 ef 65 c6 45 d4 65 c6 45 d5 78 c6 45 d6 70 c6 45 d7 6c c6 45 d8 6f c6 45 d9 72 c6 45 da 65 c6 45 db 72 c6 45 dc 2e c6 45 dd 65 c6 45 de 78 c6 45 df 65 c6 45 f4 73 c6 45 f5 76 c6 45 f6 63 c6 45 f7 68 c6 45 f8 6f c6 45 f9 73 c6 45 fa 74 c6 45 fb 2e c6 45 fc 65 c6 45 fd 78 c6 45 fe 65 89 b5 50 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "MmMapLockedPagesSpecifyCache" ascii //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "ObfDereferenceObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CPA_2147600658_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CPA!sys"
        threat_id = "2147600658"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ZwCreateFile" ascii //weight: 10
        $x_10_2 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" wide //weight: 10
        $x_10_3 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\" wide //weight: 10
        $x_10_4 = "GameHack\\RegDriver\\objfre\\i386\\Reg.pdb" ascii //weight: 10
        $x_10_5 = "\\DosDevices\\c:\\name.log" wide //weight: 10
        $x_1_6 = "atgnehz.dll" ascii //weight: 1
        $x_1_7 = "bauhgnem.dll" ascii //weight: 1
        $x_1_8 = "duygnef.dll" ascii //weight: 1
        $x_1_9 = "ijougiemnaw.dll" ascii //weight: 1
        $x_1_10 = "iqaixnaij.dll" ascii //weight: 1
        $x_1_11 = "taijoad.dll" ascii //weight: 1
        $x_1_12 = "sauhad.dll" ascii //weight: 1
        $x_1_13 = "jemnaw.dll" ascii //weight: 1
        $x_1_14 = "nadgnohiac.dll" ascii //weight: 1
        $x_1_15 = "gnolnait.dll" ascii //weight: 1
        $x_1_16 = "qlihzouhgnfe.dll" ascii //weight: 1
        $x_1_17 = "utiemnaw.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 12 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BD_2147600954_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BD"
        threat_id = "2147600954"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 45 ec c7 45 ec 47 61 6d 65 c7 45 f0 2e 65 78 65 89 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d4 7b 32 43 42 c7 45 d8 37 37 37 34 c7 45 dc 36 2d 38 45 c7 45 e0 43 43 2d 34 c7 45 e4 30 63 61 2d c7 45 e8 38 32 31 37 c7 45 ec 2d 31 30 43 c7 45 f0 41 38 42 45 c7 45 f4 35 45 46 43 c7 45 f8 38 7d 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 88 6e 5c 45 78 c7 45 8c 70 6c 6f 72 c7 45 90 65 72 5c 53 c7 45 94 68 65 6c 6c c7 45 98 45 78 65 63 c7 45 9c 75 74 65 48 c7 45 a0 6f 6f 6b 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_BE_2147600956_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BE"
        threat_id = "2147600956"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "123"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sfc_os.dll" ascii //weight: 10
        $x_10_2 = "srpcss.dll" ascii //weight: 10
        $x_10_3 = "gdipro.dll" ascii //weight: 10
        $x_10_4 = "svchost.exe" ascii //weight: 10
        $x_10_5 = "csrss.exeMutex" ascii //weight: 10
        $x_10_6 = "csrss.exeEvent" ascii //weight: 10
        $x_10_7 = "%s%02x*.dll" ascii //weight: 10
        $x_10_8 = "ServiceDll" ascii //weight: 10
        $x_10_9 = "WhichService" ascii //weight: 10
        $x_10_10 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 10
        $x_10_11 = "212.103.11.59" ascii //weight: 10
        $x_10_12 = "\\drivers\\etc\\hosts" ascii //weight: 10
        $x_1_13 = "passport.wanmei.com" ascii //weight: 1
        $x_1_14 = "reg.163.com" ascii //weight: 1
        $x_1_15 = "account.ztgame.com" ascii //weight: 1
        $x_1_16 = "sde.game.sohu.com" ascii //weight: 1
        $x_1_17 = "a=&c=%s&e=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BG_2147600960_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BG"
        threat_id = "2147600960"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 18 56 6a 32 6a 01 ff ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 2f 57 ff 15 ?? ?? ?? ?? 40 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 32}  //weight: 1, accuracy: Low
        $x_1_3 = "%s%s%s" ascii //weight: 1
        $x_1_4 = "mibao.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_BG_2147600960_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BG"
        threat_id = "2147600960"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc e8 ?? ?? ff ff 8b 55 fc 8a 54 1a ff 80 ea ?? 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {be 65 00 00 00 6a 0a e8 ?? ?? ff ff 6a 00 6a 00 6a 00 6a 08 e8 ?? ?? ff ff 6a 00 6a 02 6a 00 6a 08 e8 ?? ?? ff ff 4e 75 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fb c8 00 00 00 7e 07 6a 00 e8 ?? ?? ?? ?? 6a 64 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 0a ?? ?? ?? ?? ?? ?? ?? ?? 75 03 43 eb ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_BH_2147600962_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BH"
        threat_id = "2147600962"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 70 6f 73 74 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "&account=%s" ascii //weight: 1
        $x_1_3 = "&password" ascii //weight: 1
        $x_1_4 = "&level" ascii //weight: 1
        $x_1_5 = "server=%s" ascii //weight: 1
        $x_5_6 = {74 18 56 6a 32 6a 78 30 31 ff 75 08}  //weight: 5, accuracy: High
        $x_5_7 = {80 3d d5 4f 55 00 85 0f 85}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BI_2147600964_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BI"
        threat_id = "2147600964"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "server=%s&account=%s&password1=%s" ascii //weight: 1
        $x_1_2 = "&levels=%s&cash=%s&name=%s&specialSign=%s&" ascii //weight: 1
        $x_1_3 = "&ProtPass=%s&Verify=%s" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 70 6f 73 74 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_5 = "?act=getpos&account=%s" ascii //weight: 1
        $x_1_6 = "\\userdata\\currentserver.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_BJ_2147600966_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BJ"
        threat_id = "2147600966"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 07 61 c6 47 ?? 63 c6 47 ?? 74 c6 47 ?? 3d c6 47 ?? 67 c6 47 ?? 65 c6 47 ?? 74 c6 47 ?? 70 c6 47 ?? 6f c6 47 ?? 73 c6 47 ?? 26}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 42 aa b0 6f aa b0 2e aa b0 65 aa b0 78 aa b0 65}  //weight: 1, accuracy: High
        $x_1_3 = {b0 6d aa b0 69 aa b0 62 aa b0 61 aa b0 6f aa b0 2e aa b0 61 aa b0 73 aa b0 70}  //weight: 1, accuracy: High
        $x_1_4 = {b0 75 aa b0 6e aa b0 74 aa b0 3d aa b0 25 aa b0 73}  //weight: 1, accuracy: High
        $x_1_5 = {b0 2d aa b0 31 aa b0 32 aa aa b0 37 aa b0 2d aa b0 4e aa b0 45 aa b0 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_BK_2147601014_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BK"
        threat_id = "2147601014"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 00 80 ff ?? ?? ff 15 ?? ?? ?? ?? 8b f8 83 ff ff 74 ?? 90 90 90 90 [0-8] 8d ?? ?? 56 50 ff ?? ?? ff ?? ?? 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-16] 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 73 3f 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_BM_2147601018_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BM"
        threat_id = "2147601018"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 75 73 2f 66 66 78 69 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6d 73 67 2e 76 38 64 63 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 64 64 72 3d 52 75 61 6e 50 61 73 73 26 67 61 6d 65 3d 46 46 49 58 26 61 63 74 69 6f 6e 3d 65 72 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 41 56 45 4f 4b 00 00 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 67 61 6d 65 3d 25 73 26 73 65 72 3d 25 73 26 61 63 74 69 6f 6e 3d 75 73 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_CSB_2147601079_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSB"
        threat_id = "2147601079"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 26 8d 94 24 ?? ?? 00 00 68 04 01 00 00 52 ff d6 6a 00 ff d7 8b 44 24 ?? 50 6a 00 68 ff 0f 1f 00 ff d3 6a 00 50 ff d5 8d 4c 24 ?? 68 ?? ?? ?? 00 51 ff 15 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_2_3 = {00 61 76 70 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_4 = "360Safe.exe" ascii //weight: 1
        $x_1_5 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_6 = "del \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CSD_2147601143_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSD"
        threat_id = "2147601143"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?account=%s&pass=%s&sever=%s&name=%s&level=%s&work=%s&gold=%d" ascii //weight: 1
        $x_1_2 = "YB_OnlineClient" ascii //weight: 1
        $x_1_3 = "ResourceUpdata.exe" ascii //weight: 1
        $x_1_4 = "SendServer" ascii //weight: 1
        $x_2_5 = "\\\\.\\mssock" ascii //weight: 2
        $x_2_6 = "\\\\.\\MsAudio" ascii //weight: 2
        $x_100_7 = {8b 44 24 10 6a 00 6a 00 6a 00 6a 00 6a 00 50 6a 01 6a 03 6a 01 68 ff 01 0f 00 57 57 56 ff 15 ?? ?? 00 10 85 c0 75 0c 56 ff 15 ?? ?? 00 10 5f 32 c0 5e c3}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_L_2147601265_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.L!dll"
        threat_id = "2147601265"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f3 85 f6 7e 1e bf 01 00 00 00 8b 5d ?? 8b 45 ?? e8 ?? ?? ?? ?? 8a 13 80 f2 ?? 88 54 38 ff 47 43 4e 75 ea 8b 7d ?? 8b 75 ?? 8b 5d ?? 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_4 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_5 = {31 2e 68 69 76 04 00 43 3a 5c}  //weight: 1, accuracy: Low
        $x_1_6 = {00 48 6f 6f 6b 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BY_2147601401_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BY"
        threat_id = "2147601401"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 69 76 78 44 65 63 6f 64 65 72 2e 55 6e 49 6e 69 74 69 61 6c 69 7a 65 44 69 76 78 44 65 63 6f 64 65 72 00 66 74 73 57 6f 72 64 42 72 65 61 6b}  //weight: 2, accuracy: High
        $x_2_2 = "v1.9.6.5" ascii //weight: 2
        $x_2_3 = {48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e 00}  //weight: 2, accuracy: High
        $x_2_4 = "cqsjqwerty" ascii //weight: 2
        $x_1_5 = {6a 00 50 68 14 01 00 00 68 ?? ?? 00 10 53 ff 15 ?? ?? 00 10 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {77 73 61 73 79 73 74 65 6d 2e 67 69 66 00 00 00 44 61 74 61 5c 4c 50 4b 2e 64 6c 6c 00 00 00 00 44 61 74 61 5c 77 6f 6f 6f 6c 69 6e 69 74 2e 64 61 74 00 00 44 61 74 61 5c 77 6f 6f 6f 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_7 = "SOFTWARE\\snda\\Woool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BX_2147601403_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BX"
        threat_id = "2147601403"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 3
        $x_3_2 = {00 72 6f 2e 64 6c 6c 00 00 57 53 50 53 74 61 72 74 75 70}  //weight: 3, accuracy: High
        $x_3_3 = {75 73 65 72 3a [0-11] 70 61 73 73 77 6f 72 64 3a [0-11] 62 61 6e 6b 70 61 73 73 3a}  //weight: 3, accuracy: Low
        $x_2_4 = "Proxy-Connection: " ascii //weight: 2
        $x_2_5 = "my_game.bat" ascii //weight: 2
        $x_1_6 = {4d 61 70 6c 65 53 74 6f 72 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {52 61 67 46 72 65 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {5a 6f 64 69 61 63 4f 6e 6c 69 6e 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = "MapleStory sever" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CSF_2147601439_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSF"
        threat_id = "2147601439"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 08 56 80 20 00 33 f6 8b 4c 24 08 8a 0c 0e 80 f9 30 7c 11 80 f9 39 7f 0c 8a 10 80 c2 0d c0 e2 04 02 d1 eb 14 80 f9 41 7c 17 80 f9 46 7f 12 8a 10 c0 e2 04 02 d1 80 ea 37 46 88 10 83 fe 02 7c c7 5e c3}  //weight: 10, accuracy: High
        $x_2_2 = "\\Config\\*.HeiMingDan.txt" ascii //weight: 2
        $x_1_3 = "legend of mir" ascii //weight: 1
        $x_2_4 = "Mir2Banana" ascii //weight: 2
        $x_2_5 = "%s?RE=%s&S=%s&A=%s&P=%s&R=%s&RG=%s&RJ=%s&E=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BZ_2147601449_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BZ!dll"
        threat_id = "2147601449"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 70 6f 73 74 6c 79 2e 41 73 70 [0-2] 25 73 3a 25 73 00 00 00 46 6f 72 74 68 67 6f 6e 65 72 00 00 25 73 3f 73 65 72 76 65 72 3d 25 73 26 67 61 6d 65 69 64 3d 25 73 26 70 61 73 73 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 70 6f 73 74 6c 79 2e 61 73 70 00 00 ?? ?? ?? ?? 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 7a 6b 64 35 32 30 2e 63 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {50 43 49 4b 20 2d 20 50 61 74 63 68 20 43 6c 69 65 6e 74 00 68 74 74 70 3a 2f 2f 70 61 74 63 68 2e 70 63 69 6b 63 68 69 6e 61 2e 63 6f 6d 2f 70 61 74 63 68 69 6e 66 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_M_2147601476_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.M!dll"
        threat_id = "2147601476"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: High
        $x_10_2 = {83 f9 08 75 18 b9 02 00 00 00 bf ?? ?? ?? ?? 33 c0 f3 a7 75 08 c7 44 24 3c 01 00 00 00 8b fd 83 c9 ff 33 c0 f2 ae f7 d1 49 83 f9 0b 75 32 bf ?? ?? ?? ?? 8b f5 33 c0 f3 a6 75 ?? 8b fb 83 c9 ff}  //weight: 10, accuracy: Low
        $x_10_3 = {c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 b9 41 00 00 00 8d 7c 24 0c f3 ab 8d 84 24 10 01 00 00 8d 4c 24 0c 50 68 04 01 00 00 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5f 5e 83 f8 03 5b 76 ?? 68 04 01 00 00 6a 01 6a 2e}  //weight: 10, accuracy: Low
        $x_1_4 = "password" ascii //weight: 1
        $x_1_5 = "accountName" ascii //weight: 1
        $x_1_6 = "secretQuestionAnswer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FKM_2147602358_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FKM"
        threat_id = "2147602358"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 02 00 00 8d 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 68 04 01 00 00 8d 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 6a 05 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\knlExt.dll" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\Drivers\\usbKeyInit.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DI_2147602603_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DI"
        threat_id = "2147602603"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "69"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_20_2 = "RegRestoreKeyA" ascii //weight: 20
        $x_20_3 = "SetSecurityInfo" ascii //weight: 20
        $x_1_4 = "\\iuoiuo\\sysutils.pas" ascii //weight: 1
        $x_1_5 = "c:\\6756rrty.txt" ascii //weight: 1
        $x_1_6 = "systemlf.dll" ascii //weight: 1
        $x_1_7 = "syswin.sys" ascii //weight: 1
        $x_1_8 = "StartHook" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run" ascii //weight: 1
        $x_1_10 = "_deleteme.bat" ascii //weight: 1
        $x_1_11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_12 = "io7itu7tfyt" ascii //weight: 1
        $x_1_13 = "sysgrw.exe" ascii //weight: 1
        $x_1_14 = "\\Device\\PhysicalMemory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_DI_2147602604_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DI"
        threat_id = "2147602604"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_20_2 = "Toolhelp32ReadProcessMemory" ascii //weight: 20
        $x_20_3 = "Process32Next" ascii //weight: 20
        $x_20_4 = "EnumCalendarInfoA" ascii //weight: 20
        $x_20_5 = "gethostbyname" ascii //weight: 20
        $x_1_6 = "\\iuoiuo\\sysutils.pas" ascii //weight: 1
        $x_1_7 = "c:\\xx26.txt" ascii //weight: 1
        $x_1_8 = "usr\\all\\login_w.bin" ascii //weight: 1
        $x_1_9 = "passmem:" ascii //weight: 1
        $x_1_10 = "?passmem=" ascii //weight: 1
        $x_1_11 = "&binfile=" ascii //weight: 1
        $x_1_12 = "&bindata=" ascii //weight: 1
        $x_1_13 = "&firstbin=" ascii //weight: 1
        $x_1_14 = "C:\\xxbiin.bin" ascii //weight: 1
        $x_1_15 = "6756rrtymapfile" ascii //weight: 1
        $x_1_16 = "c:\\6756rrty.txt" ascii //weight: 1
        $x_1_17 = "pol.exe" ascii //weight: 1
        $x_1_18 = "StartHook" ascii //weight: 1
        $x_1_19 = "jpff11.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_20_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CSK_2147603037_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSK"
        threat_id = "2147603037"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks]" ascii //weight: 1
        $x_1_2 = "Windows Registry Editor Version 5.00" ascii //weight: 1
        $x_1_3 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_4 = "SeRestorePrivilege" ascii //weight: 1
        $x_1_5 = "SeBackupPrivilege" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "regedit /s " ascii //weight: 1
        $x_1_8 = "\\winsys.reg" ascii //weight: 1
        $x_1_9 = "avp.exe" ascii //weight: 1
        $x_1_10 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KA_2147603341_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KA"
        threat_id = "2147603341"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.dll" ascii //weight: 1
        $x_1_2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CSN_2147604948_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSN"
        threat_id = "2147604948"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide //weight: 1
        $x_1_2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide //weight: 1
        $x_1_3 = "%SystemRoot%\\System32\\wzcsvbc.dll" wide //weight: 1
        $x_1_4 = "wow.exe" wide //weight: 1
        $x_1_5 = "SeDebugPrivilege" wide //weight: 1
        $x_1_6 = "ServiceDll" wide //weight: 1
        $x_1_7 = "ServiceMain" wide //weight: 1
        $x_1_8 = "WZCSVC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CSO_2147604949_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSO"
        threat_id = "2147604949"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IPEnableRouter" ascii //weight: 1
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" ascii //weight: 1
        $x_1_3 = {47 45 54 00 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: High
        $x_1_4 = "action=5&keyid=%s" ascii //weight: 1
        $x_1_5 = "action=4&foolip=%s" ascii //weight: 1
        $x_1_6 = "action=3&foolip=%s&asdf=%s" ascii //weight: 1
        $x_1_7 = "action=2&foolip=%s" ascii //weight: 1
        $x_1_8 = "action=1" ascii //weight: 1
        $x_1_9 = "action=0&keyid=%s&foolip=%s" ascii //weight: 1
        $x_1_10 = "POPTANG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CSS_2147605112_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSS"
        threat_id = "2147605112"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Der Herr der Ringe Online" ascii //weight: 1
        $x_1_2 = "The Lord of the Rings Online" ascii //weight: 1
        $x_1_3 = "MapleStory*.ini" ascii //weight: 1
        $x_1_4 = "SSDTShellHook.dll" ascii //weight: 1
        $x_1_5 = {50 61 73 73 00 00 00 00 41 63 63 6f 75 6e 74}  //weight: 1, accuracy: High
        $x_1_6 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_7 = "CreateThread" ascii //weight: 1
        $x_1_8 = "GetPrivateProfileStringA" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = {73 65 6e 64 00 00 00 00 77 73 32 5f 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_C_2147605160_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.C"
        threat_id = "2147605160"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\system32\\drivers\\beep.bin" ascii //weight: 5
        $x_5_2 = "KeServiceDescriptorTable" ascii //weight: 5
        $x_5_3 = "w1.bat" ascii //weight: 5
        $x_5_4 = {69 66 20 65 78 69 73 74 20 25 73 00 64 65 6c 20 25 73 20}  //weight: 5, accuracy: High
        $x_5_5 = "AppInit_DLLs" ascii //weight: 5
        $x_5_6 = {53 79 73 57 ?? ?? ?? ?? 2e 64 6c 6c 00}  //weight: 5, accuracy: Low
        $x_1_7 = "HM_MESSWOWHHHDLL" ascii //weight: 1
        $x_1_8 = "HM_MESSWMGJHCHDLL" ascii //weight: 1
        $x_1_9 = "HM_MESSW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZDF_2147605795_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDF"
        threat_id = "2147605795"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {57 c6 44 24 ?? 6f c6 44 24 ?? 7a c6 44 24 ?? 68 c6 44 24 ?? 2e c6 44 24 ?? 2e c6 44 24 ?? 6f c6 44 24 ?? 72 c6 44 24 ?? 67 c6 44 24 ?? 00}  //weight: 5, accuracy: Low
        $x_5_2 = {ff ff ff 47 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 6d 88 85 ?? ff ff ff c6 85 ?? ff ff ff 54 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 79 c6 85 ?? ff ff ff 48 c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 73}  //weight: 5, accuracy: Low
        $x_5_3 = {2e 69 6e 69 00 00 00 00 25 73 25 73 00 00 00 00 46 74 70 50 75 74 46 69 6c 65 00 00 5c 00 00 00 6d 73 70 61 69 6e 74 2e 65 78 65 00 4d 53 50 61}  //weight: 5, accuracy: High
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FKW_2147605824_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FKW"
        threat_id = "2147605824"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "realmlist.wtf" ascii //weight: 1
        $x_1_4 = ".worldofwarcraft.com" ascii //weight: 1
        $x_1_5 = ".wowchina.com" ascii //weight: 1
        $x_1_6 = "Hook.dll" ascii //weight: 1
        $x_1_7 = "ksHookwo" ascii //weight: 1
        $x_1_8 = "tzHookwo" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CST_2147605933_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CST"
        threat_id = "2147605933"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rsaenh.drsaenh.dll" ascii //weight: 1
        $x_1_2 = ".\\tenio\\tensg.DLL" ascii //weight: 1
        $x_1_3 = "liveupdate.EXE" ascii //weight: 1
        $x_1_4 = "GtSaloon.exe" ascii //weight: 1
        $x_1_5 = ".\\qqsg.exe" ascii //weight: 1
        $x_1_6 = "wow.exe" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CSU_2147605942_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSU"
        threat_id = "2147605942"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rsaenh.drsaenh.dll" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "UpdateOnline.EXE" ascii //weight: 1
        $x_1_4 = "ThingClient.dll" ascii //weight: 1
        $x_1_5 = ".\\QQLogin.exe" ascii //weight: 1
        $x_1_6 = "GtSaloon.exe" ascii //weight: 1
        $x_1_7 = "QQhxgame.exe" ascii //weight: 1
        $x_1_8 = "wow.exe" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NC_2147605943_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NC"
        threat_id = "2147605943"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fjlogin.exe" ascii //weight: 1
        $x_1_2 = "lastGameServer" ascii //weight: 1
        $x_1_3 = "lastZone" ascii //weight: 1
        $x_1_4 = "/_FJLogin.bin" ascii //weight: 1
        $x_1_5 = "ElementClient.exe" ascii //weight: 1
        $x_1_6 = "GtSaloon.exe" ascii //weight: 1
        $x_1_7 = "wow.exe" ascii //weight: 1
        $x_1_8 = "ElementClient Window" ascii //weight: 1
        $x_1_9 = "%s?a=%s&s=%s&u=%s&ac=t" ascii //weight: 1
        $x_1_10 = "rsaenh.drsaenh.dll" ascii //weight: 1
        $x_1_11 = "explore.exe4097" wide //weight: 1
        $x_1_12 = "xul.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ND_2147605945_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ND"
        threat_id = "2147605945"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GtSaloon.exe" ascii //weight: 1
        $x_1_2 = "wow.exe" ascii //weight: 1
        $x_1_3 = "Yf=okt\"f=upt" ascii //weight: 1
        $x_1_4 = "rsaenh.drsaenh.dll" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "xul.dll" wide //weight: 1
        $x_5_7 = {25 25 25 30 32 58 00 00 3b 00 00 00 43 6f 6d 6d 75 6e 69 63 61 74 65 2e 64 6c 6c 00 42 61 73 74 65 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CSV_2147606078_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CSV"
        threat_id = "2147606078"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec 84 00 00 00 56 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 3e 8d 45 fc 50 56 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 39 45 fc 75 28 8d 85 7c ff ff ff 6a 7f 50 56 ff 15 ?? ?? ?? ?? 8d 85 7c ff ff ff 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 59 85 c0 59}  //weight: 1, accuracy: Low
        $x_1_2 = "userdata\\currentserver.ini" ascii //weight: 1
        $x_1_3 = "ChiBiElementClient Window" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "ElementClient.exe" ascii //weight: 1
        $x_1_6 = "InternetReadFile" ascii //weight: 1
        $x_1_7 = "wow.exe" ascii //weight: 1
        $x_1_8 = "lastGameServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDH_2147606340_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDH"
        threat_id = "2147606340"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6c 65 6d c7 45 ?? 65 6e 74 43 c7 45 ?? 6c 69 65 6e c7 45 ?? 74 2e 65 78 c7 45 ?? 65 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 6f 77 2e ?? ?? c7 45 ?? 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 6d 70 70 c7 45 ?? 64 73 2e 64 c7 45 ?? 6c 6c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_ZDI_2147606349_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDI"
        threat_id = "2147606349"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 2e 63 c7 45 ?? 6b 38 38 38 c7 45 ?? 36 36 2e 63 c7 45 ?? 6f 6d 2f 63 c7 45 ?? 79 38 37 36 c7 45 ?? 2f 6c 69 6e c7 45 ?? 31 31 31 2e c7 45 ?? 61 73 70 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDJ_2147606635_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDJ"
        threat_id = "2147606635"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 04 08 80 f1 55 88 4c 04 08 40 3d 04 01 00 00 7c ed a1 ?? ?? 00 10 68 04 01 00 00 6a 00 05 ?? 01 00 00 6a 2c 8d 4c 24 14 50 51}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 28 50 c7 46 ?? 01 00 00 00 [0-6] 8a 4c 24 18 8a 54 24 1c 88 4c 24 08 8a 4c 24 24 66 89 44 24 06 8a 44 24 20 88 4c 24 0b 8b ce 88 54 24 09 88 44 24 0a 66 c7 44 24 04 02 00 c7 46 ?? 01 00 00 00 c7 46 ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 10 8a 1e 8a ca 3a d3 75 1e 84 c9 74 16 8a 50 01 8a 5e 01 8a ca 3a d3 75 0e 83 c0 02 83 c6 02 84 c9 75 dc 33 c0 eb 05 1b c0 83 d8 ff 85 c0}  //weight: 1, accuracy: High
        $x_1_4 = {f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d ?? 24 ?? 83 e1 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_ZDK_2147606721_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDK"
        threat_id = "2147606721"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 20 67 6f 00 65 78 69 73 74 20 22 00 69 66 20 00 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 61 66 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 36 30 00 00 33 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 21 50 6a 00 68 01 04 10 00 ff 15 ?? ?? ?? 00 8b f0 6a 01 56 ff d5 6a 00 56 ff d5 56 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NE_2147606773_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NE"
        threat_id = "2147606773"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bf 48 41 40 00 f2 ae f7 d1 2b f9 8b f7 8b d1 8b fb 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 bf 40 41 40 00 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d1 8b fb 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 bf 3c 41 40 00 83 c9 ff f2 ae}  //weight: 10, accuracy: High
        $x_1_2 = {2e 65 78 65 00 00 00 00 72 00 00 00 70 6c 6f 72 65 00 00 00 78 00 00 00 65 00 00 00 20 00 00 00 41 70 70 49 6e 69 74 5f 44 4c 4c 73}  //weight: 1, accuracy: High
        $x_1_3 = {52 45 53 53 44 54 44 4f 53 00 00 00 42 65 65 70 00 00 00 00 5c 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 00 00 63 3a 5c 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 62 00 65 00 65 00 70 00 2e 00 73 00 79 00 73 00 00 00 00 00 53 46 43 5f 4f 53 2e 44 4c 4c 00 00 53 46 43 2e 44 4c 4c}  //weight: 1, accuracy: High
        $x_1_4 = {48 4d 5f 4d 45 53 53 [0-16] 4c 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDL_2147606850_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDL"
        threat_id = "2147606850"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6f 74 6f 20 74 72 79 20 [0-16] 69 66 20 65 78 69 73 74 20 25 73 [0-16] 64 65 6c 20 25 73 [0-16] 3a 74 72 79 [0-16] 2e 62 61 74 [0-255] 48 4d 5f 4d 45 53 53 [0-16] 4c 4c [0-80] 2e 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDN_2147606953_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDN"
        threat_id = "2147606953"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 4b e1 22 00 50 ff 15 ?? ?? ?? 00 85 c0 74 10 ff 15 ?? ?? ?? 00 85 c0 75 06 b8 01 00 00 00 c3 33 c0 c3}  //weight: 5, accuracy: Low
        $x_4_2 = {00 00 00 00 20 67 6f 74 6f 20 74 72 79 20 0a 00 69 66 20 65 78 69 73 74 20 25 73 00 64 65 6c 20 25 73 20 0a 00 00 00 00 3a 74 72 79 20 0a 00 00}  //weight: 4, accuracy: High
        $x_2_3 = {00 48 4d 5f 4d 45 53 53 57 4f 57}  //weight: 2, accuracy: High
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZDQ_2147608207_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDQ"
        threat_id = "2147608207"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b9 66 06 00 00 8d bc 24 ?? ?? 00 00 f3 ab 66 ab aa}  //weight: 3, accuracy: Low
        $x_3_2 = {f3 ab 66 ab b9 66 06 00 00 33 c0 8d}  //weight: 3, accuracy: High
        $x_2_3 = {53 65 72 76 65 72 49 50 2d 2d 3e [0-16] 53 65 72 76 65 72 4e 61 6d 65 2d 2d 3e}  //weight: 2, accuracy: Low
        $x_2_4 = {d1 d5 c9 ab 2e 74 78 74}  //weight: 2, accuracy: High
        $x_2_5 = {72 65 63 76 3a 3e 20 25 73 [0-7] 73 65 6e 64 3a 3e 20 25 73 [0-7] 51 55 49 54}  //weight: 2, accuracy: Low
        $x_2_6 = {46 72 6f 6d 3a 20 22 3d 3f 67 62 32 33 31 32 3f 42 3f 25 73 3d 3f 3d 22 20 3c 25 73 3e [0-16] 44 41 54 41 [0-7] 52 43 50 54 20 54 4f 3a 20 3c 25 73 3e [0-7] 4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 25 73 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZDR_2147608221_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDR"
        threat_id = "2147608221"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 44 46 44 00 00 00 00 25 64 00 00 2e 62 61 74 00 00 00 00 40 65 63 68 6f 20 6f 66 66 0d 0a 00 3a 4c 6f 6f 70 0d 0a 00 64 65 6c 20 22 00 00 00 22 0d 0a 00 69 66 20 65 78 69 73 74 20 22 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 00 00 00 64 65 6c 20 25 30 0d 0a 00 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {4d 61 69 6e 2e 64 6c 6c 00 45 6e [0-1] 48 6f 6f 6b [0-1] 57 69 6e 64 6f 77 00 00 00 00 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {00 3f 61 63 74 3d 00 00 00 26 64 31 30 3d 00 00 00 3a 2f 2f 00 2f 00 00 00 6d 69 62 61 6f 2e 61 73 70 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {3a 2f 2f 00 68 74 74 70 3a 2f 2f 00 2f 00 00 00 47 45 54 20 00 00 00 00 20 48 54 54 50 2f 31 2e 31 0d 0a 00 48 6f 73 74 3a 20 00 00 0d 0a 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZDS_2147608837_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDS"
        threat_id = "2147608837"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 77 53 65 74 56 61 6c 75 65 4b 65 79 00 a9 05 77 63 73 6c 65 6e 00 00 14 05 5a 77 4f 70 65 6e 4b 65 79 00 0b 04 52 74 6c 49 6e 69 74 55 6e 69 63 6f 64 65 53 74 72 69 6e 67 00 00 36 05 5a 77 52 65 61 64 46 69 6c 65 00 00 28 05 5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 00 00 f3 04 5a 77 43 72 65 61 74 65 46 69 6c 65 00 00 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "code\\new\\GameHack1216my\\RegDriver\\objfre\\i386\\Reg.pdb" ascii //weight: 1
        $x_1_3 = "Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\AsyncMac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_EQ_2147609019_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.EQ"
        threat_id = "2147609019"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 [0-59] 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d [0-16] 2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d}  //weight: 2, accuracy: Low
        $x_1_2 = {48 6f 6f 6b 2e 64 6c 6c 00 6b 73 48 6f 6f 6b 77 6f 00 74 7a 48 6f 6f 6b 77 6f}  //weight: 1, accuracy: High
        $x_1_3 = {4c 69 75 5f 4d 61 7a 69 4e 7d 6a 51 73 72 58 32 79 64 79 90 4f 71 7d 6e 68 49 6c 32 79 64 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NG_2147609102_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NG"
        threat_id = "2147609102"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 6c ff ff ff 65 6c 6c 53 c7 85 70 ff ff ff 65 72 76 69 c7 85 74 ff ff ff 63 65 4f 62 c7 85 78 ff ff ff 6a 65 63 74 c7 85 7c ff ff ff 44 65 6c 61 c7 45 80 79 4c}  //weight: 1, accuracy: High
        $x_1_2 = "Hook.dll" ascii //weight: 1
        $x_1_3 = "BroadcastSystemMessageA" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NH_2147609245_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NH"
        threat_id = "2147609245"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 3f 01 72 05 83 3f 2f 76 1e 83 3f 3a 72 05 83 3f 40 76 14 83 3f 5b 72 05 83 3f 60 76 0a 83 3f 7b 72 27 83 3f 7e 77 22}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 85 ff 75 04 85 ed 74 5c 68 00 90 01 00}  //weight: 1, accuracy: High
        $x_1_3 = "?act=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ER_2147609911_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ER"
        threat_id = "2147609911"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "oe12233tInputState" ascii //weight: 10
        $x_10_2 = "oe12233tMessageA" ascii //weight: 10
        $x_10_3 = "oe12233stThreadMessageA" ascii //weight: 10
        $x_10_4 = {00 72 65 6c 64 65 6c 00}  //weight: 10, accuracy: High
        $x_1_5 = {8b f0 f7 d6 d1 e8 83 e6 01 40}  //weight: 1, accuracy: High
        $x_1_6 = {2e 72 61 77 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ER_2147609911_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ER"
        threat_id = "2147609911"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".rawdat" ascii //weight: 1
        $x_10_2 = "oe12233tInputState" ascii //weight: 10
        $x_10_3 = "oe12233tMessageA" ascii //weight: 10
        $x_10_4 = "oe12233stThreadMessageA" ascii //weight: 10
        $x_10_5 = "\\system32\\advapi32.dll" ascii //weight: 10
        $x_10_6 = "reldel" ascii //weight: 10
        $x_10_7 = "xpia9cx31cvtSystemDirectoryA" ascii //weight: 10
        $x_10_8 = "xpia9cx31cvtTempFileNameA" ascii //weight: 10
        $x_10_9 = "xpia9cx31cvtTempPathA" ascii //weight: 10
        $x_10_10 = "xpia9cx31cvtTickCount" ascii //weight: 10
        $x_10_11 = "xpia9cx31cvtWindowsDirectoryA" ascii //weight: 10
        $x_10_12 = "xpia9cx31cvveFileExA" ascii //weight: 10
        $x_1_13 = {8b 00 03 c1 50 e8 ?? ?? ?? ?? [0-2] 85 c0 [0-2] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CF_2147609936_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CF"
        threat_id = "2147609936"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "suser=%s&spass=%s&serial=%s&serNum=%s&level=%d&money=%d&line=%s" ascii //weight: 1
        $x_1_2 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-16] 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_4 = "Referer: makesurethismymail" ascii //weight: 1
        $x_1_5 = "TenQQAccount.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDT_2147609990_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDT"
        threat_id = "2147609990"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 72 61 72 79 41 00 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 52 65 67 43 6c 6f 73 65 4b 65 79 00 00 00 50 61 74 68 54 6f 52 65 67 69 6f 6e 00 00 53 79 73 46 72 65 65 53 74 72 69 6e 67 00 00 00 49 73 4d 65 6e 75 00 00 73 65 6e 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 f2 00 00 01 00 00 00 02 00 00 00 02 00 00 00 3c f2 00 00 44 f2 00 00 4c f2 00 00 e8 67 00 00 c0 67 00 00 59 f2 00 00 62 f2 00 00 01 00 00 00 48 6f 6f 6b 2e 64 6c 6c 00 6b 73 48 6f 6f 6b 77 6f 00 74 7a 48 6f 6f 6b 77 6f 00 00 00 e0 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDY_2147610042_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDY"
        threat_id = "2147610042"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 20 01 00 8d 20 01 00 6b 62 64 68 65 6c 61 35 2e 64 6c 6c 00 41 20 01 00 53 20 01 00 64 20 01 00 3f 41 64 64 48 6f 6f 6b 40 40 59 47 5f 4e 4b 40 5a 00 3f 44 65 6c 48 6f 6f 6b 40 40 59 47 5f 4e 58 5a 00 3f 53 63 61 6e 50 77 64 40 40 59 47 5f 4e 51 41 55 48 57 4e 44 5f 5f 40 40 30 40 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_Q_2147610502_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.Q"
        threat_id = "2147610502"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {d6 85 c0 0f 84 10 00 [0-5] c6 [0-3] 78 88 [0-3] 88 [0-3] ff}  //weight: 3, accuracy: Low
        $x_3_2 = "sed.drauGemaG" ascii //weight: 3
        $x_3_3 = {6c 6f 67 69 6e 6e 61 6d 65 3d 64 66 00}  //weight: 3, accuracy: High
        $x_2_4 = "DFTemp:%08x dwGetPass2Addr:%08x dwGetPass2RetAddr:%08x" ascii //weight: 2
        $x_2_5 = {26 6d 78 64 70 3d 00 00 3f 6d 78 64 75 3d 00}  //weight: 2, accuracy: High
        $x_2_6 = "document.domain = \"hangame.com\"" ascii //weight: 2
        $x_1_7 = "Password%3A" ascii //weight: 1
        $x_1_8 = "&earthworm2=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CTA_2147610611_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CTA"
        threat_id = "2147610611"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 01 8d 85 90 fc ff ff 53 50 ff 75 f0 ff 15 ?? ?? ?? ?? ff 75 f0 ff d6 8d 45 ec c7 85 60 ff ff ff 53 4f 46 54 50 8d 85 60 ff ff ff 50 68 02 00 00 80 c7 85 64 ff ff ff 57 41 52 45 c7 85 68 ff ff ff 5c 4d 69 63 c7 85 6c ff ff ff 72 6f 73 6f c7 85 70 ff ff ff 66 74 5c 57 c7 85 74 ff ff ff 69 6e 64 6f c7 85 78 ff ff ff 77 73 5c 43 c7 85 7c ff ff ff 75 72 72 65 c7 45 80 6e 74 56 65 c7 45 84 72 73 69 6f c7 45 88 6e 5c 45 78 c7 45 8c 70 6c 6f 72 c7 45 90 65 72 5c 53 c7 45 94 68 65 6c 6c c7 45 98 45 78 65 63 c7 45 9c 75 74 65 48 c7 45 a0 6f 6f 6b 73 89 5d a4 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db c7 45 e4 54 41 32 45 c7 45 e8 64 69 74 00 89 5d ec c7 45 d4 54 46 72 6d c7 45 d8 4c 6f 67 4f c7 45 dc 6e 00 00 00 89 5d e0 8d 45 d4 53 50 53}  //weight: 1, accuracy: High
        $x_1_3 = {33 ff 8d 45 e0 57 50 57 ff 35 ?? ?? ?? ?? c7 45 e0 54 46 72 6d c7 45 e4 50 61 73 73 c7 45 e8 45 74 63 00 89 7d ec c7 45 f0 54 41 32 45 c7 45 f4 64 69 74 00 89 7d f8 ff d6 8b d8 8d 45 f0 57 50 57 53 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_CTB_2147610682_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CTB"
        threat_id = "2147610682"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 47 61 6d 65 5c [0-40] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_3 = "KickRole" ascii //weight: 10
        $x_10_4 = "\\verclsid.exe" ascii //weight: 10
        $x_10_5 = "?act=" ascii //weight: 10
        $x_10_6 = "&d00=" ascii //weight: 10
        $x_1_7 = "TerminateThread" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_R_2147610925_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.R"
        threat_id = "2147610925"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db 8a 18 69 e9 0a 05 00 00 0f af dd 03 f3 41 40 4a 75 ec}  //weight: 1, accuracy: High
        $x_1_2 = {2d 39 33 45 41 2d 34 34 41 32 2d 39 38 43 32 2d 43 30 36 39 42 37 44 30 43 41 36 37 7d 00}  //weight: 1, accuracy: High
        $x_1_3 = {36 32 41 42 33 37 42 43 00}  //weight: 1, accuracy: High
        $x_1_4 = "gold_coin" ascii //weight: 1
        $x_1_5 = "silver_coin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_ZFA_2147611282_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFA"
        threat_id = "2147611282"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "accountname" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "wow.exe" ascii //weight: 1
        $x_1_4 = "%s\\e%dUP.exe" ascii //weight: 1
        $x_1_5 = "secretQuestionAnswer" ascii //weight: 1
        $x_1_6 = "swow.asp" ascii //weight: 1
        $x_1_7 = "realmlist.wtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_U_2147611592_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.U"
        threat_id = "2147611592"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 ec 2d 36 38 38 c7 45 f0 44 42 35 46 c7 45 f4 41 35 42 45 c7 45 f8 42 7d 00 00 e8 bf 22 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {c7 45 d4 67 6f 6c 64 c7 45 d8 5f 63 6f 69 c7 45 dc 6e 00 00 00 89 75 e0 75 0f}  //weight: 2, accuracy: High
        $x_1_3 = {e8 dc 21 00 00 90 90 c7 45 d0 45 78 70 6c 89 5d d4 90 90 c7 45 e0 6f 72 65 72 89 5d e4 90 90 c7 45 f0 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GA_2147611734_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GA"
        threat_id = "2147611734"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6c 6f 72 c7 45 ?? 65 72 5c 53 c7 45 ?? 68 65 6c 6c c7 45 ?? 45 78 65 63 c7 45 ?? 75 74 65 48 c7 45 ?? 6f 6f 6b 73}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 ff d6 53 a3 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 02 ff d6 53 a3 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 07 ff d6 a3}  //weight: 1, accuracy: Low
        $x_1_3 = {50 57 c7 45 ?? 6f 6b 00 00 ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 57 75 19 ff 15 ?? ?? ?? ?? 59 68 10 27 00 00 ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 50 72 c7 45 ?? 6f 63 53 65 c7 45 ?? 72 76 65 72 c7 45 ?? 33 32 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_V_2147611783_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.V"
        threat_id = "2147611783"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 56 6a fc 57 ff d3 8d 45 f8 56 8b 35 ?? ?? ?? ?? 50 8d 45 f4 6a 04 50 57 ff d6 81 7d f4 fe db 43 bd 74 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_W_2147612278_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.W"
        threat_id = "2147612278"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ff 8b f6 90 90 90 90 8b db 90 8b ff 90 90 8b d2 90 90 8b f6 90 8b c9 90 8b db 90 90 8b ed 8b c0 90 8b f6 8b d2 8b f6 8b ed 90 8b ff 90 8b ff 8b c0 90 8b f6 90 8b c9 8b d2 90 8b f6 90 8b d2 90 8b f6}  //weight: 5, accuracy: High
        $x_5_2 = {8b ff 90 90 8b d2 90 90 90 8b c9 90 8b db 90 90 8b ed 8b c0 90 8b d2 8b f6 8b ed 90 8b ff 90 8b ff 8b c0 90 90 8b c9 8b d2 90 90 8b d2}  //weight: 5, accuracy: High
        $x_2_3 = {34 46 34 46 30 30 36 34 2d 37 31 45 30 2d 34 66 30 64 2d 30 30 30 ?? 2d 37 30 38 34 37 36 43 37 38 31 35 46}  //weight: 2, accuracy: Low
        $x_1_4 = "360Safe.exe" ascii //weight: 1
        $x_1_5 = "serverlist.txt" ascii //weight: 1
        $x_1_6 = "Hook.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_Z_2147612691_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.Z"
        threat_id = "2147612691"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d6 8d 8c 24 28 01 00 00 68 04 01 00 00 51 ff d6 8b 35 38 20 40 00 8d 54 24 24 68 a0 30 40 00 52 ff d6 8b f8 8d 84 24 28 01 00 00 68 90 30 40 00 50 89 7c 24 24 ff d6 8d 4c 24 10 89 44 24 20 51 68 06 00 02 00 6a 00 68 60 30 40 00 68 02 00 00 80 ff 15 08 20 40 00 8b 35 00 20 40 00 85 c0 74 07 8b 54 24 10 52 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "karnel32.dll" ascii //weight: 1
        $x_1_4 = "KartSvr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AE_2147614455_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AE"
        threat_id = "2147614455"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {55 8b ec 83 ec 20 56 57 ff 15 ?? ?? 40 00 33 f6 56 56 56 ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 56 56 8d 45 e0 56 50 ff ?? ?? 10 40 00 8d 45 fc 50 6a 20 ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 6a 01 68 ?? ?? 40 00 ff 75 fc e8 aa fe ff ff 83 c4 0c 68 ?? ?? 40 00 6a 01 56 ff 15 ?? ?? 40 00 8b f8 ff 15 ?? ?? 40 00}  //weight: 20, accuracy: Low
        $x_1_2 = "button-red-securitytoken.gif" ascii //weight: 1
        $x_1_3 = "weiter_zu_fm.gif" ascii //weight: 1
        $x_1_4 = "worldofwarcraft" ascii //weight: 1
        $x_1_5 = "Passwd" ascii //weight: 1
        $x_1_6 = "webget" ascii //weight: 1
        $x_1_7 = "www.youtube999.com" ascii //weight: 1
        $x_1_8 = "grunt.wowchina.com" ascii //weight: 1
        $x_1_9 = "kr.version.worldofwarcraft.com" ascii //weight: 1
        $x_1_10 = "kr.logon.worldofwarcraft.com" ascii //weight: 1
        $x_1_11 = "us.version.worldofwarcraft.com" ascii //weight: 1
        $x_1_12 = "us.logon.worldofwarcraft.com" ascii //weight: 1
        $x_1_13 = "tw.version.worldofwarcraft.com" ascii //weight: 1
        $x_1_14 = "tw.logon.worldofwarcraft.com" ascii //weight: 1
        $x_1_15 = "eu.version.worldofwarcraft.com" ascii //weight: 1
        $x_1_16 = "eu.logon.worldofwarcraft.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AF_2147615083_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AF"
        threat_id = "2147615083"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Device\\dadef955" wide //weight: 2
        $x_2_2 = "\\Device\\d1037a1d" wide //weight: 2
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "ZwClose" ascii //weight: 1
        $x_1_6 = "\\KnownDlls\\KnownDllPath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AG_2147616231_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AG"
        threat_id = "2147616231"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/new/get.asp" ascii //weight: 1
        $x_1_2 = "login_password" ascii //weight: 1
        $x_1_3 = "login_email" ascii //weight: 1
        $x_1_4 = ".paypal." ascii //weight: 1
        $x_1_5 = "onlinegame" ascii //weight: 1
        $x_1_6 = "%s?us=%s&ps=%s&mo=%s" ascii //weight: 1
        $x_1_7 = "cardlee" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AK_2147616780_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AK"
        threat_id = "2147616780"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 84 91 00 00 00 6a 02 6a 00 68 4a ff ff ff 53 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b c8 49 85 c9 72 1e 41 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 18 80 c3 ?? 80 f3 ?? 80 eb ?? 88 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AL_2147616896_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AL"
        threat_id = "2147616896"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 50 8d ?? ?? ?? 6a 04 51 56 ff d3 8b 54 24 10 6a 00 81 c2 f8 00 00 00 6a 00 52 56 ff d7 33 c0 8d ?? ?? ?? 89 ?? ?? ?? 8d ?? ?? ?? 89 ?? ?? ?? 50 51 6a 08 52 56 66 ?? ?? ?? ?? ff d3 8b ?? ?? ?? 8b ?? ?? ?? 40 00 3d 32 54 76 98}  //weight: 5, accuracy: Low
        $x_1_2 = "wow.exe" ascii //weight: 1
        $x_1_3 = "qq.exe" ascii //weight: 1
        $x_1_4 = "infection started" ascii //weight: 1
        $x_1_5 = "/c  del C:\\myapp.exe > nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_D_2147616900_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.gen!D"
        threat_id = "2147616900"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks\\" ascii //weight: 1
        $x_1_3 = {3f 64 6f 3d 73 65 6e 64 26 47 61 6d 65 3d [0-5] 26 53 65 72 76 65 72 3d 25 73 26 5a 6f 6e 65 3d 25 73 26 4e 61 6d 65 3d 25 73 26 50 61 73 73 3d 25 73 26 72 6f 6c 65 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "regsvr32.exe /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AN_2147617089_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AN"
        threat_id = "2147617089"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b c0 74 45 89 85 ?? fe ff ff c7 85 ?? fe ff ff e8 03 00 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 40 89 85 ?? fe ff ff 8d 05 ?? ?? 40 00 89 85 ?? fe ff ff 8d 85 ?? fe ff ff 50 6a 00 6a 4a ff b5 ?? fe ff ff ff 15 ?? ?? 40 00}  //weight: 5, accuracy: Low
        $x_5_2 = {68 60 ea 00 00 6a 00 6a 00 ff 15 ?? ?? 00 10 a3 ?? ?? 00 10 68 ?? ?? 00 10 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? 00 10 0b c0 75 3f 68 c8 00 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = "HBQQ.dll" ascii //weight: 5
        $x_5_4 = "Program Manager" ascii //weight: 5
        $x_1_5 = "360safebox.exe" ascii //weight: 1
        $x_1_6 = "rename %s %s" ascii //weight: 1
        $x_1_7 = "if exist %s goto Repeat" ascii //weight: 1
        $x_1_8 = "del %s" ascii //weight: 1
        $x_1_9 = "http://" ascii //weight: 1
        $x_1_10 = "Forthgoner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AP_2147617115_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AP"
        threat_id = "2147617115"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 44 44 2e 64 6c 6c 00 4c 70 6b 44 6c 6c}  //weight: 2, accuracy: High
        $x_1_2 = {66 61 73 73 64 66 6a 66 73 64 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_3 = {4c 6f 61 64 44 4c 4c 2e 64 6c 6c 00 4c 70 6b 44 6c 6c}  //weight: 2, accuracy: High
        $x_1_4 = {67 61 6d 65 74 65 78 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_5 = {6a 02 6a 00 68 (4a|44) ff ff ff 53 e8 ?? ?? ff ff 8d 85 7c ff ff ff e8}  //weight: 2, accuracy: Low
        $x_2_6 = {8a 0c 10 80 c1 ?? 80 f1 ?? 80 e9 ?? 8b 1d ?? ?? ?? ?? 88 0c 13 42 81 fa ?? ?? 00 00 75 e2}  //weight: 2, accuracy: Low
        $x_1_7 = {c6 04 03 e9 40 8b ca c1 e9 00 80 e1 ff 88 0c 03 40 8b ca c1 e9 08 80 e1 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AQ_2147617356_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AQ"
        threat_id = "2147617356"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 ff 8b 44 24 10 8a 04 02 32 01 34 ?? 46 3b 74 24 14 88 01 7c dd}  //weight: 2, accuracy: Low
        $x_2_2 = {3c ff 74 1c 57 ff d6 3c 30 59 7c f4 3c 39 7f f0 8b 4d fc ff 45 fc 83 7d fc 06 88 44 0d f4 7c e0}  //weight: 2, accuracy: High
        $x_1_3 = {83 c0 05 0f b7 f0 c1 e6 10 8b 85 ?? ?? ff ff 83 c0 05 0f b7 c0 0b f0 89 b5 ?? ?? ff ff 56 6a 01 68 01 02 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {d3 d0 c3 dc b1 a3 00}  //weight: 1, accuracy: High
        $x_1_5 = "re=%s&s=%s&A=%s&P=%s&MB=%s" ascii //weight: 1
        $x_1_6 = {3d 25 64 26 6d 61 63 3d 25 73 26 52 47 31 3d 25 64 26 5a 3d 25 73 3a 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AR_2147617386_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AR"
        threat_id = "2147617386"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-16] 5c 73 79 73 74 65 6d 33 32 5c 77 64 [0-6] 2e 64 6c 6c 2c 48 6f 6f 6b 00}  //weight: 2, accuracy: Low
        $x_2_2 = {5c 73 79 73 74 65 6d 33 32 00 41 73 6b 54 61 6f 00 00 53 74 61 72 74 77 64 00 53 74 61 72 74 00 00 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_3 = {68 20 00 cc 00 68 02 01 00 00 68 a8 00 00 00 55 6a 19 56 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? be ?? ?? ?? ?? 68 80 00 00 00 56 ff d5}  //weight: 1, accuracy: Low
        $x_2_4 = {26 41 63 63 6f 75 6e 74 3d 00 00 00 26 43 61 73 68 3d 00 00 26 52 61 6e 6b 3d 00 00 26 52 6f 6c 65 3d 00 00 26 59 75 61 6e 62 61 6f 3d}  //weight: 2, accuracy: High
        $x_2_5 = {26 53 65 72 76 65 72 3d 00 00 00 00 62 61 73 69 63 69 6e 66 6f 2e 61 73 70 78 3f 41 72 65 61 3d 00 00 00 00 50 4f 53 54 20 00 00 00 79 6f 75 20 61 72 65 20 6b 69 63 6b 65 64}  //weight: 2, accuracy: High
        $x_1_6 = {d1 b0 cf c9 ce ca b5 c0 00}  //weight: 1, accuracy: High
        $x_1_7 = {d5 cc bd a3 b3 a4 b8 e8 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_NJ_2147617435_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NJ!sys"
        threat_id = "2147617435"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 08 68 53 53 44 54 c1 e0 02 50 56 ff 15 ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\KnownDlls\\KnownDllPath" wide //weight: 1
        $x_1_3 = "\\DosDevices\\*:\\" wide //weight: 1
        $x_1_4 = {89 46 28 c6 46 20 00 c7 46 08 05 01 00 00 e8 ?? ?? 00 00 89 46 50 8b 46 60 89 5e 64 83 e8 24}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c0 39 71 08 76 18 8b 4d 08 2b 8d 28 ff ff ff 01 0c 83 8b 0d ?? ?? 01 00 40 3b 41 08 72 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AX_2147617483_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AX"
        threat_id = "2147617483"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "game.exe" ascii //weight: 10
        $x_1_2 = "\\dri~$~vers\\e~$~tc\\hos~$~ts" ascii //weight: 1
        $x_1_3 = "%s~$~%s~$~*~$~.dll" ascii //weight: 1
        $x_1_4 = "expl~$~orer.exe" ascii //weight: 1
        $x_1_5 = "http://%s:%d%s?%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AM_2147618165_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AM"
        threat_id = "2147618165"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 5b 74 0a e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 90 5f 01 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0a 68 c8 00 00 00 56 ff 15 ?? ?? 40 00 85 c0 74 29 50 56 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_2_3 = {6a 64 ff d6 e8 ?? ?? ff ff 6a 64 ff d6 e8 ?? ?? ff ff 6a 64 ff d6 eb a6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AM_2147618165_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AM"
        threat_id = "2147618165"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "server=%s&account=%s&password1=%s" ascii //weight: 1
        $x_1_2 = "&levels=%s&cash=%s&name=%s&specialSign=%s&" ascii //weight: 1
        $x_1_3 = "&ProtPass=%s&Verify=%s" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 77 6f 77 2f 70 6f 73 74 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_5 = "?act=getmbok&account=%s&mb=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NL_2147618427_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NL"
        threat_id = "2147618427"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Forthgoner" ascii //weight: 1
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "HBQQ.dll" ascii //weight: 1
        $x_1_4 = "HBInject32" ascii //weight: 1
        $x_1_5 = "rename %s %s" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 1
        $x_1_8 = "AppInit_DLLs" ascii //weight: 1
        $x_1_9 = "Program Manager" ascii //weight: 1
        $x_1_10 = "WM_HOOKEX_RK" ascii //weight: 1
        $x_1_11 = "BasicCtrlDll.dll" ascii //weight: 1
        $x_1_12 = "d10=%s&d11=%s" ascii //weight: 1
        $x_1_13 = "FY_PASSWORD" ascii //weight: 1
        $x_1_14 = "http://woyaoshe.com/iptest/t/xcly.asp" ascii //weight: 1
        $x_1_15 = "OSTURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule PWS_Win32_OnLineGames_NM_2147618624_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NM"
        threat_id = "2147618624"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 fe 36 7e 05 83 ee 32 eb 03 83 c6 05 8d 4c 24 08 51 ff d7 8b 54 24 14 81 e2 ff ff 00 00 3b d6 75 eb}  //weight: 2, accuracy: High
        $x_2_2 = {eb 03 8b d6 46 8a 0c 07 32 0c 1a 40 4d 88 48 ff 75 e4}  //weight: 2, accuracy: High
        $x_2_3 = {7e 24 56 8b 74 24 ?? 57 8d 3c 16 8b 74 24 ?? 8a 14 07 88 14 30 40 3b c1 7c f5}  //weight: 2, accuracy: Low
        $x_1_4 = "hpig_WS2.dat" ascii //weight: 1
        $x_1_5 = {26 74 79 70 65 3d 00 00 64 61 74 61 3d}  //weight: 1, accuracy: High
        $x_1_6 = "\\hunsa4.dll" ascii //weight: 1
        $x_1_7 = "MIBAO.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CC_2147618739_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CC"
        threat_id = "2147618739"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 81 36 ?? ?? ?? ?? 81 3e 00 04 00 00 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 81 75 fc ?? ?? ?? ?? 81 7d fc 00 04 00 00 0f 83}  //weight: 1, accuracy: Low
        $x_2_3 = {00 10 8a 50 02 32 96 ?? ?? ?? ?? 28 d1 88 48 01 8a 48 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GC_2147618745_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GC"
        threat_id = "2147618745"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 0a c0 74 03 32 45 10 aa 80 3e 00 75 06 80 7e 01 00 74 02 eb ea}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 94 6a 00 6a 18 8d 45 98 50 6a 00 ff 75 94 e8 ?? ?? 00 00 0b c0 75 72 ff 75 ac 6a 00 68 00 04 00 00 e8 ?? ?? 00 00 0b c0 74 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CE_2147620097_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CE"
        threat_id = "2147620097"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b ca 8a d1 02 d0 30 10 40 8d 14 01 81 fa 00 01 00 00 72 ee}  //weight: 1, accuracy: High
        $x_1_2 = {2b f7 89 47 06 83 ee 0a c6 47 0a e9 89 77 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ET_2147620108_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ET"
        threat_id = "2147620108"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 04 03 e9 40 8b ca c1 e9 00 80 e1 ff 88 0c 03}  //weight: 2, accuracy: High
        $x_2_2 = "action=" ascii //weight: 2
        $x_2_3 = "&zt=" ascii //weight: 2
        $x_1_4 = {50 61 74 63 68 44 4c 4c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CJ_2147620355_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CJ"
        threat_id = "2147620355"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 61 72 74 20 57 6d 64 6d 50 6d 53 4e 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 74 6f 70 20 57 6d 64 6d 50 6d 53 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CJ_2147620355_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CJ"
        threat_id = "2147620355"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 52 8d ?? ?? ?? ?? 00 00 68 14 01 00 00 50 56 ff 15 24 20 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 b8 0b 00 00 f3 ab ff 15 ?? ?? 40 00 8d ?? ?? ?? 51 68 04 01 00 00 ff 15 ?? ?? 40 00 8d ?? ?? ?? 68 ?? ?? 40 00 52 ff 15 ?? ?? 40 00 8d ?? ?? ?? 50 6a 6b e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CK_2147621051_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CK"
        threat_id = "2147621051"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 20 75 03 c6 00 5f 40}  //weight: 1, accuracy: High
        $x_1_2 = {5f 58 5a 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 1a 2b c1 59 83 c0 0d 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CI_2147621494_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CI"
        threat_id = "2147621494"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6d 00 70 00 75 00 74 00 20 00 00 00 06 00 00 00 62 00 79 00 65 00}  //weight: 10, accuracy: High
        $x_10_2 = "cmd /c ftp -s:" wide //weight: 10
        $x_10_3 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00 00 00 43 00 6c 00 69 00 63 00 6b 00}  //weight: 10, accuracy: High
        $x_5_4 = ".servehttp.com" wide //weight: 5
        $x_5_5 = ".servehalflife.com" wide //weight: 5
        $x_1_6 = "(downer)" wide //weight: 1
        $x_1_7 = "(ftuper)" wide //weight: 1
        $x_1_8 = "(address)" wide //weight: 1
        $x_1_9 = "(email)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CG_2147621794_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CG"
        threat_id = "2147621794"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 69 76 78 44 65 63 6f 64 65 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {00 77 6f 6f 6f 6c 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_3 = {00 61 76 70 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 52 8d ?? ?? ?? ?? 00 00 68 14 01 00 00 50 57 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 b8 0b 00 00 f3 ab 66 ?? ?? ?? ?? ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CH_2147621976_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CH"
        threat_id = "2147621976"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 b8 0b 00 00 89 ?? ?? ?? ff 15 ?? ?? 40 00 8d ?? ?? ?? ?? 00 00 52 68 04 01 00 00 ff 15 ?? ?? 40 00 [0-32] 51 6a 6a e8 0c fa ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {51 6a 6a e8 5b fc ff ff 83 c4 08 85 c0 5f 5e 5b 74 23 8d 94 ?? ?? ?? ?? 00 52 6a 6b e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 0d 8d ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CL_2147622115_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CL"
        threat_id = "2147622115"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mir1.dat" ascii //weight: 1
        $x_1_2 = {2e 64 6c 6c 00 68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e}  //weight: 1, accuracy: High
        $x_1_3 = {7e 24 53 56 8b 74 24 18 8b dd 2b de 8a 04 33 55 04 ?? 34 ?? 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CN_2147622430_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CN"
        threat_id = "2147622430"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Zone=%s&server=%s&Name=%s&Pass=%s&" ascii //weight: 1
        $x_1_2 = "?action=getmbok&" ascii //weight: 1
        $x_1_3 = "qqlogin.exe" ascii //weight: 1
        $x_1_4 = "mibao.asp" ascii //weight: 1
        $x_1_5 = "360Safe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_FT_2147622736_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FT"
        threat_id = "2147622736"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\microsoft\\windows\\currentversion\\Explorer\\shellexecutehooks" ascii //weight: 1
        $x_1_2 = {6a 0a ff 15 ?? ?? 40 00 8d 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 50 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 83 c4 10 6a 01 58}  //weight: 1, accuracy: Low
        $x_1_3 = {68 e8 03 00 00 ff 15 ?? ?? 40 00 ff d3 2b 45 ?? 3d 40 77 1b 00 76 ?? ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CO_2147622755_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CO"
        threat_id = "2147622755"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "game-r2" ascii //weight: 1
        $x_1_2 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "222.73.10.84    www.game-r2.com" ascii //weight: 1
        $x_1_4 = "cv.bat" ascii //weight: 1
        $x_1_5 = "del %0" ascii //weight: 1
        $x_1_6 = "8F62C148-2937-4F60-971D-D6A9547B19C3" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CP_2147622766_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CP"
        threat_id = "2147622766"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\microsoft\\windows\\currentversion\\Explorer\\shellexecutehooks" ascii //weight: 1
        $x_1_2 = "=%s&PIN=%s&" ascii //weight: 1
        $x_1_3 = "=%s&R=%s&RG=%d&M=%d&" ascii //weight: 1
        $x_1_4 = "/mibao.asp" ascii //weight: 1
        $x_1_5 = "/mb.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CQ_2147622827_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CQ"
        threat_id = "2147622827"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Zone=%s&server=%s&Name=%s&Pass=%s&" ascii //weight: 1
        $x_1_2 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_3 = "regsvr32.exe /s " ascii //weight: 1
        $x_1_4 = "360tray.exe" ascii //weight: 1
        $x_1_5 = "360Safe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CR_2147622872_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CR"
        threat_id = "2147622872"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "action=fresh&zt=on" ascii //weight: 10
        $x_10_2 = "tty3dfadsfasdfsa" ascii //weight: 10
        $x_5_3 = {74 74 79 33 64 71 77 65 72 74 79 [0-4] 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_1_4 = "QQLogin.exe" ascii //weight: 1
        $x_1_5 = "tty3d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_CS_2147622873_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CS"
        threat_id = "2147622873"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "suser=%s&spass=%s&serial=%s&serNum=%s&name=%s&level=%d&money=%d&line=%s&boxpass=%s" ascii //weight: 10
        $x_10_2 = {33 c0 f2 ae f7 d1 2b f9 8d 95 d0 fd ff ff 8b c1 8b f7 8b fa 6a 2f c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 8d d7 fd ff ff 51 ff 15}  //weight: 10, accuracy: High
        $x_5_3 = "installHook" ascii //weight: 5
        $x_5_4 = "msgCallBack@@YGJHIJ@Z" ascii //weight: 5
        $x_1_5 = "uname.nls" ascii //weight: 1
        $x_1_6 = "killGame" ascii //weight: 1
        $x_1_7 = "qqfo.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ABS_2147622888_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABS"
        threat_id = "2147622888"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EnHookWindow" ascii //weight: 1
        $x_1_2 = "UninstallHook" ascii //weight: 1
        $x_1_3 = "sub_getmessage" ascii //weight: 1
        $x_1_4 = "sub_keyboard" ascii //weight: 1
        $x_1_5 = "game.exe" ascii //weight: 1
        $x_1_6 = "Explorer.EXE" ascii //weight: 1
        $x_1_7 = "&ac=" ascii //weight: 1
        $x_1_8 = "&mb=kick" ascii //weight: 1
        $x_1_9 = "InternetOpenA" ascii //weight: 1
        $x_1_10 = "ElementClient Window" ascii //weight: 1
        $x_1_11 = "Element Client" ascii //weight: 1
        $x_1_12 = "ticked" ascii //weight: 1
        $x_1_13 = "userdata\\currentserver.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule PWS_Win32_OnLineGames_CT_2147622926_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CT"
        threat_id = "2147622926"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8b 35 ?? ?? 00 10 57 ff 35 ?? ?? 00 10 68 ?? ?? 00 10 6a 04 ff d6 57 a3 ?? ?? 00 10 ff 35 ?? ?? 00 10 68 ?? ?? 00 10 6a 02 ff d6 57 a3 ?? ?? 00 10 ff 35 ?? ?? 00 10 68 56 1c 00 10 6a 07 ff d6 a3 ?? ?? 00 10 be ?? ?? 00 10 8d 45 ?? 56 50 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f4 01 00 00 ff 15 ?? ?? 00 10 bf 00 00 30 00 53 57 be 00 10 40 00 68 ?? ?? 00 10 56 e8 ?? ff ff ff 83 c4 10 83 f8 ff 0f ?? ?? ?? 00 00 03 c6 53 89 45 ?? 57 83 c0 05 68 ?? ?? 00 10 56 a3 ?? ?? 00 10 e8 ?? ff ff ff 83 c4 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CU_2147622931_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CU"
        threat_id = "2147622931"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 65 61 72 74 68 77 6f 72 6d 32 3d 00 00 00 00 26 74 75 72 74 6c 65 32 3d}  //weight: 1, accuracy: High
        $x_1_2 = {81 ff 2c 01 00 00 77 ?? 68 ?? ?? 00 10 55 e8 ?? ?? ff ff 8b f0 bb ?? ?? 00 10 56 53 55 e8 ?? ?? ff ff 2b c6 83 c6 0d 83 e8 0d 50 56}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c9 7c 26 85 c0 7c 22 85 ff 74 1e 83 c1 05 51 68 ?? ?? ?? ?? 55 e8 ?? ?? ff ff 8b 4c ?? ?? 2b c1 83 e8 0a 83 c1 0a 50 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CV_2147622932_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CV"
        threat_id = "2147622932"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 61 73 74 47 61 6d 65 53 65 72 76 65 72 00 00 75 73 65 72 5c 75 69 63 6f 6d 6d 6f 6e 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_2 = {6a 05 52 68 d2 60 47 00 6a 00 e8 ?? ?? ff ff 68 ?? ?? 00 10 8d ?? ?? ?? 6a 06 50 68 9b e6 40 00 6a 01 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 06 e9 55 55 8d 83 ?? ?? ?? ?? 57 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02 c1 ea 10 c1 e8 18 88 56 03 56 88 46 04 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_EU_2147622939_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.EU"
        threat_id = "2147622939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 07 e9 47 2b c7 83 e8 04 89 07}  //weight: 5, accuracy: High
        $x_5_2 = {66 3d 15 00 74 2d 66 8b 06 50 e8 ?? ?? ?? ?? 66 3d 50 00 74 1e 66 8b 06 50 e8 ?? ?? ?? ?? 66 3d 99 05 74 0f 66 8b 06 50 e8 ?? ?? ?? ?? 66 3d ff 15 75 48}  //weight: 5, accuracy: Low
        $x_1_3 = "wq=%s&wf=%s&ws=%d&bb=%s&d=g&yx=" ascii //weight: 1
        $x_1_4 = "d=rw&bb=%s&wf=%s&yx=%s" ascii //weight: 1
        $x_1_5 = "yx=host&wjm=%s&ss=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ABF_2147622990_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABF"
        threat_id = "2147622990"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?action=&Name=%s&State=%d" ascii //weight: 1
        $x_1_2 = "\\UserSetting.ini" ascii //weight: 1
        $x_1_3 = "PINCODE1" ascii //weight: 1
        $x_1_4 = "qqlogin.exe" ascii //weight: 1
        $x_1_5 = "gzqqdnf.dat" ascii //weight: 1
        $x_1_6 = "DNF.exe" ascii //weight: 1
        $x_1_7 = "TenQQAccount.dll" ascii //weight: 1
        $x_1_8 = "360Safe.exe" ascii //weight: 1
        $x_1_9 = "360tray.exe" ascii //weight: 1
        $x_1_10 = "DNF.DLL" ascii //weight: 1
        $x_1_11 = "?gameType" ascii //weight: 1
        $x_1_12 = "&Name=%s&password=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule PWS_Win32_OnLineGames_ABE_2147622991_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABE"
        threat_id = "2147622991"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".rxjh.com.cn" ascii //weight: 1
        $x_1_2 = "User=%s&Pass=%s&Server=%s-%s-%d&Role=%s" ascii //weight: 1
        $x_1_3 = "yb_mem.dll" ascii //weight: 1
        $x_1_4 = "%s(%s-%d)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ABD_2147622992_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABD"
        threat_id = "2147622992"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 61 6d 65 3d 25 73 26 50 61 73 73 [0-5] 3d 25 73 26 [0-32] 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 73 26 59 42 3d 25 73 26 [0-32] 3d 25 73 26 4d 42 3d 25 73 26 [0-32] 3d 25 73 26 [0-32] 3d 25 73 26 [0-32] 3d 25 73 26 [0-32] 3d 25 73 26 [0-64] 76 65 72 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = "&Server=%s" ascii //weight: 1
        $x_1_3 = "&Zone=%s" ascii //weight: 1
        $x_1_4 = "&State=2" ascii //weight: 1
        $x_1_5 = "?action=&Name=" ascii //weight: 1
        $x_1_6 = "servername" ascii //weight: 1
        $x_1_7 = "\\config.ini" ascii //weight: 1
        $x_1_8 = "Getmb.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ABH_2147623009_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABH"
        threat_id = "2147623009"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\data\\id.ini" ascii //weight: 1
        $x_1_2 = "A1B2C3" ascii //weight: 1
        $x_1_3 = "?action=getpos&Name=" ascii //weight: 1
        $x_1_4 = "Readmb.asp" ascii //weight: 1
        $x_1_5 = "gold_coin" ascii //weight: 1
        $x_1_6 = "balance" ascii //weight: 1
        $x_1_7 = "level" ascii //weight: 1
        $x_1_8 = "?gameType" ascii //weight: 1
        $x_1_9 = "&Server=%s" ascii //weight: 1
        $x_1_10 = "&Zone=%s" ascii //weight: 1
        $x_1_11 = "&Name=%s&password=%s&" ascii //weight: 1
        $x_1_12 = "nickName=%s&Level=%s&Money=%s&" ascii //weight: 1
        $x_1_13 = "secoPass=%s&MB=%s&bankPass=%s&noRefreshCode=%s&para=%s&ver=%s" ascii //weight: 1
        $x_1_14 = "\\data\\config.ini" ascii //weight: 1
        $x_1_15 = "asktao.mod" ascii //weight: 1
        $x_1_16 = "360Safe.exe" ascii //weight: 1
        $x_1_17 = "360Tray.exe" ascii //weight: 1
        $x_1_18 = "ZoneLink" ascii //weight: 1
        $x_1_19 = "AutoUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ABG_2147623010_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABG"
        threat_id = "2147623010"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?action=&Name=%s&State=%d" ascii //weight: 1
        $x_1_2 = "?gameType" ascii //weight: 1
        $x_1_3 = "&Name=%s&password=%s" ascii //weight: 1
        $x_1_4 = "game.exe" ascii //weight: 1
        $x_1_5 = "sound.dll" ascii //weight: 1
        $x_1_6 = "%s(%d) " ascii //weight: 1
        $x_1_7 = "regsvr32.exe /s " ascii //weight: 1
        $x_1_8 = "&Server=%s" ascii //weight: 1
        $x_1_9 = "&Zone=%s" ascii //weight: 1
        $x_1_10 = "&nickName=%s&lord=%s&Level=%s&Money=%u&goldCoin=%u&YB=%u&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFG_2147623049_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFG"
        threat_id = "2147623049"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8d 54 ?? ?? 52 ff 15 ?? ?? 00 10 8b 74 ?? ?? 8b 3d ?? ?? 00 10 8d 44 ?? ?? 50 66 c7 ?? ?? ?? cf 07 ff d7 68 b8 0b 00 00 ff d5 8d 4c ?? ?? 51 66 89 ?? ?? ?? ff d7 a1 ?? ?? 00 10 85 c0 74 05 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "%s?acnt=%s&pass=%s&serv=%s&game=Dnf&temp=%d" ascii //weight: 1
        $x_1_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 [0-96] 06 07 07 07 06 06 09 4f 6c 6c 79 44 62 67 4f 6c 6c 79 49 43 45 50 45 64 69 74 6f 72 4c 6f 72 64 50 45 43 33 32 41 73 6d 49 6d 70 6f 72 74 52 45 43 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 [0-16] 73 76 63 68 6f 73 74 2e 65 78 65 [0-16] 44 65 62 75 67 67 65 72 [0-16] 5c [0-16] 2e 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_ABJ_2147623108_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABJ"
        threat_id = "2147623108"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {66 6f 6e 74 73 5c 67 74 68 [0-32] 2e 66 6f 6e}  //weight: 100, accuracy: Low
        $x_1_2 = "%s?action=&Name=%s&State=%d" ascii //weight: 1
        $x_1_3 = {3f 64 6f 3d 73 65 6e 64 26 47 61 6d 65 3d [0-7] 26 69 6e 70 75 74 73 6f 75 72 63 65 3d 25 73 26 25 76 65 72 3d 33 32 35 26 5a 6f 6e 65 3d 25 73 26 73 65 72 76 65 72 3d 25 73 26 4e 61 6d 65 3d 25 73 26 50 61 73 73 3d 25 73 26 50 61 73 73 54 77 6f 3d 25 73 26 72 6f 6c 65 3d 25 73 26 6c 6f 72 64 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 75 26 67 6f 6c 64 43 6f 69 6e 3d 25 75 26 59 42 3d 25 75 26 65 71 75 69 70 6d 65 6e 74 3d 25 73 26 62 61 67 3d 25 73 26 4d 42 3d 25 64 26 4d 42 74 69 6d 65 3d 25 64 26 68 61 72 64 77 61 72 65 3d 25 73 26 4b 65 79 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_4 = "?Name=%s&Pass=%s&Zone=%s&Server=%s&Store=%s&Level=%s&MB=%d&Key=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ABK_2147623109_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ABK"
        threat_id = "2147623109"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {66 6f 6e 74 73 5c 67 74 68 [0-32] 2e 66 6f 6e}  //weight: 100, accuracy: Low
        $x_1_2 = {53 65 72 76 65 72 3d 25 73 26 [0-32] 4e 61 6d 65 3d 25 73 26 50 61 73 73 3d 25 73 26 72 6f 6c 65 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 73 26 [0-32] 26 4d 42 3d 25 73 26 43 61 72 64 3d 25 73 3d 25 73 7c 25 73 3d 25 73 7c 25 73 3d 25 73 26 53 74 6f 72 65 3d 25 73 26 4b 65 79 3d 25 73 26 [0-32] 69 6e 70 75 74 73 6f 75 72 63 65 3d 25 73 26 76 65 72 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_3 = "?action=&Name=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CW_2147623130_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CW"
        threat_id = "2147623130"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 56 4d 6f 6e 58 50 2e 65 78 65 00 61 76 70 2e 65 78 65 00 5c 6a 78 6f 6e 6c 69 6e 65 2e 65 78}  //weight: 1, accuracy: High
        $x_1_2 = {8b cb 33 c0 8d bc ?? ?? 04 00 00 68 b8 0b 00 00 f3 ab 89 54 ?? ?? ff d5 8d 94 ?? ?? 04 00 00 52 68 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 10 27 00 00 ff d5 8b 3d ?? ?? 40 00 8b 1d ?? ?? 40 00 6a 00 56 6a 00 6a 01 ff d3 50 ff d7 68 ?? ?? 40 00 e8 ?? ?? ff ff 8b f0 83 c4 04 85 f6 77 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CX_2147623131_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CX"
        threat_id = "2147623131"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "game.exe" ascii //weight: 1
        $x_1_2 = {6a 06 50 68 8b e6 40 00 6a 01 e8 ?? ?? ff ff 68 ?? ?? 00 10 8d 4c ?? ?? 6a 06 51 68 d8 a9 62 00 6a 02}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 09 00 00 00 be ?? ?? 00 10 8d ?? ?? ?? 01 00 00 33 c0 f3 a5 66 a5 a4 b9 0c 00 00 00 bf ?? ?? 00 10 f3 ab 8d ?? ?? ?? 01 00 00 68 ?? ?? 00 10 52 66 ab e8 ?? ?? ff ff 83 c4 40 e8 ?? ?? ff ff a1 ?? ?? 00 10 8b 0d ?? ?? 00 10 8b 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CY_2147623174_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CY"
        threat_id = "2147623174"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "action=fresh&zt=succmbh&u=" ascii //weight: 1
        $x_1_2 = "InternetQueryDataAvailable" ascii //weight: 1
        $x_1_3 = "start\\UserSetting.ini" ascii //weight: 1
        $x_1_4 = "qqlogin.exe" ascii //weight: 1
        $x_1_5 = "action=ok&u=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_EX_2147623177_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.EX"
        threat_id = "2147623177"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8d 7d ?? c6 45 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 ff 75 08 89 ?? 0c 89 75 ?? c6 45 ?? 60 56 68 ff 0f 1f 00 c6 45 ?? ?? c6 45 ?? ?? c6 45}  //weight: 1, accuracy: Low
        $x_1_3 = "%s?us=%s&ps=%s&" ascii //weight: 1
        $x_1_4 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_CZ_2147623418_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.CZ"
        threat_id = "2147623418"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jxsjwsasystem.gif" ascii //weight: 1
        $x_1_2 = {c6 06 e9 55 55 8d 83 ?? ?? ?? ?? 57 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02 c1 ea 10 c1 e8 18 88 56 03 56 88 46 04 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {7e 24 53 56 8b 74 24 18 8b dd 2b de 8a 04 33 55 04 ?? 34 ?? 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DC_2147623983_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DC"
        threat_id = "2147623983"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f0 50 66 c7 45 f0 6c 07 ff d6 68 e8 03 00 00 ff 15 ?? ?? 40 00 8d 45 f0 50 ff d3 66 8b 45 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 04 37 8a 44 05 ac 88 04 0a ff 15 ?? ?? 40 00 ff 45 fc 39 75 fc 72 bd 60 b8 0c 00 00 00 bb 0c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DD_2147623984_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DD"
        threat_id = "2147623984"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 81 64 cc 0f c1 6a 80 30 56 eb 0f 89 ef 4d}  //weight: 1, accuracy: High
        $x_1_2 = {3b c3 0f 85 a3 00 00 00 c7 05 ?? ?? 00 10 79 3a 40 00 eb 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HA_2147624031_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HA"
        threat_id = "2147624031"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 03 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 71 03 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 00 00 74 02 4f 70 65 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "?Name=%s&password=%s&Zone=%s&Server=%s&bankPass=%s&Level=%s&MB=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DE_2147624041_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DE"
        threat_id = "2147624041"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "?user=" ascii //weight: 1
        $x_1_3 = "fuck" ascii //weight: 1
        $x_1_4 = "&pwd=" ascii //weight: 1
        $x_1_5 = {8b f8 85 ff 7e 4e bb 01 00 00 00 8b 45 fc 8a 44 18 ff 24 0f 8b 55 ?? 8a 54 32 ff 80 e2 0f 32 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DF_2147624225_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DF"
        threat_id = "2147624225"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mdmmm.vxd" ascii //weight: 1
        $x_1_2 = "VerCLSID.exe" ascii //weight: 1
        $x_1_3 = {57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 00 00 00 ff ff ff ff 2c 00 00 00 43 4c 53 49 44 5c 7b 39 32 42 31 45 38 31 36 2d 32 43 45 46 2d 34 33 34 35 2d 38 37 34 38 2d 37 36 39 39 43 37 43 39 39 33 35 46 7d 00 00 00 00 ff ff ff ff 0f 00 00 00 5c 49 6e 50 72 6f 63 53 65 72 76 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DG_2147624226_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DG"
        threat_id = "2147624226"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 64 6d 33 36 35 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 69 72 73 74 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 61 6c 6c 5f 6d 64 6d 5f 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 42 68 ?? ?? 40 00 6a 00 6a 00 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_5 = {50 6a 02 e8 ?? ?? ff ff a3 ?? ?? 40 00 6a 00 a1 ?? ?? 40 00 50 b8 ?? ?? 40 00 50 6a 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DH_2147624389_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DH"
        threat_id = "2147624389"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "currentversion\\Explorer\\shellexecutehooks" ascii //weight: 1
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "%s\\FOnts\\%s.ttf" ascii //weight: 1
        $x_1_4 = "&PIN=%s&R=%s&RG=%d&M=%d&M1=%d&mac=%s" ascii //weight: 1
        $x_1_5 = {63 6f 6e 6e 65 63 74 00 72 65 63 76}  //weight: 1, accuracy: High
        $x_1_6 = "User-Agent: igameclient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_EL_2147624577_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.EL"
        threat_id = "2147624577"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 20 8d 4c 24 28 89 5c 24 28 51 8b 10 50 ff 52 1c}  //weight: 1, accuracy: High
        $x_1_2 = "%s?user=%s&pass=%s&" ascii //weight: 1
        $x_1_3 = "wow.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFI_2147624612_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFI"
        threat_id = "2147624612"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 33 63 37 6d 79 63 35 39 [0-10] 5e 6a 6a 66 30 25 25 27 24 69 57 64 5d 6b 65 6d 5f 6b 69 5d 5c 27 26 26 26 26 24 59 64 25 66 65 69 6a 6e 58 63 25 66 65 69 6a 24 57 69 66}  //weight: 2, accuracy: Low
        $x_1_2 = "?gameType=qqsg&Zone=%s&Server=%s&Name=%s&password=%s&nickName=%s&Level=%s&Money=%s&secoPass=%s&MB=%s&Card=%s=%s|%s=%s|%s=%s&bankPass=%s&noRefreshCode=%s&hardInfo=%s&para=%s&ver=%s" ascii //weight: 1
        $x_1_3 = {7b 35 46 41 44 43 37 33 43 2d 33 43 45 32 2d 34 37 42 42 2d 42 43 43 36 2d 35 34 35 31 39 33 39 45 33 43 30 41 7d [0-10] 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_EY_2147624744_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.EY"
        threat_id = "2147624744"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 8d bd b8 f0 ff ff f3 a5 66 a5 b9 c9 03 00 00 33 c0 8d bd ce f0 ff ff 68 ?? ?? ?? ?? f3 ab 66 ab 8d 85 b8 f0 ff ff 68 ?? ?? ?? ?? 50 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "http://$1%s$1:%d%s?%s" ascii //weight: 1
        $x_1_3 = "%s$1%s$1*$1.dll" ascii //weight: 1
        $x_1_4 = "dri$1vers\\e$1tc\\hos$1ts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_NW_2147625025_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NW"
        threat_id = "2147625025"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ehsniffer.exe" ascii //weight: 10
        $x_10_2 = "ethereal.exe" ascii //weight: 10
        $x_10_3 = ":D:\\Backup\\" ascii //weight: 10
        $x_10_4 = "explorer.exe" ascii //weight: 10
        $x_10_5 = "{3C374A41-BAE4-11cf-bf7d-00aa006946ee}" ascii //weight: 10
        $x_10_6 = "tuiguangid" ascii //weight: 10
        $x_10_7 = "PowerRemind.exe" ascii //weight: 10
        $x_10_8 = "taskmgr.exe" ascii //weight: 10
        $x_5_9 = ".exe;" ascii //weight: 5
        $x_5_10 = "Accept-Language: zh-cn" ascii //weight: 5
        $x_5_11 = "Process32Next" ascii //weight: 5
        $x_100_12 = {3f 73 7a 63 6c 69 65 6e 74 69 64 3d 25 73 [0-21] 26 73 7a 6d 61 63 3d 25 73 [0-21] 26 73 7a 75 73 65 72 6e 61 6d 65 3d 25 73}  //weight: 100, accuracy: Low
        $x_100_13 = {26 73 7a 76 65 72 3d 25 73 [0-21] 26 6d 6f 64 65 3d 25 64 [0-21] 26 76 61 6c 75 65 3d 25 64 [0-21] 26 73 79 73 74 79 70 65 3d 25 64 [0-21] 26 73 7a 6e 61 6d 65 3d 25 73 [0-21] 26 73 7a 70 61 6e 61 6d 65 3d 25 73 [0-21] 26 70 61 6c 65 6e 3d 25 64}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 5 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FA_2147625252_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FA"
        threat_id = "2147625252"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b c0 90 90 8b d2}  //weight: 1, accuracy: High
        $x_2_2 = {8b 55 0c 8d 4d fc 51 57 52 53 56 ff 15 ?? ?? 40 00 85 c0 0f 84 ?? 00 00 00 b0 45 b1 61}  //weight: 2, accuracy: Low
        $x_1_3 = {b0 20 b1 73 88 45 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FB_2147625361_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FB"
        threat_id = "2147625361"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 7a 74 3d 77 61 69 [0-4] 61 63 74 69 6f 6e 3d 75 70 26 75 3d [0-8] 26 7a 74 3d 73 75 63 63 6d 62 68}  //weight: 10, accuracy: Low
        $x_10_2 = "SGCQ" ascii //weight: 10
        $x_1_3 = "wmgmb.asp" ascii //weight: 1
        $x_1_4 = "cgameasdfgh" ascii //weight: 1
        $x_1_5 = "gameqwerty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_E_2147625693_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.gen!E"
        threat_id = "2147625693"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 ?? ?? ?? ?? 6c 73 74 72 63 61 74 41 [0-128] 4c 6f 61 64 44 4c 4c 2e 64 6c 6c 00 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00 73 79 73 47 54 48 2e 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GD_2147625695_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GD"
        threat_id = "2147625695"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 78 65 00 77 2b 62}  //weight: 1, accuracy: High
        $x_1_2 = {49 44 52 5f 51 51 47 41 4d 45 [0-4] 42 49 4e 00 25 73}  //weight: 1, accuracy: Low
        $x_1_3 = {64 6f 77 6e 6c 6f 61 64 [0-4] 75 72 6c 25 64 [0-4] 25 73 5c 25 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_10_4 = {50 56 c7 44 24 18 28 01 ?? ?? e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 8d 4c 24 34 8d 54 24 0c 51 68 ?? ?? ?? ?? 52}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FC_2147625927_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FC"
        threat_id = "2147625927"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "qqlogin.exe" ascii //weight: 10
        $x_10_3 = "action=ok&u=" ascii //weight: 10
        $x_10_4 = "TenQQAccount" ascii //weight: 10
        $x_1_5 = "/mibao.asp" ascii //weight: 1
        $x_1_6 = "/gaibao.asp" ascii //weight: 1
        $x_1_7 = "/flash.asp" ascii //weight: 1
        $x_1_8 = "/mail.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FD_2147626141_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FD"
        threat_id = "2147626141"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 b8 c6 46 05 ff c6 46 06 e0 c6 46 07 00 8d 45 fc 50 6a 08}  //weight: 1, accuracy: High
        $x_1_2 = {8a 5c 10 ff 80 eb 7f 8d 45 f8 8b d3 e8 ?? ?? ff ff 8b 55 f8 8b c7 e8 ?? ?? ff ff ff 45 fc 4e 75 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_F_2147626711_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.gen!F"
        threat_id = "2147626711"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pufkspxr.dat ssygwre" ascii //weight: 1
        $x_1_2 = "c=%s&h=%d&v=%s&ep=%s&db=%d" ascii //weight: 1
        $x_1_3 = {25 64 2e 64 6c 6c 00 25 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {2e 74 6d 70 00 61 76 70 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_G_2147626712_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.gen!G"
        threat_id = "2147626712"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {65 6c 65 6d 65 6e 74 77 64 61 6f 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_2 = {6f 6e 6c 69 6e 65 00 00 69 73 6f 6e 6c 69 6e 65}  //weight: 1, accuracy: High
        $x_1_3 = "action=up&u=" ascii //weight: 1
        $x_1_4 = {63 6f 6e 74 72 6f 6c 00 73 65 72 76 65 72 3d 00 43 6f 6e 66 69 67 5c 63 6f 6e 66 69 67 2e 78 6d 6c}  //weight: 1, accuracy: High
        $x_1_5 = "cgameasdfgh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FK_2147626922_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FK"
        threat_id = "2147626922"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s?us=%s&ps=%s" ascii //weight: 1
        $x_1_2 = "polcore.dll" ascii //weight: 1
        $x_1_3 = "/ffxi/mail.asp" ascii //weight: 1
        $x_2_4 = {05 cb 4a 04 00 6a 01 50}  //weight: 2, accuracy: High
        $x_2_5 = {33 c0 80 7d ff e8 0f 94 c0}  //weight: 2, accuracy: High
        $x_3_6 = {c6 45 a8 60 c6 45 a9 6a c6 45 aa 1e c6 45 ab 8b}  //weight: 3, accuracy: High
        $x_2_7 = {bf e8 03 00 00 57 ff d6 57 eb fb 57 68}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FL_2147627026_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FL"
        threat_id = "2147627026"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 4a c7 04 24 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c7 04 83 c6 04 83 c3 04 ff 0c 24 75 cc}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 65 76 65 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 72 76 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_FM_2147627342_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FM"
        threat_id = "2147627342"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 6a 0d 8b c1 5b f7 f3 8d bc 0d 30 f9 ff ff 8a 82 ?? ?? ?? ?? 8b 55 0c 32 04 0a 32 07 32 c1 41 3b ce 88 07 7c ?? 8b 7d 08 33 db 53 53 53 ff 37 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = "wscntfy_mtx" wide //weight: 10
        $x_10_3 = "&morph_id=" ascii //weight: 10
        $x_1_4 = {6d 72 74 2e 65 78 65 [0-4] 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c [0-8] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FR_2147627366_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FR"
        threat_id = "2147627366"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 7a 68 75 6a 69 3d [0-16] 26 71 75 3d [0-16] 26 73 65 72 3d [0-16] 26 75 73 65 72 3d [0-16] 26 70 61 73 73 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 f9 02 78 11 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 10, accuracy: High
        $x_1_3 = "game.exe" ascii //weight: 1
        $x_1_4 = "qunithookdll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_DNF_2147627552_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DNF"
        threat_id = "2147627552"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 65 50 56 c6 45 ?? 55 c6 45 fd 56 c6 45 fe 42 88 5d ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 ff 15 ?? ?? 40 00 56 6a 00 43 ff d7 85 c0 75 07 83 fb 0a 7c e9 eb 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_DNG_2147627553_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.DNG"
        threat_id = "2147627553"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 1e 74 26 8b c9 8b d2 8b c9 8b c0 90 8b c9 8b c9 8b d2 8b c9 8b c0 90 8b c9 57 ff 16 59 85 c0 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 06 50 57 56 c6 45 f8 50 c6 45 f9 68 c6 45 fa f9 c6 45 fb e9 c6 45 fc be e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_FU_2147627574_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FU"
        threat_id = "2147627574"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&u=%s&p=%s&r=%s" ascii //weight: 1
        $x_1_2 = {61 63 74 69 6f 6e 3d 74 65 73 74 6c 6f 63 6b 26 75 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "action=getproc&u=%s" ascii //weight: 1
        $x_1_4 = "action=postmb&u=%s&mb=%s" ascii //weight: 1
        $x_2_5 = {2b c6 83 e8 05 89 46 01 8d 47 fb 50 68 90 00 00 00 8d 46 05}  //weight: 2, accuracy: High
        $x_3_6 = {81 7d f4 1c d7 53 56 74 0e}  //weight: 3, accuracy: High
        $x_1_7 = {74 10 8b c8 2b f0 8a 54 0e 01 47 41 84 d2 88 11 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_FZ_2147627951_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.FZ"
        threat_id = "2147627951"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 33 db 80 60 06 00 8b ca 88 50 01 8a de c1 e9 10 33 d2 88 58 02 8a d5 c6 00 ea 88 48 03 88 50 04 c6 40 05 1b 5b}  //weight: 2, accuracy: High
        $x_2_2 = {75 4c 53 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 8d 45 0f ff 35 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 14 80 7d 0f e8 75 27}  //weight: 2, accuracy: Low
        $x_1_3 = "%s?us=%s&ps=%s&lv=%s&se=%s&qu=%s&os=%s" ascii //weight: 1
        $x_1_4 = "%s?u=%s&m=%s&url=%s&action=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_BX_2147628357_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.BX"
        threat_id = "2147628357"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSAFD Tcpip [TCP/IP]" ascii //weight: 1
        $x_1_2 = {64 65 6c 2e 62 61 74 00 ff ff ff ff 07 00 00 00 3a 5f 64 65 6c 6d 65}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff 8b 55 fc 8b c3 b9 12 8d 40 00 e8 6d b2 ff ff 8b c3 8b d6 e8 b0 b4 ff ff 33 c0 5a 59 59 64 89 10 68 03 8d 40 00 8d 45 fc e8 8f af ff ff c3 e9 b1 a9 ff ff eb f0 5e 5b 59 5d c3 00 00 ff ff ff ff 06 00 00 00 72 6f 2e 64 6c 6c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NZ_2147628481_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NZ"
        threat_id = "2147628481"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 40 77 1b 00 76 9d}  //weight: 1, accuracy: High
        $x_1_2 = "CLsID\\{%s}\\" ascii //weight: 1
        $x_1_3 = "%s\\Tasks\\%s.ico" ascii //weight: 1
        $x_1_4 = "%s&PIN=%s" ascii //weight: 1
        $x_1_5 = "&F1=%s&F2=%s&F3=%s&F4=%s" ascii //weight: 1
        $x_1_6 = {78 00 00 00 65 00 00 00 2e 00 00 00 44 00 00 00 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_GH_2147628929_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GH"
        threat_id = "2147628929"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 d0 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b c7 e8 ?? ?? ?? ?? 43 81 e3 07 00 00 80 79 05}  //weight: 2, accuracy: Low
        $x_2_2 = {b3 08 8b fb 81 e7 ff 00 00 00 57 e8 ?? ?? ?? ?? 66 3d 01 80 0f 85 ?? ?? ?? ?? 33 c0 8a c3 83 f8 ?? 0f 8f ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 83 f8}  //weight: 2, accuracy: Low
        $x_2_3 = {74 68 65 66 74 5f 64 6e 66 2e 64 6c 6c 00 48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e 00 50 6f 73 74 55 52 4c}  //weight: 2, accuracy: High
        $x_1_4 = "set FtpFile=%temp%\\TempAcc.txt" ascii //weight: 1
        $x_1_5 = {63 3a 5c 57 49 4e 44 4f 57 53 5c 64 6e 66 70 61 74 68 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GH_2147628930_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GH"
        threat_id = "2147628930"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 3b f3 74 30 68 ?? ?? ?? ?? 6a 01 6a ff 6a 01 ff 15 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? 66 85 c0 6a 01 0f 85 ?? ?? ?? ?? 8d 55 ac 52 ff 15 ?? ?? ?? ?? eb e1}  //weight: 3, accuracy: Low
        $x_1_2 = "C:\\WINDOWS\\360_safe\\safe\\*.jpg" wide //weight: 1
        $x_1_3 = "C:\\WINDOWS\\360_safe\\sendmail.bat" wide //weight: 1
        $x_1_4 = "c:\\WINDOWS\\dnfpath.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GI_2147629324_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GI"
        threat_id = "2147629324"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 50 56 c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73}  //weight: 2, accuracy: Low
        $x_2_2 = {25 50 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c9 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 26 c6 45 ?? 73 c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 26}  //weight: 2, accuracy: Low
        $x_1_4 = {33 db c6 45 ?? 45 c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e c6 45 ?? 65}  //weight: 1, accuracy: Low
        $x_1_5 = "?a=%s&s=%s&u=%s&p=%s" ascii //weight: 1
        $x_1_6 = "pin=%s" ascii //weight: 1
        $x_1_7 = " __%s_%s_%d__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GL_2147629733_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GL"
        threat_id = "2147629733"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "&mb=kick" ascii //weight: 2
        $x_1_2 = {05 c0 bb 00 00 a3 ?? ?? ?? ?? 60 e8 ?? ?? ?? ?? 61 a1 ?? ?? ?? ?? 05 b8 b3 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {05 10 bf 00 00 a3 ?? ?? ?? ?? 60 e8 ?? ?? ?? ?? 61 a1 ?? ?? ?? ?? 05 08 b7 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 6a 09 50 8d 75 18 81 fb 44 24 0c 50 75 10 83 c2 03}  //weight: 1, accuracy: High
        $x_1_5 = {3d 8b ff 0f b6 75 18 81 fb 08 41 81 e1 75 10 83 ea 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GM_2147629963_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GM"
        threat_id = "2147629963"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUNIT" ascii //weight: 1
        $x_1_2 = "\\comresreal.dll" ascii //weight: 1
        $x_1_3 = "\\my_sfc_os.dll" ascii //weight: 1
        $x_2_4 = "hedgepig.dat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GM_2147629963_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GM"
        threat_id = "2147629963"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 37 8a 04 28 32 c2 74 04 88 06 eb 02 88 16 46 49 75 dd}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0c 07 32 0c 1a 40 4d 88 48 ff 75 e4}  //weight: 1, accuracy: High
        $x_1_3 = {68 65 64 67 65 70 69 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 65 73 74 44 6c 6c 2e 64 6c 6c 00 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00 53 65 74 49 6e 73 65 72 74 48 6f 6f 6b 00 55 6e 49 6e 73 65 72 74 48 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_ZFJ_2147630038_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.gen!ZFJ"
        threat_id = "2147630038"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 c6 45 e8 4c c6 45 e9 61 c6 45 ea 75 c6 45 eb 6e c6 45 ec 63 c6 45 ed 68 c6 45 ee 2e c6 45 ef 65 c6 45 f0 78 c6 45 f1 65 c6 45 d4 53 c6 45 d5 65 c6 45 d6 44 c6 45 d7 65 c6 45 d8 62 c6 45 d9 75 c6 45 da 67 c6 45 db 50 c6 45 dc 72 c6 45 dd 69 c6 45 de 76 c6 45 df 69 c6 45 e0 6c c6 45 e1 65 c6 45 e2 67 c6 45 e3 65 c6 45 f4 47 c6 45 f5 61 c6 45 f6 6d c6 45 f7 65 c6 45 f8 2e c6 45 f9 65 c6 45 fa 78 c6 45 fb 65 e8}  //weight: 10, accuracy: High
        $x_10_2 = {53 56 57 c6 45 e4 73 c6 45 e5 66 c6 45 e6 63 c6 45 e7 5f c6 45 e8 6f c6 45 e9 73 c6 45 ea 2e c6 45 eb 64 c6 45 ec 6c c6 45 ed 6c 80 65 ee 00 68 04 01 00 00 6a 00 68 c4 45 40 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_OnLineGames_ZFJ_2147630038_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.gen!ZFJ"
        threat_id = "2147630038"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 5d 90 c6 45 94 53 c6 45 95 68 c6 45 96 49 c6 45 97 6d c6 45 98 67 c6 45 99 56 c6 45 9a 77 c6 45 9b 3a c6 45 9c 43 c6 45 9d 50 c6 45 9e 72 c6 45 9f 65 c6 45 a0 76 c6 45 a1 69 c6 45 a2 65 c6 45 a3 77 c6 45 a4 57 c6 45 a5 6e c6 45 a6 64 88 5d a7 c6 45 b8 65 c6 45 b9 78 c6 45 ba 70 c6 45 bb 6c c6 45 bc 6f c6 45 bd 72 c6 45 be 65 c6 45 bf 72 c6 45 c0 2e c6 45 c1 65 c6 45 c2 78 c6 45 c3 65 88 5d c4}  //weight: 10, accuracy: High
        $x_10_2 = {ff 75 a4 c6 45 ac 25 c6 45 ad 73 c6 45 ae 3f 50 8d 85 a0 fd ff ff 50 c6 45 af 61 c6 45 b0 63 c6 45 b1 74 c6 45 b2 69 c6 45 b3 6f c6 45 b4 6e c6 45 b5 3d c6 45 b6 64 c6 45 b7 72 c6 45 b8 6f c6 45 b9 70 c6 45 ba 6f c6 45 bb 66 c6 45 bc 66 c6 45 bd 26 c6 45 be 75 c6 45 bf 3d c6 45 c0 25 c6 45 c1 73 88 5d c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_OnLineGames_GP_2147630479_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GP"
        threat_id = "2147630479"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {60 be 00 c0 40 00 8d be ?? ?? ?? ?? 57 [0-16] 90 90 90 90 8a 06 46 88 07 47 01 db 75}  //weight: 2, accuracy: Low
        $x_2_2 = {81 7d f0 2a 7b 5a 13 0f 85}  //weight: 2, accuracy: High
        $x_2_3 = {81 7d f4 2a 7b 5a 13 74}  //weight: 2, accuracy: High
        $x_3_4 = {74 10 8b c8 2b f0 8a 54 0e 01 47 41 84 d2 88 11 75 f4}  //weight: 3, accuracy: High
        $x_3_5 = {05 ec 00 00 00 50 e8 ?? ?? ?? ?? c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 26 c6 45 ?? 73 c6 45 ?? 3d c6 45 ?? 25}  //weight: 3, accuracy: Low
        $x_3_6 = {25 50 8d 86 ?? ?? ?? ?? 50 8d 45 ?? 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GS_2147630892_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GS"
        threat_id = "2147630892"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 43 42 74 72 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 fb 41 50 33 32 75 3d 8b 5e 04 83 fb 18 72 35}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 52 ff d5 8b 84 24 9c 00 00 00 6a 00 50 57 ff d3 57 6a 01 8d 8c 24 b4 00 00 00 68 f8 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GT_2147630924_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GT"
        threat_id = "2147630924"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&mb=kick" ascii //weight: 1
        $x_1_2 = {3d 3b 91 10 02 75 18 81 fb 00 00 7e 0e 75 10 83 ea 1c}  //weight: 1, accuracy: High
        $x_1_3 = {eb 08 eb 06 aa e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GU_2147631019_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GU"
        threat_id = "2147631019"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 25 73 7d 00 00 00 00 50 41 53 53 5f 4e 4f 44 33 32 5f 4f 4b 00 00 00 5f 4c 4f 41 44 4c 49 42 52 41 52 59 5f 44 55 4d 4d 59 00 00 25 73 2e 66 6f 6e 00 00 25 73 5c 66 6f 6e 74 73 5c 25 73 2e 66 6f 6e 00 25 73 5c 73 79 73 74 65 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GK_2147631022_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GK"
        threat_id = "2147631022"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kick.ashx?username=" ascii //weight: 10
        $x_10_2 = "bankpassword.aspx?username=" ascii //weight: 10
        $x_10_3 = "cash.aspx?username=" ascii //weight: 10
        $x_10_4 = "yuanbao.aspx?username=" ascii //weight: 10
        $x_10_5 = "mibaopicture.aspx?username=" ascii //weight: 10
        $x_10_6 = "mibao.aspx?username=" ascii //weight: 10
        $x_1_7 = "Microsoft Office Picture Manager" ascii //weight: 1
        $x_1_8 = "Microsoft Photo Editor" ascii //weight: 1
        $x_1_9 = "IrfanView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_GU_2147631034_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GU!dll"
        threat_id = "2147631034"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/c.asp?do=tr&c=q&i=%s&a=%s&s=%s&m=%s" ascii //weight: 1
        $x_1_2 = "/uploadimg.asp?FileName=" ascii //weight: 1
        $x_1_3 = "rundll32 shell32,Control_RunDLL \"%s\"" ascii //weight: 1
        $x_1_4 = "idleprocmutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GU_2147631171_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GU"
        threat_id = "2147631171"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 62 61 6e 6b 70 61 73 73 77 6f 72 64 3d [0-5] 62 61 6e 6b 70 61 73 73 77 6f 72 64 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {26 66 69 72 73 74 3d 00 6d 69 62 61 6f 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d}  //weight: 1, accuracy: High
        $x_1_3 = {26 72 61 6e 6b 3d [0-5] 26 70 77 64 3d [0-5] 26 75 73 65 72 6e 61 6d 65 3d [0-5] 26 73 65 72 76 65 72 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "kick.ashx?username=" ascii //weight: 1
        $x_1_5 = {79 6f 75 20 61 72 65 20 6b 69 63 6b 65 64 [0-5] 79 6f 75 20 61 72 65 20 70 72 65 70 6f 62 61 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_GV_2147631198_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GV"
        threat_id = "2147631198"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/pobao/GetTuPian.asp" ascii //weight: 1
        $x_1_2 = "?A=%s&B=%s&E=%s&I=%s" ascii //weight: 1
        $x_2_3 = {6a 04 6a 30 68 b0 2f 4b 00}  //weight: 2, accuracy: High
        $x_2_4 = {3d 56 8b 74 24 74 0f 68 e8 03 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZFK_2147632053_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFK"
        threat_id = "2147632053"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f0 57 50 53 c6 45 f1 6f c6 45 f2 72 c6 45 f3 6c c6 45 f4 64}  //weight: 1, accuracy: High
        $x_1_2 = "%s?action=postmb&u=%s&mb=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GZ_2147632054_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GZ"
        threat_id = "2147632054"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6c 4d 61 69 6e 2e 64 6c 6c 00 4d 79 44 6c 6c 52 75 6e 00 53 65 72 76 69 63 65 4d 61 69 6e 00 58 69 65 5a 61 69 44 4c 4c}  //weight: 1, accuracy: High
        $x_1_2 = "www.xiaohua.kr:8001" ascii //weight: 1
        $x_1_3 = "NetBot Attacker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_GZ_2147632054_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.GZ"
        threat_id = "2147632054"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM32\\hf0021.dll" ascii //weight: 1
        $x_1_2 = {73 65 74 68 6f 6f 6b 65 20 3d 20 25 30 38 78 00 53 65 74 48 6f 6f 6b}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 25 73 3f 64 66 75 3d 25 73 26 64 66 70 3d 25 73 26 64 66 70 32 3d 25 73 26 64 66 6e 3d 25 73 00 00 53 45 4c 45 43 54 20 53 45 52 56 45 52 00 00 00 2e 5c 44 4e 46 2e 63 66 67}  //weight: 1, accuracy: High
        $x_1_4 = {6c 6f 67 69 6e 6e 61 6d 65 3d 64 66 00 00 00 00 26 73 74 72 50 61 73 73 77 6f 72 64 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HG_2147632467_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HG!dll"
        threat_id = "2147632467"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 66 30 30 32 31 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = {73 65 74 68 6f 6f 6b 65 20 3d 20 25 30 38 78 00}  //weight: 2, accuracy: High
        $x_2_3 = {2e 5c 44 4e 46 2e 63 66 67 00}  //weight: 2, accuracy: High
        $x_1_4 = {26 73 65 63 75 6c 6f 67 69 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 73 74 72 50 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_NN_2147632541_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NN"
        threat_id = "2147632541"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 4d 5f 25 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 86 74 0e 05 00 81 7d ?? 52 90}  //weight: 1, accuracy: Low
        $x_1_3 = {47 65 74 50 c7 45 ?? 72 6f 63 41 c7 45 ?? 64 64 72 65 c7 45 ?? 73 73 00 00 89 45 ?? 89 45 ?? 60 64 a1 30 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {89 03 8b 46 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 66 ff 40 06 8b 17 8b 4e 18 8b 52 0c 8b 41 28 89 51 28 8b 0f 2b 41 0c 2d 22 01 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 5c 56 aa c6 45 ?? 5c c6 45 ?? 73 c6 45 ?? 79 c6 45 ?? 73 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 6d c6 45 ?? 5c}  //weight: 1, accuracy: Low
        $x_2_6 = {3f 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d}  //weight: 2, accuracy: Low
        $x_2_7 = {25 73 3f 61 63 74 69 6f 6e 3d 74 65 73 74 6c 6f 63 6b 26 75 3d 25 73 [0-37] 25 73 3f 61 63 74 69 6f 6e 3d 67 65 74 70 72 6f 63}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZFL_2147632598_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFL"
        threat_id = "2147632598"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 53 6a 10 57 ff d6 53 53 6a 12 57 ff d6 53 53}  //weight: 1, accuracy: High
        $x_1_2 = {64 62 72 25 30 32 78 2a 2e ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 5f 5f 25 73 5f 25 73 5f 25 64 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5f 5f 25 73 5f 25 64 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFL_2147632598_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFL"
        threat_id = "2147632598"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dnf.exe" ascii //weight: 1
        $x_1_2 = "dsound010.DirectSoundCaptureCreate" ascii //weight: 1
        $x_1_3 = {f2 ae f7 d1 49 51 8d 8c 24 ?? ?? ?? ?? 68 ?? ?? 00 10 51 ff 15 ?? ?? 00 10 5f 5e 85 c0 75 0b 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 33 c0 81 c4 08 02 00 00 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HI_2147632711_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HI"
        threat_id = "2147632711"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 3
        $x_3_2 = "SFCDisable" ascii //weight: 3
        $x_3_3 = "InternetReadFile" ascii //weight: 3
        $x_1_4 = "/kickout.asp" ascii //weight: 1
        $x_1_5 = "act=online&Name=%s" ascii //weight: 1
        $x_1_6 = "%s\\soso.bmp" ascii //weight: 1
        $x_1_7 = "%s\\soso.dat" ascii //weight: 1
        $x_1_8 = "%sJackson.bat" ascii //weight: 1
        $x_1_9 = "\\start\\usersetting.ini" ascii //weight: 1
        $x_1_10 = "blink" ascii //weight: 1
        $x_1_11 = "secondpass" ascii //weight: 1
        $x_1_12 = "password" ascii //weight: 1
        $x_1_13 = "dnf.exe" ascii //weight: 1
        $x_1_14 = "qqlogin.exe" ascii //weight: 1
        $x_1_15 = "Accept-Language: zh-cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_3_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_HJ_2147632804_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HJ"
        threat_id = "2147632804"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d d8 6a 00 6a 00 6a 01 6a 01 51 8d 4d a4 c6 45 e3 00 c6 45 fc 15 e8 ?? ?? ?? ?? 8b 10 8d 4d e8 51 8b c8 ff 52 60}  //weight: 1, accuracy: Low
        $x_1_2 = {3f 74 6f 6e 67 6a 69 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 74 70 6d 64 35 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "jdyou.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_NO_2147632809_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NO"
        threat_id = "2147632809"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 50 56 c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73}  //weight: 2, accuracy: Low
        $x_2_2 = {73 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 1c 03 32 da 88 18 40 ff 4d ?? 89 45 ?? 75 ad}  //weight: 2, accuracy: Low
        $x_1_4 = "%s?action=testlock&u=%s" ascii //weight: 1
        $x_1_5 = "%s?action=dropoff&u=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_HL_2147632875_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HL"
        threat_id = "2147632875"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MAPLESTORY.EXE" ascii //weight: 10
        $x_2_2 = "POST %s?path=%s" ascii //weight: 2
        $x_2_3 = "InstallHOOK" ascii //weight: 2
        $x_2_4 = "%s?action=getma&u=%s" ascii //weight: 2
        $x_1_5 = "getmoneyevent" ascii //weight: 1
        $x_1_6 = "getpassevent" ascii //weight: 1
        $x_1_7 = "got money:%s" ascii //weight: 1
        $x_1_8 = "in getmoney thread" ascii //weight: 1
        $x_1_9 = "upload %s" ascii //weight: 1
        $x_1_10 = "getp.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_HL_2147632875_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HL"
        threat_id = "2147632875"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POST %s?path=%s" ascii //weight: 1
        $x_1_2 = "%s?action=getma&u=%s" ascii //weight: 1
        $x_1_3 = "%s?action=setmp&mp=%s&u=%s" ascii //weight: 1
        $x_1_4 = "money:%d" ascii //weight: 1
        $x_1_5 = {26 6d 3d 00 26 70 3d 00 26 75 3d 00 3f 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "user:%s pass:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_HM_2147632939_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HM"
        threat_id = "2147632939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "DNF.exe" wide //weight: 2
        $x_2_2 = "HOOK" wide //weight: 2
        $x_2_3 = {64 00 65 00 6c 00 [0-11] 69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 [0-11] 67 00 6f 00 74 00 6f 00}  //weight: 2, accuracy: Low
        $x_1_4 = "&password2=" ascii //weight: 1
        $x_1_5 = "&money=" ascii //weight: 1
        $x_1_6 = "&level=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HS_2147633077_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HS"
        threat_id = "2147633077"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c %s %s,%s %s" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Blizzard Entertainment\\World of Warcraft" ascii //weight: 1
        $x_1_3 = "winowater.exe" ascii //weight: 1
        $x_1_4 = "RavMonD.exe" ascii //weight: 1
        $x_1_5 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_HS_2147633077_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HS"
        threat_id = "2147633077"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "G am virus! Fuck you :-)" ascii //weight: 1
        $x_1_2 = "yes && net user guest 124277668 && net" ascii //weight: 1
        $x_1_3 = "Super-X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HS_2147633077_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HS"
        threat_id = "2147633077"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 80 34 11 19 [0-8] 41 3b c8 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "wINDOWS nt\\cURRENTvERSION\\sVCHOST" ascii //weight: 1
        $x_1_3 = "%sYSTEMrOOT%\\sYSTEM32\\SVCHOST.EXE -K NETSVCS" ascii //weight: 1
        $x_1_4 = "SuperX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KG_2147634343_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KG"
        threat_id = "2147634343"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUID_SysKeyboard" ascii //weight: 1
        $x_1_2 = "SHELLHOOK" ascii //weight: 1
        $x_1_3 = "/c del" ascii //weight: 1
        $x_1_4 = "\\DNF" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HT_2147634382_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HT"
        threat_id = "2147634382"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\start\\DNFchina.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Tencent\\DNF\\JinShaILoveYou" ascii //weight: 1
        $x_1_3 = "\\start\\DNFComponent.DLL" ascii //weight: 1
        $x_1_4 = "DNF.exe" ascii //weight: 1
        $x_1_5 = "QQLogin.exe" ascii //weight: 1
        $x_1_6 = ".sousuo100.com:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_HU_2147634459_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HU"
        threat_id = "2147634459"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "kick.ashx?" ascii //weight: 1
        $x_1_2 = "bankpassword.aspx?username=" ascii //weight: 1
        $x_1_3 = "cash.aspx?" ascii //weight: 1
        $x_1_4 = "yuanbao.aspx?" ascii //weight: 1
        $x_1_5 = "mibaopicture.aspx?username=" ascii //weight: 1
        $x_1_6 = "mibao.aspx?username=" ascii //weight: 1
        $x_1_7 = {26 66 69 72 73 74 3d 00 6d 69 62 61 6f 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d}  //weight: 1, accuracy: High
        $x_1_8 = {26 72 61 6e 6b 3d [0-5] 26 70 77 64 3d [0-5] 26 75 73 65 72 6e 61 6d 65 3d [0-5] 26 73 65 72 76 65 72 3d}  //weight: 1, accuracy: Low
        $x_1_9 = "qqlogin.exe" ascii //weight: 1
        $x_1_10 = "Host: ilovedxc5.blog.163.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_Win32_OnLineGames_HW_2147634545_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HW"
        threat_id = "2147634545"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\start\\DNFchina.exe" ascii //weight: 1
        $x_1_2 = "cmd /c erase /F" ascii //weight: 1
        $x_1_3 = "\\start\\DNFComponent.DLL" ascii //weight: 1
        $x_1_4 = "DNF.exe" ascii //weight: 1
        $x_1_5 = "QQLogin.exe" ascii //weight: 1
        $x_1_6 = "qq.update.sousuo100.com:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_HX_2147634584_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.HX!dll"
        threat_id = "2147634584"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(*^__^*)" wide //weight: 1
        $x_1_2 = "?d80=2&d10=" wide //weight: 1
        $x_1_3 = "&h=%d&m=%d" wide //weight: 1
        $x_1_4 = "?a=%s&b=%s&c=%s&e=%s&d=%d&f=%d&l=%s&mbh=%s" wide //weight: 1
        $x_1_5 = "?a=%s&b=%s&c=%s&mbh=" wide //weight: 1
        $x_1_6 = "&%s=%s&%s=%s&%s=%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IB_2147636752_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IB"
        threat_id = "2147636752"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DNF.exe" ascii //weight: 2
        $x_1_2 = "User-Agent: Mozilla/4.0" ascii //weight: 1
        $x_3_3 = {8b 44 24 08 8a da 03 c2 f6 d3 32 18 32 d9 42 3b 54 24 0c 88 18 7c e9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_IB_2147636752_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IB"
        threat_id = "2147636752"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 54 4d 42 3a 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 41 53 41 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 6a 61 76 61 5c 74 72 75 73 74 6c 69 62 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "?do=tr&c=q&i=%s" ascii //weight: 1
        $x_2_5 = {83 f8 03 74 05 83 f8 04 75 ?? 68 20 40 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_IB_2147636752_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IB"
        threat_id = "2147636752"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 63 20 63 6f 6e 66 69 67 20 63 72 79 70 74 73 76 63 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 00 00 6e 65 74 20 73 74 6f 70 20 63 72 79 70 74 73 76 63 00 00 00 6d 6d 67 6c 25 64 2e 64 6c 6c 00 00 25 73 64 6c 6c 63 61 63 68 65 5c 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 68 6c fb ff ff 56 ff 15 ?? ?? ?? ?? 56 68 94 04 00 00 6a 01}  //weight: 1, accuracy: Low
        $x_1_3 = {59 85 c0 59 74 4f 8b 0d ?? ?? ?? ?? 47 81 c5 04 01 00 00 3b f9 7c e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_IB_2147636752_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IB"
        threat_id = "2147636752"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "|miniie.exe|360se.exe|" ascii //weight: 1
        $x_1_2 = "|firefox.exe|maxthon.exe|ttraveler.exe" ascii //weight: 1
        $x_1_3 = {2e 61 73 70 3f 64 6f 3d 63 68 65 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 6f 6c 64 5f 63 6f 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {3f 55 73 65 72 4e 61 6d 65 3d [0-16] 26 50 61 73 73 77 6f 72 64 3d [0-16] 26 50 [0-16] 6e 61 6d 65 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {26 63 61 72 64 70 61 73 73 3d [0-16] 26 63 61 72 64 6e 75 6d 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_IA_2147636881_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IA!dll"
        threat_id = "2147636881"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\dmlq.ini" ascii //weight: 1
        $x_1_2 = "boundary=---------------------------j34890jks09u83" ascii //weight: 1
        $x_1_3 = "%s?act=getpos&d10=%s&pos=&d80=%d" ascii //weight: 1
        $x_1_4 = "%s\\dllcache\\%s_%d.jpg" ascii //weight: 1
        $x_1_5 = "%s\\system%d.exe" ascii //weight: 1
        $x_1_6 = {b4 f3 c3 f7 c1 fa c8 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_ID_2147637025_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ID!dll"
        threat_id = "2147637025"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "act=online&Name=%s" ascii //weight: 1
        $x_1_2 = "%sJackson.bat" ascii //weight: 1
        $x_1_3 = {64 6e 66 2e 65 78 65 00 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 5c 50 72 65 6c 6f 61 64}  //weight: 1, accuracy: High
        $x_1_4 = {71 71 6c 6f 67 69 6e 2e 65 78 65 00 25 73 5c 73 6f 73 6f 2e 62 6d 70 00 25 73 5c 73 6f 73 6f 2e 64 61 74 00 73 35 61 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IE_2147637026_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IE!dll"
        threat_id = "2147637026"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTTP/%*d.%*d %d" ascii //weight: 1
        $x_1_2 = {b5 d8 cf c2 b3 c7}  //weight: 1, accuracy: High
        $x_1_3 = {25 64 00 00 4c 76 2e 25 64 00 00 00 bd f0 b1 d2}  //weight: 1, accuracy: High
        $x_1_4 = {26 6c 6f 6f 6b 3d 00 00 26 67 6f 6c 64 3d 00 00 26 6c 6f 63 6b 3d 00 00 26 72 6f 6c 65 3d 00 00 26 6e 61 6d 65 3d}  //weight: 1, accuracy: High
        $x_1_5 = {26 78 78 78 78 3d 00 00 26 75 73 65 72 3d 00 00 26 6c 69 6e 65 3d 00 00 26 73 69 67 6e 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_II_2147637248_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.II"
        threat_id = "2147637248"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YYDNF.TenEdit" ascii //weight: 1
        $x_1_2 = "\\System32\\rthsvc.exe" wide //weight: 1
        $x_1_3 = "\\TMP09DB09E.JPG" wide //weight: 1
        $x_1_4 = {64 00 6e 00 66 00 2e 00 61 00 73 00 70 00 00 00 16 00 00 00 6d 00 61 00 69 00 6c 00 2e 00 61 00 73 00 70 00 3f 00 64 00 3d 00 00 00 06 00 00 00 3c 00 23 00 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IJ_2147637249_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IJ!dll"
        threat_id = "2147637249"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\%s%d.gif" ascii //weight: 1
        $x_1_2 = "mibaoshou" ascii //weight: 1
        $x_1_3 = "JMV_VMJ" ascii //weight: 1
        $x_1_4 = "-----------------------------7d83c8277088c" ascii //weight: 1
        $x_1_5 = "/pobao/GetTuPian.asp" ascii //weight: 1
        $x_1_6 = {b5 d8 cf c2 b3 c7 d3 eb d3 c2 ca bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_IC_2147637487_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IC"
        threat_id = "2147637487"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 07 e8 2b c7 83 e8 05 89 47 01 8a 45 0b 3c 68 88 47 05 74 0e 3c a3}  //weight: 2, accuracy: High
        $x_1_2 = "%s?act=getpos&d10" ascii //weight: 1
        $x_1_3 = "%s\\dllcache\\%s_%d.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KH_2147637521_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KH"
        threat_id = "2147637521"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 05 c6 00 e9 40 53 bb ?? ?? 00 10 2b d8 83 eb 04 89 18 5b}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 52 6a 00 6a 5a ff 15 ?? ?? ?? 10 c6 44 24 13 01 68 30 75 00 00 ff 15 ?? ?? ?? 10 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "http://%s:%s/pobao/GetTuPian.asp" ascii //weight: 1
        $x_1_4 = "%sbline.asp%s" ascii //weight: 1
        $x_1_5 = "WINDOWS\\SYSTEM32\\MSWC.ime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_IP_2147637802_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IP"
        threat_id = "2147637802"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killmb" ascii //weight: 1
        $x_1_2 = "/GetGif.asp" ascii //weight: 1
        $x_1_3 = "/lin.asp?RE=%s&s=%s&a=%s&p=%s&z=%d&NO=%s" ascii //weight: 1
        $x_1_4 = "/lin.asp?s=%s&a=%s&R=%s&RG=%d&" ascii //weight: 1
        $x_1_5 = "/mb.asp?a=postmb&u=%s&mb=%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KK_2147638078_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KK"
        threat_id = "2147638078"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f4 25 c6 45 f5 73 c6 45 f6 26 c6 45 f7 70 c6 45 f8 73 c6 45 f9 3d c6 45 fa 25 c6 45 fb 73 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {80 65 ff 00 c6 45 f8 77 c6 45 f9 6f c6 45 fa 77 c6 45 fb 2e c6 45 fc 65 c6 45 fd 78 c6 45 fe 65 e8}  //weight: 1, accuracy: High
        $x_1_3 = {74 50 68 04 01 00 00 c6 45 ?? 74 c6 45 ?? 63 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 67 c6 45 ?? 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {57 50 c6 45 ?? 54 c6 45 ?? 46 c6 45 ?? 5c c6 45 ?? 43 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 66}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 03 53 6a 01 66 ab 68 00 00 00 80 c6 45 ?? 72 ff 75 08 c6 45 ?? 65 aa c6 45 ?? 61 c6 45 ?? 6c c6 45 ?? 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_IR_2147638141_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IR"
        threat_id = "2147638141"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thebiggay" ascii //weight: 1
        $x_1_2 = "OHOHWEWEARE0." ascii //weight: 1
        $x_1_3 = "RXJH_KICKARSE0." ascii //weight: 1
        $x_1_4 = "DIALER USER.EXE" ascii //weight: 1
        $x_1_5 = {20 78 79 32 2e 65 78 65 20 2f 66 0d 0a 64 65 6c 20 25 30}  //weight: 1, accuracy: High
        $x_1_6 = {b4 f3 bb b0 ce f7 d3 ce 20 49 49 20 28 24 52 65 76 69 73 69 6f 6e 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_IS_2147638142_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IS"
        threat_id = "2147638142"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?a=postmb&u=%s&mb=%" ascii //weight: 1
        $x_1_2 = {3f 73 3d 25 73 26 61 3d 25 73 26 ?? 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 f4 83 c4 0c 50 58 5d 33 db 89 5d e4 c6 45 dc 57 c6 45 dd 69 c6 45 de 6e c6 45 df 49 c6 45 e0 6e c6 45 e1 65 c6 45 e2 74 88 5d e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IT_2147638307_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IT"
        threat_id = "2147638307"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ReadProcessMemory" ascii //weight: 3
        $x_2_2 = "&TB_CardPassword2=" ascii //weight: 2
        $x_1_3 = "userdata\\currentserver.ini" ascii //weight: 1
        $x_1_4 = "Element Client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_IT_2147638307_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IT"
        threat_id = "2147638307"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\dinput8_.dll" ascii //weight: 1
        $x_1_2 = {b0 73 c6 44 24 39 66 52 88 44 24 3c c6 44 24 3e 63 c6 44 24 3f 5f c6 44 24 40 6f 88 44 24 41 c6 44 24 42 2e c6 44 24 43 64 c6 44 24 44 6c c6 44 24 45 6c 88 5c 24 46 ff}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 2c 6c c6 44 24 2d 7a c6 44 24 2e 67 c6 44 24 2f 2e 88 ?? 24 ?? 88 ?? 24 33 89 ?? 24 3c c6 44 24 18 6c c6 44 24 19 7a c6 44 24 1a 67 c6 44 24 1b 31 c6 44 24 1c 2e 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IU_2147638366_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IU"
        threat_id = "2147638366"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 ea 00 00 c7 44 24 ?? 00 00 00 00 c7 44 24 ?? d8 c4 c4 c0 c7 44 24 ?? bf a1 be a1 c7 44 24 ?? b0 a2 a0 a0 c7 44 24 ?? 90 90 90 90 c7 44 24 ?? d7 d5 c4 90 c7 44 24 ?? d1 f3 f3 f5}  //weight: 1, accuracy: Low
        $x_1_2 = "205.209.161.110" ascii //weight: 1
        $x_1_3 = {54 4e 53 48 [0-10] 2d 53 51 59 50 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IV_2147638918_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IV"
        threat_id = "2147638918"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 6b 66 68 67 35 36 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c c3 c0 c3 bc 2e 6a 70 67 2a}  //weight: 1, accuracy: High
        $x_1_3 = {5c ce d2 b5 c4 cf e0 c6 ac [0-1] 2e 65 78 65 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 c3 c0 a6 b0 f3 c6 f7 bf c9 d2 d4 c0 a6 b0 f3 c8 ce ba ce d0 ce ca bd b5 c4 ce c4 bc fe a3 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IW_2147638944_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IW"
        threat_id = "2147638944"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {83 c2 41 71 05 e8 ?? ?? ?? ?? 88 50 01 c6 00 01 8d 55 f4 8d 45 f0 e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 45 f0 b1 02 e8 ?? ?? ?? ?? 8d 55 f0 8d 45 fc e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 e8 03}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 ff 00 00 00 e8 ?? ?? ?? ?? 8b d8 53 68 ff 00 00 00 6a 0d a1 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IX_2147639321_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IX"
        threat_id = "2147639321"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fvcwet" ascii //weight: 1
        $x_1_2 = "\\toypedle.dll" ascii //weight: 1
        $x_1_3 = "!@#*(^#@$@!!*@" ascii //weight: 1
        $x_1_4 = {26 78 79 33 3d 00 26 78 79 32 3d 00 26 78 79 31 3d 00 26 50 4e 61 6d 65 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IY_2147639572_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IY"
        threat_id = "2147639572"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 21 01 00 a1 ?? ?? ?? ?? 3b c3 56 8b 35 ?? ?? ?? ?? 74 09 50 ff d6 89 1d}  //weight: 1, accuracy: Low
        $x_1_2 = "DarkStoryOnline" ascii //weight: 1
        $x_1_3 = "@GameHook.DLL" ascii //weight: 1
        $x_1_4 = "http://xuanbbs.net/bbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KB_2147639598_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KB"
        threat_id = "2147639598"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 60 2b ?? c6 40 01 54 83 ?? 07 c6 40 02 e8 89 ?? 03 c6 40 07 61}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ea 05 89 54 24 04 8b 54 24 14 2b d0 c6 00 e9 83 ea 05}  //weight: 1, accuracy: High
        $x_1_3 = "senduser=%s&receiveuser=%s&money=%s" ascii //weight: 1
        $x_1_4 = {00 73 74 72 70 61 73 73 77 6f 72 64 3d}  //weight: 1, accuracy: High
        $x_1_5 = "U=%s+P=%s+P2=%s+S=MS+A=%s+R=%s+G=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_IQ_2147639609_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IQ!dll"
        threat_id = "2147639609"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 53 c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65}  //weight: 1, accuracy: Low
        $x_1_2 = {50 53 c6 45 ?? 74 c6 45 ?? 66 c6 45 ?? 6d c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 45 08 80 65 ?? 00 a3 ?? ?? ?? ?? c6 45 ?? 4b c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c}  //weight: 2, accuracy: Low
        $x_2_4 = {43 50 c6 45 ?? 72 ff 75 ?? c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 54 c6 45 ?? 68 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 64 88 5d}  //weight: 2, accuracy: Low
        $x_2_5 = "/wsidny.asp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KL_2147639886_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KL"
        threat_id = "2147639886"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 50 ff 83 e8 02 88 51 ff 8a 50 02 88 11 8d 14 06 83 c1 02 85 d2 7f e8}  //weight: 1, accuracy: High
        $x_1_2 = {00 65 39 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KM_2147639887_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KM"
        threat_id = "2147639887"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 6c 68 cc 00 00 00 50 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {6a 14 c1 fe 08 83 e6 01 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {00 54 57 49 4e 43 4f 4e 54 52 4f 4c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 4e 46 63 68 69 6e 61 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IZ_2147640393_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IZ"
        threat_id = "2147640393"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2}  //weight: 1, accuracy: High
        $x_1_2 = {83 ff 78 0f 82 ?? ?? ?? ?? 83 fe 64 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 04 3b e9 8b c6 2b c3 83 e8 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JA_2147640563_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JA"
        threat_id = "2147640563"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 32 c0 88 45 ?? c6 45 ?? 61 c6 45 ?? 6c c6 45 ?? 67 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78}  //weight: 1, accuracy: Low
        $x_1_2 = {57 ff 75 08 c6 45 ?? 6f c6 45 ?? 77 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65}  //weight: 1, accuracy: Low
        $x_1_3 = {72 02 73 00 [0-1] 61 80 65 ?? 00 8d 45 ?? 50 c6 45 ?? 57 ff 75 ?? c6 45 ?? 53 c6 45 ?? 50 c6 45 ?? 53 c6 45 ?? 74 c6 45 ?? 61 c6 45 ?? 72 c6 45 ?? 74 c6 45 ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 5c 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 88 58 01 c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 72 c6 85 ?? ?? ?? ?? 64 c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_JB_2147640658_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JB"
        threat_id = "2147640658"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 50 56 c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73}  //weight: 2, accuracy: Low
        $x_2_2 = {3f 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d}  //weight: 2, accuracy: Low
        $x_1_3 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2}  //weight: 1, accuracy: High
        $x_2_4 = {3f 5b c6 45 ?? 64 c6 45 ?? ?? c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73}  //weight: 2, accuracy: Low
        $x_1_5 = "%s/bmp/%s_mibaoka.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_JC_2147640804_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JC"
        threat_id = "2147640804"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\bin\\gameclient.exe" ascii //weight: 1
        $x_1_2 = "%s\\%d%d_res.tmp" ascii //weight: 1
        $x_1_3 = "vcd.exe" ascii //weight: 1
        $x_2_4 = {6a 40 52 03 f0 56 51 ff 15 ?? ?? ?? ?? 8b 4c 24 1c 8b 44 24 24 83 c1 28 48 89 4c 24 1c 89 44 24 24 75 95 8b 8c 24 5c 02 00 00 8d 54 24 28 52 8b 54 24 10 6a 04 8d 44 24 28 50 83 c1 08 51 52 c7 84 24 cc 01 00 00 07 00 01 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 5b fe ff ff 8b 44 24 20 8b 8c 24 e8 00 00 00 03 c8 8b 44 24 10 8d 94 24 b8 01 00 00 52 50 89 8c 24 70 02 00 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JD_2147640813_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JD"
        threat_id = "2147640813"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b0 6c 52 c6 44 24 ?? 66 c6 44 24 ?? 63 c6 44 24 ?? 5f c6 44 24 ?? 6f c6 44 24 ?? 2e c6 44 24 ?? 64 88 44 24 ?? 88 44 24 ?? 88 5c 24}  //weight: 2, accuracy: Low
        $x_1_2 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" ascii //weight: 1
        $x_1_3 = "Content-Disposition: form-data; name=\"upload\"" ascii //weight: 1
        $x_1_4 = "Content-Type: multipart/form-data; boundary=---------------------------7d9cb310484" ascii //weight: 1
        $x_1_5 = "%s&a=%s&u=%s&p=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_IW_2147640823_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IW!dll"
        threat_id = "2147640823"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 1f 00 00 e8 ?? ?? ff ff a1 f8 c3 40 00 80 38 01 0f 84 ?? ?? ff ff 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "dNlAuNchEr.exE" ascii //weight: 1
        $x_1_3 = "C6-80-CD-00-00-00-01-" ascii //weight: 1
        $x_1_4 = {06 48 61 63 6b 65 72 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IY_2147641111_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IY!dll"
        threat_id = "2147641111"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 2c 52 c6 44 24 2e 61 c6 44 24 2f 64 c6 44 24 30 46 88 4c 24 31 c6 44 24 32 6c 88 5c 24 34}  //weight: 1, accuracy: High
        $x_1_2 = {b2 72 b0 65 51 56 c6 44 24 18 5c c6 44 24 19 63 c6 44 24 1a 78 88 54 24 1b c6 44 24 1c 2e}  //weight: 1, accuracy: High
        $x_1_3 = "%s&jb=%s&y=%s" ascii //weight: 1
        $x_1_4 = "%s?a=%s&s=%s&u=%s&p=%s&js=%s&dj=%s&l=%s&mb=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_IZ_2147641112_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.IZ!dll"
        threat_id = "2147641112"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 44 24 3c 38 c6 44 24 3d 39 c6 44 24 3e 2b c6 44 24 3f 2f 33 c0 38 4c 04 00 74 06 40 83 f8 3f 7e f4 83 c4 40 c3}  //weight: 2, accuracy: High
        $x_2_2 = {8a da 8a 4d 02 80 e2 03 c0 eb 02 88 5c 24 10 8a d8 c0 e2 04 c0 eb 04 0a d3 24 0f 88 54 24 11 8a d1 c0 e0 02 c0 ea 06 0a c2 80 e1 3f}  //weight: 2, accuracy: High
        $x_2_3 = "KBDLoger" ascii //weight: 2
        $x_1_4 = "\\hexil.dll" ascii //weight: 1
        $x_1_5 = "hpig_WS2.dat" ascii //weight: 1
        $x_1_6 = "D-windowname.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_JA_2147641113_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JA!dll"
        threat_id = "2147641113"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 04 85 c9 74 19 8b 44 24 08 85 c0 74 11 7c 0f 8a 14 01 80 f2 30 80 c2 20 88 14 01 48 79 f1 c3}  //weight: 1, accuracy: High
        $x_1_2 = "zhihuiguan" ascii //weight: 1
        $x_1_3 = "RXJH_KICKARSE0." ascii //weight: 1
        $x_1_4 = "%hs?u=%hs&p=unknow&c=%hs&ac=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JF_2147641230_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JF"
        threat_id = "2147641230"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WriteProcessMemory err." ascii //weight: 2
        $x_2_2 = "start hook getchar" ascii //weight: 2
        $x_3_3 = "%s?action=getma&u=%s" ascii //weight: 3
        $x_2_4 = "%s?action=setmp&mp=%s&u=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JB_2147641490_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JB!dll"
        threat_id = "2147641490"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 56 c6 45 ?? 8b c6 45 ?? 4d c6 45 ?? 0c c6 45 ?? 8b c6 45 ?? 75 c6 45 ?? 10 c6 45 ?? 8a c6 45 ?? 45 c6 45 ?? 18}  //weight: 1, accuracy: Low
        $x_1_2 = {57 56 c6 45 ?? 40 c6 45 ?? 83 c6 45 ?? c1 c6 45 ?? 03 c6 45 ?? 83 c6 45 ?? c2 c6 45 ?? 08 c6 45 ?? 83 c6 45 ?? f8 c6 45 ?? 03 c6 45 ?? 7c c6 45 ?? e1 c6 45}  //weight: 1, accuracy: Low
        $x_1_3 = "up/Upf.asp" ascii //weight: 1
        $x_1_4 = "%s%s?c=q&i=%s&s=%s&a=%s&m=%s&t=%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JC_2147641491_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JC!dll"
        threat_id = "2147641491"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 50 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d c6 45 ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 80 65 ?? 00 a3 ?? ?? ?? ?? c6 45 ?? 4b c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 50 c6 45 ?? 72 ff 75 ?? c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 54 c6 45 ?? 68 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 64}  //weight: 1, accuracy: Low
        $x_1_4 = {50 56 c6 45 ?? 6d c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73 c6 45 ?? 70 88 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JD_2147641492_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JD!dll"
        threat_id = "2147641492"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 50 c6 44 24 ?? 51 c6 44 24 ?? 52 c6 44 24 ?? 8d c6 44 24 ?? 85 e8 ?? ?? ?? ?? 83 c4 14 83 f8 ff 74 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {56 c6 44 24 ?? 50 c6 44 24 ?? 8d c6 44 24 ?? 4c c6 44 24 ?? 24 c6 44 24 ?? 28 e8 ?? ?? ?? ?? 83 c4 14 83 f8 ff 74 11}  //weight: 1, accuracy: Low
        $x_1_3 = "wsidny.asp" ascii //weight: 1
        $x_1_4 = "?a=%s&s=%s&u=%s&p=%s&pin=%s&r=%s&l=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JJ_2147641494_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JJ!dll"
        threat_id = "2147641494"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 bc 44 c6 45 bd 49 c6 45 be 53 c6 45 bf 50 c6 45 c0 4c c6 45 c1 41 c6 45 c2 59 88 5d c3 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f0 65 c6 45 f1 78 c6 45 f2 70 c6 45 f3 6c c6 45 f4 6f c6 45 f5 72 c6 45 f6 65 c6 45 f7 72 c6 45 f8 2e c6 45 f9 65 c6 45 fa 78 c6 45 fb 65}  //weight: 1, accuracy: High
        $x_1_3 = {ff 50 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 ?? ?? ?? 74 ?? ?? ?? 69 ?? ?? ?? 6f ?? ?? ?? 6e c6 45 ?? 3d ?? ?? ?? 74 ?? ?? ?? 65 ?? ?? ?? 73 ?? ?? ?? 74 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 63 c6 45 ?? 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JK_2147641495_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JK!dll"
        threat_id = "2147641495"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3f 88 63 00 00 74 0a 6a 32 ff 15 ?? ?? ?? ?? eb ee e8 ?? ?? ?? ?? b9 ff 00 00 00 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 bc 44 c6 45 bd 49 c6 45 be 53 c6 45 bf 50 c6 45 c0 4c c6 45 c1 41 c6 45 c2 59 88 5d c3 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {ff 50 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 ?? ?? ?? 74 ?? ?? ?? 69 ?? ?? ?? 6f ?? ?? ?? 6e c6 45 ?? 3d ?? ?? ?? 74 ?? ?? ?? 65 ?? ?? ?? 73 ?? ?? ?? 74 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 63 c6 45 ?? 6b}  //weight: 1, accuracy: Low
        $x_1_4 = "%s/bmp/%s_mibaoka.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AAC_2147641865_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AAC"
        threat_id = "2147641865"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 0c 83 c0 05 89 45 f4 8b 4d 08 c1 e1 08 81 c1 ?? ?? ?? ?? 2b 4d f4 89 4d f4 8b 55 0c 03 55 fc c6 02 e9 8b 45 fc}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c4 14 68 ?? ?? ?? ?? 6a 05 8d 8d ?? ?? ff ff 51 8b 55 ?? 52 6a ?? e8}  //weight: 2, accuracy: Low
        $x_1_3 = "360SE" ascii //weight: 1
        $x_1_4 = "TTraveler" ascii //weight: 1
        $x_1_5 = "TheWorld" ascii //weight: 1
        $x_1_6 = "elementclient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_AAD_2147641868_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AAD"
        threat_id = "2147641868"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 52 ff 25 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = "60safe" ascii //weight: 1
        $x_1_3 = "KVMonXP" ascii //weight: 1
        $x_1_4 = "'cmd /c %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_AAB_2147641870_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.AAB"
        threat_id = "2147641870"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 5a 52 ff 25}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 44 8b 01 35 55 8b ec 83}  //weight: 2, accuracy: High
        $x_1_3 = "KVMonXP" ascii //weight: 1
        $x_1_4 = "Hookoff" ascii //weight: 1
        $x_1_5 = "60safe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_JH_2147641983_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JH"
        threat_id = "2147641983"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 ff 75 08 c6 45 ?? 71 c6 45 ?? 66 c6 45 ?? 66 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78}  //weight: 1, accuracy: Low
        $x_1_2 = {80 f9 47 75 15 80 b8 ?? ?? ?? ?? 49 75 0c 80 b8 ?? ?? ?? ?? 46 75 03}  //weight: 1, accuracy: Low
        $x_1_3 = {65 50 53 c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 0a 0f 83 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 83 25 ?? ?? ?? ?? 00 bb ?? ?? ?? ?? c6 45 ?? 3f c6 45 ?? 64 c6 45 ?? ?? c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_JI_2147641984_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JI"
        threat_id = "2147641984"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 c6 45 ?? 6d c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73 c6 45 ?? 70}  //weight: 1, accuracy: Low
        $x_1_2 = {3f 50 8d 85 ?? ?? ?? ?? 50 c6 [0-5] 61 c6 [0-5] 63 c6 [0-5] 74 c6 [0-5] 69 c6 [0-5] 6f c6 [0-5] 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDA_2147642138_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDA!dll"
        threat_id = "2147642138"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 6c b1 78 88 44 24 ?? 88 44 24 ?? b0 6f c6 44 24 ?? 43 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? c6 44 24 ?? 61 50 56 c6 44 24 ?? 4e c6 44 24 ?? 65}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 84 24 a0 00 00 00 c6 44 24 ?? 6d 50 68 04 01 00 00 c6 44 24 ?? 70 c6 44 24 ?? 63 c6 44 24 ?? 6f c6 44 24 ?? 72 c6 44 24 ?? 65 c6 44 24 ?? 2e c6 44 24 ?? 78 c6 44 24 ?? 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "?us=%s&ps=%s&lv=%d&qu=%s&se=%s" ascii //weight: 1
        $x_1_4 = "?WOWID=%s&WU=%s&WP=%s&Area=%s&SYS=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JK_2147642290_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JK"
        threat_id = "2147642290"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?action=postmb&u=%s&mb=%s" ascii //weight: 1
        $x_1_2 = "%s?action=testlock2&u=%s" ascii //weight: 1
        $x_1_3 = "QQLogin.exe" ascii //weight: 1
        $x_1_4 = "LoadDll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZEA_2147642529_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZEA!dll"
        threat_id = "2147642529"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f9 f7 74 05 80 f9 f6 75 12 a8 38 75 0e f6 c1 01 74 08 f6 c5 01 75 02 46 46 46 46 8b d0 24 07 f6 c2 c0}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e4 31 c6 45 e5 32 c6 45 e6 31 c6 45 e7 2e c6 45 e8 31 c6 45 e9 32 c6 45 ea 2e c6 45 eb 31 c6 45 ec 37 c6 45 ed 30 c6 45 ee 2e c6 45 ef 31 c6 45 f0 38 c6 45 f1 34}  //weight: 1, accuracy: High
        $x_1_3 = "/t.asp" ascii //weight: 1
        $x_1_4 = "C:\\mxdos.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDX_2147642531_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDX!dll"
        threat_id = "2147642531"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 80 3e 00 00 ff 15 24 19 00 10 e9 4b ff ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? f7 d8 1b c0 40 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {57 56 c6 45 ?? 8b c6 45 ?? 4d c6 45 ?? 0c c6 45 ?? 8b c6 45 ?? 75 c6 45 ?? 10 c6 45 ?? 8a c6 45 ?? 45 c6 45 ?? 18 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "up/Upf.asp" ascii //weight: 1
        $x_1_4 = "%s%s?ac=h&i=%s&h=%s" ascii //weight: 1
        $x_1_5 = "%s%s?c=q&i=%s&s=%s&a=%s&m=%s&t=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_ZDM_2147642533_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDM!dll"
        threat_id = "2147642533"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 b8 0b 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ?? ?? 55 8b ec 8b c9 8b d2 8b c9 8b c0 90 8b c9}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 e0 fd ff ff 50 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c9 33 db c6 45 ?? 45 c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {3f 61 3d 25 73 26 73 3d b5 da 28 25 64 29 b7 fe 26 75 3d 25 73 26 70 3d 25 73 26 72 3d 25 73 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZDV_2147642534_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZDV!dll"
        threat_id = "2147642534"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 09 60 90 61 90 90 6a 01 eb 07 60 90 61 90 90 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b c6 33 d2 b9 60 00 00 00 bb 03 00 00 00 f7 f1 8b c6 8b ca 33 d2 f7 f3 8a 1c 3e 32 ca 32 cb 80 f1 95 88 0c 3e 46 3b f5 72 d6}  //weight: 1, accuracy: High
        $x_1_3 = "/mibao.asp" ascii //weight: 1
        $x_1_4 = "%s?act=&d10=%s&d80=%d" ascii //weight: 1
        $x_1_5 = "?d10=%s&d11=%s&d00=%s&d01=%s&d22=%s&d32=%s&d70=%d&d90=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_ZED_2147642537_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZED!dll"
        threat_id = "2147642537"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 65 b3 6e b1 70 b2 61}  //weight: 1, accuracy: High
        $x_1_2 = {b0 65 b2 2e b1 78 33 db c6 45 ?? 76 c6 45 ?? 73 c6 45 ?? 6e c6 45 ?? 69 c6 45 ?? 66 c6 45 ?? 66 88 45}  //weight: 1, accuracy: Low
        $x_1_3 = "%s?act=getpos&d10=%s&d80=" ascii //weight: 1
        $x_1_4 = "?a=%s&s=%s&u=%s&p=%s&pin=%s&" ascii //weight: 1
        $x_2_5 = "mibao.asp" ascii //weight: 2
        $x_2_6 = "wsidny.asp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_JL_2147642591_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JL"
        threat_id = "2147642591"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 27 53 8b 54 24 ?? 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 ?? 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 4f 70 65 6e 50 c7 44 24 ?? 77 69 6e 69 c7 44 24 ?? 6e 65 74 2e c7 44 24 ?? 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 e0 93 04 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b9 ff 01 00 00 33 c0 8d bd ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 00 f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_OnLineGames_XZA_2147642701_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.XZA"
        threat_id = "2147642701"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 6a 02 56 ff 15 84 80 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff 61 ff 25 07 00 60 ff ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {00 4b 73 55 73 65 72 2e 64 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-4] 6c 70 6b 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "\\ShellNoRoam\\MUICache" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_XZB_2147642702_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.XZB"
        threat_id = "2147642702"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 25 73 5f 6c 25 64 (2e 6a|2e 62)}  //weight: 1, accuracy: Low
        $x_1_2 = "\\ShellNoRoam\\MUICache" ascii //weight: 1
        $x_1_3 = "%s\\ksuser.dll" ascii //weight: 1
        $x_1_4 = "%s?act=getpos&d10=%s&pos=&d80=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JN_2147642858_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JN!dll"
        threat_id = "2147642858"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f 61 3d 00 26 49 6d 67 55 70 3d 00 62 79 73 75 6e 3d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 40 25 30 00 25 00 61 69 6f 6e 2e 62 69 6e 00 5c 62 79 7a 79 68 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 66 61 6e 68 75 69 62 61 6f 3d 00 3f 63 3d 71 26 69 3d 00 31 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "BlackMoon.dll" ascii //weight: 1
        $x_1_5 = {58 6e 56 69 65 77 00 56 69 65 77 65 72 00 50 69 63 61 73 61 00 46 61 73 74 53 74 6f 6e 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JN_2147642859_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JN"
        threat_id = "2147642859"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\bin32\\byzyh.exe" ascii //weight: 1
        $x_1_2 = "\\bin32\\rasadhlp.dll" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\snda\\AION\\Path" ascii //weight: 1
        $x_1_4 = {6a 00 6a 00 6a 00 68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 01 03 00 80 6a 00 68 04 00 00 00 68 03 00 00 00 bb 98 06 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_JO_2147642904_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JO"
        threat_id = "2147642904"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 30 80 f3 ?? 88 1c 30 40 3d ?? ?? ?? ?? 72 ef}  //weight: 1, accuracy: Low
        $x_2_2 = {b2 41 b1 4e 50 68 02 00 00 80 c6 44 24 ?? 4f 88 54 24 ?? c6 44 24 ?? 52 c6 44 24 ?? 45 c6 44 24 ?? 5c}  //weight: 2, accuracy: Low
        $x_1_3 = {74 04 3c 6e 75 37 80 7c ?? ?? 2e 75 30 8a 44 ?? ?? 3c 45}  //weight: 1, accuracy: Low
        $x_1_4 = {81 c7 99 00 00 00 89 7c 24 ?? bf ?? ?? ?? ?? 8b 44 24 ?? 8d 54 24 ?? 6a 00 52 55 50 56 ff d3 4f 75 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZEG_2147643235_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZEG!dll"
        threat_id = "2147643235"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 14 51 c6 44 24 15 51 c6 44 24 16 4c c6 44 24 17 6f c6 44 24 18 67 c6 44 24 19 69 c6 44 24 1a 6e c6 44 24 1b 2e 88 5c 24 1c}  //weight: 1, accuracy: High
        $x_1_2 = "\\dnf\\bieshawo.exe" ascii //weight: 1
        $x_1_3 = "\\system32\\wahaha.ime" ascii //weight: 1
        $x_1_4 = {c4 e3 ba c3 c9 b1 b6 be c8 ed bc fe 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 71 75 3d ?? ?? ?? ?? 26 70 61 73 73 3d 00 00 3f 75 73 65 72 6e 61 6d 65 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6c 69 6e 2e 61 73 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_ZEI_2147643237_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZEI!dll"
        threat_id = "2147643237"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {64 62 72 25 30 32 78 2a 2e 74 73 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "dmdbccfdaoigalkga" ascii //weight: 1
        $x_1_4 = {5f 72 65 67 61 6d 6c 65 5f 25 30 38 64 5f 0d 00 00 67 62 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFM_2147643593_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFM"
        threat_id = "2147643593"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\data.evp" ascii //weight: 1
        $x_1_2 = "360tray.exe" ascii //weight: 1
        $x_1_3 = "\\dllcache\\lpk.dll" ascii //weight: 1
        $x_1_4 = "del \"%s\" if exist \"%s\" goto delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFM_2147643593_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFM"
        threat_id = "2147643593"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 6a 04 57 68 ?? ?? ?? ?? ff d5 85 c0 74}  //weight: 2, accuracy: Low
        $x_2_2 = "\\ksuser.dll" ascii //weight: 2
        $x_1_3 = {c1 ee 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c3 dc 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "SecurityMatrixKeypadButton" ascii //weight: 1
        $x_1_6 = "SecurityMatrixPinwheelButton" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZFM_2147643593_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFM"
        threat_id = "2147643593"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4f 3c 83 c4 0c 03 cf 66 81 79 18 0b 01 75 ?? 66 8b 51 58 66 3b c2 1b db f7 db 03 da 66 8b 51 5a}  //weight: 1, accuracy: Low
        $x_2_2 = {00 6b 73 75 73 65 72 2e 64 6c 6c 00 00 6d 69 64 69 6d 61 70 2e 64 6c 6c 00 63 6f 6d 72 65 73 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_3 = "sserddAcorPteG" ascii //weight: 1
        $x_1_4 = "%s, ServerMain %c%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_JZ_2147647062_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.JZ"
        threat_id = "2147647062"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\xlelsp" ascii //weight: 1
        $x_1_2 = "\\bvlrdw.exe" ascii //weight: 1
        $x_1_3 = "\\start\\UserSetting.ini" ascii //weight: 1
        $x_1_4 = "\\aowjfk.exe" ascii //weight: 1
        $x_1_5 = "\\qqlogin.exe" ascii //weight: 1
        $x_1_6 = "\\dnfchina.exe" ascii //weight: 1
        $x_1_7 = "\\dnf.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KD_2147647119_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KD"
        threat_id = "2147647119"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Content-Type: multipart/form-data; boundary=---------------------------7dbfa291b0390" ascii //weight: 4
        $x_4_2 = "%s?s=%s&a=%s&u=%s&p=%s&n=%s&lv=%d&g=%d&xg=%d&y=%d&%s=%s&%s=%s&%s=%s&mbh=%d&l=%s&sl=%s" ascii //weight: 4
        $x_3_3 = "^$^SerialNum" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KO_2147647688_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KO"
        threat_id = "2147647688"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0e 8a 06 d2 c0 32 c2 88 06 46 4b 85 db 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {68 5c fe ff ff 50 89 45 ?? ff d7 be 18 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KQ_2147647900_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KQ"
        threat_id = "2147647900"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 ca 32 cb 80 f1}  //weight: 10, accuracy: High
        $x_10_2 = {32 ca 32 0e 80 f1}  //weight: 10, accuracy: High
        $x_1_3 = {32 ca 66 0f a3 ee 32 cb}  //weight: 1, accuracy: High
        $x_3_4 = {5c 44 66 4c 6f 67 2e 69 6e 69 00}  //weight: 3, accuracy: High
        $x_3_5 = {5c 46 46 4c 6f 67 2e 69 6e 69 00}  //weight: 3, accuracy: High
        $x_3_6 = {5c 47 61 6d 65 4c 6f 67 2e 69 6e 69 00}  //weight: 3, accuracy: High
        $x_3_7 = {5c 68 61 6e 67 61 6d 65 2e 69 6e 69 00}  //weight: 3, accuracy: High
        $x_3_8 = {5c 4c 75 6f 71 69 4c 6f 67 2e 69 6e 69 00}  //weight: 3, accuracy: High
        $x_3_9 = {5c 54 69 61 6e 79 69 4c 6f 67 2e 69 6e 69 00}  //weight: 3, accuracy: High
        $x_3_10 = {26 6c 6f 67 69 6e 5f 69 6e 66 6f 35 3d 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_3_*) and 1 of ($x_1_*))) or
            ((7 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KS_2147648022_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KS"
        threat_id = "2147648022"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5b 64 6e 74 5d bc d3 d4 d8 64 6c 6c b3 c9 b9 a6 a3 a1 00 00 5b 64 6e 74 5d bc d3 d4 d8 64 6c 6c [0-16] 72 62 00 00 5c 64 64 72 [0-4] 2e 6f 63 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KU_2147648260_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KU"
        threat_id = "2147648260"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f [0-37] 2f 63 68 69 6e 61 2e 61 73 70 00}  //weight: 2, accuracy: Low
        $x_1_2 = "Program Files\\Outlook Express\\" ascii //weight: 1
        $x_1_3 = {00 53 65 6e 64 20 4f 4b 21 00}  //weight: 1, accuracy: High
        $x_2_4 = {8b 55 dc a1 ?? ?? ?? 00 b9 ?? ?? ?? 00 e8 ?? ?? ff ff e8 ?? ?? ff ff a3 ?? ?? ?? 00 6a 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 85 c0 75 [0-6] 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 6a 00 e8 ?? ?? ff ff eb 1e 68 ?? ?? ?? 00 68 58 1b 00 00 6a 00 6a 00 e8}  //weight: 2, accuracy: Low
        $x_2_5 = {56 57 89 c6 89 d7 89 c8 39 f7 77 13 74 2f c1 f9 02 78 2a f3 a5 89 c1 83 e1 03 f3 a4 5f 5e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KV_2147648343_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KV"
        threat_id = "2147648343"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FF15246040005368800000006A03536A018D856CFEFFFF680000008050FF15206" ascii //weight: 1
        $x_1_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 31 00}  //weight: 1, accuracy: High
        $x_1_3 = "LF-WOOOLDLQ-2010" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KW_2147648411_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KW"
        threat_id = "2147648411"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {45 6c 65 6d 65 6e 74 20 43 6c 69 65 6e 74 00 00 5a 45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 00 00 00 ff ff ff ff 05 00 00 00}  //weight: 4, accuracy: High
        $x_4_2 = {26 50 61 73 73 3d 00 00 ff ff ff ff 04 00 00 00 26 63 6b 3d 00 00 00 00 ff ff ff ff 04 00 00 00 26 64 6a 3d 00 00 00 00 ff ff ff ff 04 00 00 00}  //weight: 4, accuracy: High
        $x_2_3 = "Send OK!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KX_2147648650_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KX"
        threat_id = "2147648650"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3f 61 31 3d 25 64 26 61 33 3d 25 73 26 61 34 3d 25 73 26 61 36 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 64 66 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 0c 02 88 08 40 ff 4d 08 89 45 18 75 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KY_2147649517_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KY"
        threat_id = "2147649517"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 c2 61 88 14 3e 46 83 fe 09 7c ea 68 ?? ?? ?? ?? 57 c6 04 3e 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {71 71 70 63 74 72 61 79 2e 65 78 65 [0-5] 72 61 76 6d 6f 6e 64 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 25 73 20 2f 63 20 64 65 6c 20 25 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 00 76 00 65 00 72 00 [0-10] 49 00 49 00 4f 00 4c 00 53 00 50 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_KY_2147649517_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KY"
        threat_id = "2147649517"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 10 fe cb 88 1c 10 40 3b c1 7c f3}  //weight: 2, accuracy: High
        $x_2_2 = {26 72 61 6e 6b 3d [0-5] 26 70 77 64 3d [0-5] 26 75 73 65 72 6e 61 6d 65 3d [0-5] 26 73 65 72 76 65 72 3d}  //weight: 2, accuracy: Low
        $x_2_3 = {26 6d 61 63 3d [0-5] 26 7a 68 61 6e 62 69 61 6f 3d [0-5] 26 63 68 61 6e 6e 65 6c 3d}  //weight: 2, accuracy: Low
        $x_1_4 = "basicinfo.aspx?area=" ascii //weight: 1
        $x_1_5 = "param.aspx?username=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KZ_2147649692_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KZ"
        threat_id = "2147649692"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "23lenreK" ascii //weight: 10
        $x_10_2 = "teniniW" ascii //weight: 10
        $x_5_3 = {6d 6f 64 4d 65 73 73 61 67 65 00 6d 6f 64 6d 43 61 6c 6c 62 61 63 6b 00}  //weight: 5, accuracy: High
        $x_5_4 = {50 4d 20 56 65 72 69 66 79 21 00}  //weight: 5, accuracy: High
        $x_1_5 = {25 73 3f 61 31 3d 25 64 26 61 33 3d 25 73 26 61 34 3d 25 73 26 61 36 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = "maplestory.exe" ascii //weight: 1
        $x_1_7 = ".nexon.com" ascii //weight: 1
        $x_1_8 = "DNF.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_KZ_2147649692_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.KZ"
        threat_id = "2147649692"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KJDJSKKW" ascii //weight: 1
        $x_1_2 = {c6 45 e4 6f c6 45 ?? 03 c6 45 ?? 17 c6 45 ?? 1b c6 45 ?? 6d c6 45 ?? 18 c6 45 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_OnLineGames_LA_2147649693_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LA"
        threat_id = "2147649693"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "delself.bat" ascii //weight: 10
        $x_10_2 = "sfc_os.dll" ascii //weight: 10
        $x_1_3 = {c6 45 cc 6f c6 45 cd 6c c6 45 ce 68 c6 45 cf 65}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 dd 65 c6 45 de 74 c6 45 df 54 c6 45 e0 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_LB_2147649694_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LB"
        threat_id = "2147649694"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "DNFchina.exe" ascii //weight: 100
        $x_100_2 = ".data21" ascii //weight: 100
        $x_10_3 = "qqlogin.exe" ascii //weight: 10
        $x_10_4 = "\\start\\usersetting.ini" ascii //weight: 10
        $x_10_5 = "DNFThreadSendParam" ascii //weight: 10
        $x_1_6 = {c6 45 cc 6f c6 45 cd 6c c6 45 ce 68 c6 45 cf 65}  //weight: 1, accuracy: High
        $x_1_7 = {c6 45 a9 72 c6 45 aa 65 c6 45 ab 72 c6 45 ac 2e c6 45 ad 65 c6 45 ae 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZFO_2147649890_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFO"
        threat_id = "2147649890"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMD_SOFTKEYDOWN" ascii //weight: 1
        $x_1_2 = "=EYEYu" ascii //weight: 1
        $x_1_3 = "DNF.exe" ascii //weight: 1
        $x_1_4 = {80 3b 2f 75 08 80 7b 01 2f 75 02 43 43}  //weight: 1, accuracy: High
        $x_3_5 = {c6 45 f4 6d c6 45 f5 69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_LC_2147650428_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LC"
        threat_id = "2147650428"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 70 6b 69 6e 69 74 2e 64 [0-4] 63 6c 69 65 6e 74 54 58 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\"C:\\Windows\\iexplore.exe\"" ascii //weight: 1
        $x_1_3 = {8d 45 fc 57 8b 3d ?? ?? ?? 10 50 6a 40 6a 05 56 ff d7 a0 ?? ?? ?? 10 6a 00 88 06 a0 ?? ?? ?? 10 88 46 01 a0 ?? ?? ?? 10 88 46 02 a0 ?? ?? ?? 10 88 46 03 a0 ?? ?? ?? 10 88 46 04 ff 75 fc 6a 05 56 ff d7}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 45 fc 57 8b ?? ?? ?? ?? 10 50 6a 40 6a 05 56 ff d7 6a 00 b8 ?? ?? ?? 10 ff 75 fc 2b c6 83 e8 05 c6 06 e9 6a 05 56 89 46 01 ff d7 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LD_2147651151_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LD"
        threat_id = "2147651151"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Text=GAMEQUAN|" ascii //weight: 1
        $x_1_2 = "ruNdLl32.ExE" ascii //weight: 1
        $x_1_3 = "scivisat.hlp" ascii //weight: 1
        $x_1_4 = "drAGonneSt.eXe" ascii //weight: 1
        $x_1_5 = "dNlAuNchEr.exE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFP_2147651491_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFP"
        threat_id = "2147651491"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 45 f8 50 c6 45 f9 4f [0-16] c6 45 fa 53 c6 45 fb 54}  //weight: 10, accuracy: Low
        $x_10_2 = {69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70}  //weight: 10, accuracy: High
        $x_10_3 = {25 73 5f 25 64 25 73 00 2e 6a 70 67}  //weight: 10, accuracy: High
        $x_1_4 = "DNF.exe" ascii //weight: 1
        $x_1_5 = "QQLogin.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZFP_2147651491_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFP"
        threat_id = "2147651491"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 44 24 2e 66 c7 44 24 10 6c 00 66 c7 44 24 12 6f 00 66 c7 44 24 14 67 00 66 c7 44 24 16 69 00 66 c7 44 24 18 6e 00 66 c7 44 24 1a 2e 00 66 c7 44 24 1e 78 00}  //weight: 10, accuracy: High
        $x_10_2 = {c6 44 24 0d 6c c6 44 24 0e 69 c6 44 24 10 6e c6 44 24 11 74 c6 44 24 12 2e c6 44 24 14 78}  //weight: 10, accuracy: High
        $x_1_3 = "cha_password" wide //weight: 1
        $x_1_4 = "%s?s=%s&a=%s&u=%s&p=%s&n=%s&lv=%d&g=%d&y=%d&l=%s&%s=%s&%s=%s&%s=%s&mbh=%d&sg=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_LI_2147652535_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LI"
        threat_id = "2147652535"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\Xy%dnd.temp" ascii //weight: 1
        $x_1_2 = "BEGIN FUWU" ascii //weight: 1
        $x_1_3 = {b2 e9 d5 d2 50 45 49 5a 49 d0 c5 cf a2}  //weight: 1, accuracy: High
        $x_1_4 = "JIJI  SHANGXIAN" ascii //weight: 1
        $x_2_5 = {8b 48 34 03 48 28 eb 08 8b 4d ?? 8b 49 28 03 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_LK_2147652792_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LK"
        threat_id = "2147652792"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {05 00 00 00 57 49 4e 4e 54 00 00 00 ff ff ff ff 06 00 00 00 53 68 61 6e 64 61 00 00 ff ff ff ff}  //weight: 5, accuracy: High
        $x_1_2 = "System Volume Information" ascii //weight: 1
        $x_3_3 = {00 43 4f 4d 53 50 45 43 00 2f 63 20 64 65 6c 20 00 20 3e 20 6e 75 6c 00 00 4f 70 65 6e 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LM_2147653273_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LM"
        threat_id = "2147653273"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 14 5c c6 44 24 15 6d c6 44 24 16 70 c6 44 24 17 63 c6 44 24 18 6f c6 44 24 19 72 c6 44 24 1a 65 c6 44 24 1b 2e}  //weight: 1, accuracy: High
        $x_1_2 = "KickUserOutGame:%u,%u" ascii //weight: 1
        $x_1_3 = "WTF\\Config.wtf" ascii //weight: 1
        $x_1_4 = {72 65 61 6c 6d 4e 61 6d 65 20 22 00 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LN_2147653279_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LN"
        threat_id = "2147653279"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5f c6 45 f1 5f c6 45 f2 48 c6 45 f3 48 c6 45 f4 45 c6 45 f5 58 c6 45 f6 45 c6 45 f7 4d c6 45 f8 55 c6 45 f9 54 c6 45 fa 45 c6 45 fb 58 c6 45 fc 5f c6 45 fd 5f}  //weight: 3, accuracy: High
        $x_1_2 = {73 50 8d 85 ?? ?? ?? ?? [0-1] c6 45 ?? 6b c6 45 ?? 69 c6 45 ?? 6c c6 45 ?? 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 88 5d ff [0-1] c6 45 ?? 64 c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 73 c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 66 c6 45 ?? 2e c6 45 ?? 62}  //weight: 1, accuracy: Low
        $x_2_4 = {47 50 6a 00 68 03 00 1f 00 c6 ?? f1 6c c6 ?? f2 6f c6 ?? f3 62 c6 ?? f4 61 c6 ?? f5 6c c6 ?? f6 5c c6 ?? f7 45 c6 ?? f8 6e c6 ?? f9 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_LO_2147653425_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LO"
        threat_id = "2147653425"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "4game\\4GameManager" ascii //weight: 1
        $x_1_2 = {5f 7a 61 70 75 73 6b 61 74 ?? 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "Roll\\Red\\csrss.exe" ascii //weight: 1
        $x_1_4 = "Macro\\Red\\taskmgr.exe" ascii //weight: 1
        $x_1_5 = "\\Sys\\MacromediaFlash.exe" ascii //weight: 1
        $x_1_6 = {34 47 61 6d 65 5a 61 70 ?? 73 6b 61 74 72}  //weight: 1, accuracy: Low
        $x_1_7 = "\\_data_ec.tmp" ascii //weight: 1
        $x_1_8 = "Dowelor\\Teem\\Ko\\" ascii //weight: 1
        $x_1_9 = "Visit\\Noly\\4034\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_LP_2147653788_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LP"
        threat_id = "2147653788"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_rel_regamle_%08d_" ascii //weight: 1
        $x_1_2 = {8d 45 ec 50 c6 ?? ec 49 c6 ?? ed 70 c6 ?? ee 68 c6 ?? ef 6c c6 ?? f0 70 c6 ?? f1 61 c6 ?? f2 70 c6 ?? f3 69 c6 ?? f4 2e c6 ?? f5 64 c6 ?? f6 6c c6 ?? f7 6c c6 ?? dc 47 c6 ?? dd 65 c6 ?? de 74 c6 ?? df 41}  //weight: 1, accuracy: Low
        $x_1_3 = {80 65 ec 00 80 65 fc 00 39 75 0c c6 ?? e0 65 c6 ?? e1 78 c6 ?? e2 70 c6 ?? e3 6c c6 ?? e4 6f c6 ?? e5 72 c6 ?? e6 65 c6 ?? e7 72 c6 ?? e8 2e c6 ?? e9 65 c6 ?? ea 78 c6 ?? eb 65 c6 ?? f0 72 c6 ?? f1 75 c6 ?? f2 6e c6 ?? f3 64}  //weight: 1, accuracy: Low
        $x_1_4 = {50 8d 85 e4 fd ff ff 50 c6 ?? e5 61 c6 ?? e6 63 c6 ?? e7 74 c6 ?? e8 69 c6 ?? e9 6f c6 ?? ea 6e c6 ?? eb 3d c6 ?? ec 70 c6 ?? ed 6c c6 ?? ee 61 c6 ?? ef 79 c6 ?? f0 65 c6 ?? f1 72 c6 ?? f2 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LQ_2147653816_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LQ"
        threat_id = "2147653816"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GMAL+HOST:%s+IP:%s+NAME:%s+PASS:%s+Ver:%s" ascii //weight: 1
        $x_1_2 = "YAHO+HOST:%s+IP:%s+NAME:%s+PASS:%s+Ver:%s" ascii //weight: 1
        $x_1_3 = "https://tw.gash.gamania.com/GASHLogin.aspx" ascii //weight: 1
        $x_1_4 = "POST %s?CODE=%s HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LS_2147654044_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LS"
        threat_id = "2147654044"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gamecfg.ini" ascii //weight: 1
        $x_1_2 = "DragonNest.exe" ascii //weight: 1
        $x_1_3 = "yuksuser.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LT_2147654161_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LT"
        threat_id = "2147654161"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 84 24 1c 03 00 00 54 c6 84 24 1d 03 00 00 4d c6 84 24 1e 03 00 00 32}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 14 7a c6 44 24 16 69 c6 44 24 17 63 c6 44 24 19 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_OnLineGames_LV_2147654709_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LV"
        threat_id = "2147654709"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/cxpid/submit.php?SessionID=" ascii //weight: 1
        $x_1_2 = {8b d0 8a 83 ?? ?? ?? ?? 32 d0 8d 45 f4 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? 43 81 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFQ_2147655041_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFQ"
        threat_id = "2147655041"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 c6 04 1f e9 89 4c 1f 01 8b 44 24 0c 50 53 56 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {f7 d2 33 d0 83 f2 74 89 90 ?? ?? ?? ?? 40 8d 94 01 ?? ?? ?? ?? 83 fa 74 7e}  //weight: 1, accuracy: Low
        $x_1_3 = {d5 cb ba c5 25 73 20 20 20 c3 dc c2 eb 25 73 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_MA_2147656704_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MA!dll"
        threat_id = "2147656704"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rxjh.17game.com" ascii //weight: 1
        $x_1_2 = "zhihuiguan" ascii //weight: 1
        $x_1_3 = "RXJH_KICKARSE0." ascii //weight: 1
        $x_1_4 = "WHERESHXTE0." ascii //weight: 1
        $x_1_5 = "DnsGetBufferLengthForStringCopy" ascii //weight: 1
        $x_1_6 = "DnsGetCacheDataTable" ascii //weight: 1
        $x_1_7 = "feedURL" ascii //weight: 1
        $x_1_8 = "YB_OnlineClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_LW_2147657254_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.LW"
        threat_id = "2147657254"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mscrosoft.dll" ascii //weight: 1
        $x_1_2 = {8d 45 f4 c6 45 f4 6d 50 56 c6 45 f5 69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFU_2147657837_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFU"
        threat_id = "2147657837"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 10 fe cb 88 1c 10 40 3b c1 7c f3 5f 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = "d;]njcbp/kqh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFV_2147657839_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFV"
        threat_id = "2147657839"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 10 80 c3 ?? 88 1c 10 40 3b c1 7c f2 5b c3}  //weight: 10, accuracy: Low
        $x_1_2 = "edvlflqir1dvs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_MB_2147657965_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MB"
        threat_id = "2147657965"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SoftupNotify.exe" ascii //weight: 1
        $x_1_2 = {47 61 6d 65 20 4f 76 65 72 00 00 00 48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\FW.FW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_ZFW_2147658120_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZFW"
        threat_id = "2147658120"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f c6 45 e5 64 c6 45 e6 33 c6 45 e7 3d c6 45 e8 25 c6 45 e9 73 c6 45 ea 26}  //weight: 1, accuracy: High
        $x_1_2 = {c6 04 3b e9 8b c6 2b c3 83 e8 05}  //weight: 1, accuracy: High
        $x_1_3 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_MC_2147658166_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MC"
        threat_id = "2147658166"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/china.asp?0k=" ascii //weight: 5
        $x_2_2 = "/qq.asp?QQNumber=" ascii //weight: 2
        $x_2_3 = "C:\\B00T.SYS" ascii //weight: 2
        $x_2_4 = ":1314" ascii //weight: 2
        $x_2_5 = "&QQPassWord=" ascii //weight: 2
        $x_2_6 = "&QQclub=" ascii //weight: 2
        $x_1_7 = "hangame" ascii //weight: 1
        $x_1_8 = "fifaonline." ascii //weight: 1
        $x_1_9 = "aostray.exe" ascii //weight: 1
        $x_1_10 = "cultureland.co.kr" ascii //weight: 1
        $x_1_11 = "happymoney" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_MM_2147660307_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MM"
        threat_id = "2147660307"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\sockhelp32.exe" ascii //weight: 1
        $x_1_2 = "%s\\scansock.exe" ascii //weight: 1
        $x_1_3 = "http://%d.%d.%d.%d:808/GetMeInfo.aspx" ascii //weight: 1
        $x_1_4 = "%s?id=%s&pass=%s&place=%s&level=%d&money=%d&q1=%s&q2=%s&q3=%s&a1=%s&a2=%s&a3=%s&sj=%s&ver=%s&sign=%s" ascii //weight: 1
        $x_1_5 = "dnfhack.cy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_MO_2147661327_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MO"
        threat_id = "2147661327"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 b8 0b 00 00 ff d6 eb f7}  //weight: 1, accuracy: High
        $x_1_2 = {3f 61 31 3d 25 73 26 61 32 3d 25 73 26 61 33 3d 25 64 26 61 35 3d 25 73 26 61 34 3d 25 73 26 61 36 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 49 41 42 4c 4f 20 49 49 49 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 78 2e 6c 66 63 67 61 6d 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 33 2f 64 78 32 2f 77 6f 77 2e 61 73 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_MP_2147661332_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MP"
        threat_id = "2147661332"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Modl\\Mn\\" ascii //weight: 4
        $x_3_2 = {34 67 61 6d 65 5f 7a 61 70 75 73 6b 61 74 6f 72 2e 65 78 65 00}  //weight: 3, accuracy: High
        $x_3_3 = {5c 73 72 74 2e 65 78 65 00}  //weight: 3, accuracy: High
        $x_2_4 = {5a 61 70 75 73 6b 61 74 00}  //weight: 2, accuracy: High
        $x_2_5 = {72 5c 5f 64 61 74 61 5f 65 63 2e 74 6d 70 00}  //weight: 2, accuracy: High
        $x_1_6 = {5c 34 47 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {41 76 69 72 53 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {4e 6f 72 65 5c 42 72 74 5c 00}  //weight: 1, accuracy: High
        $x_1_9 = {53 6f 66 74 77 61 72 65 5c 34 67 61 6d 65 5c 34 47 61 6d 65 4d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_MQ_2147661346_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MQ"
        threat_id = "2147661346"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f4 5b c6 45 f5 5e c6 45 f6 26 c6 45 f7 5e c6 45 f8 0d c6 45 f9 5e c6 45 fa 0a c6 45 fb 5d c6 45 fc 26 e8}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 4c ff ff ff 68 c6 85 4d ff ff ff 61 c6 85 4e ff ff ff 6e c6 85 4f ff ff ff 67 c6 85 50 ff ff ff 61 c6 85 51 ff ff ff 6d c6 85 52 ff ff ff 65 c6 85 53 ff ff ff 2e c6 85 54 ff ff ff 63 c6 85 55 ff ff ff 6f c6 85 56 ff ff ff 6d}  //weight: 1, accuracy: High
        $x_1_3 = {26 73 65 63 72 65 74 41 6e 73 77 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 65 6d 61 69 6c 3d 00 26 72 65 71 75 65 73 74 54 79 70 65 3d 50 41 53 53 57 4f 52 44 5f 52 45 53 45 54 00 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58}  //weight: 1, accuracy: High
        $x_1_5 = "yaoyao25" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_OnLineGames_MR_2147662339_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MR"
        threat_id = "2147662339"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c6 74 2c 83 e8 65 74 07 2d c7 00 00 00 eb 1b ff 74 24 10 8b cf 68}  //weight: 1, accuracy: High
        $x_1_2 = {3d 96 00 00 00 74 05 83 c8 ff eb 5a 6a 00 8d 85 00 f0 ff ff 68 00 10 00 00 50 a1}  //weight: 1, accuracy: High
        $x_1_3 = {3d e3 00 00 00 5e 0f 85 c3 00 00 00 6a 28 ff 35 cc 6e 00 10 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {83 7d 08 78 59 59 75 0f 8d 45 e8 50 8d 45 a8 50 e8}  //weight: 1, accuracy: High
        $x_1_5 = {8b d8 c1 e2 10 23 de 89 45 0c 03 d3 33 db 8a 7d 0e c1 e2 08 03 d3 c1 e8 18 03 d0 89 11 83 c1 04 ff 4d 08 75 d6}  //weight: 1, accuracy: High
        $x_1_6 = "esck@team" ascii //weight: 1
        $x_1_7 = {25 64 2c 25 64 2c 25 64 2c 25 64 2c 25 64 2c 25 64 00 00 00 50 41 53 56 [0-4] 52 45 54 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_MS_2147667477_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MS"
        threat_id = "2147667477"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 33 65 6e 67 69 6e 65 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {76 15 8a 48 04 8a 54 (28|30|38) 05 (2a|32) d1 88 94 ?? (84|88) (00|fe) (40|46|47) 3b (30|38|c6) 72 ee}  //weight: 1, accuracy: Low
        $x_1_3 = {76 15 8a 4d 04 8a 54 (28|30|38) 05 (2a|32) d1 88 94 ?? (84|88) (00|fe) (40|46|47) 3b (30|38|c6) 72 ee}  //weight: 1, accuracy: Low
        $x_1_4 = {b2 5c 8d 8d fc fe ff ff e8 (78|8f) 01 00 00 ba ?? ?? ?? ?? 8d 48 01 e8 (df|f6) 00 00 00 85 c0 0f 84 9f 00 00 00 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 5c 50 e8 (8f|91) 01 00 00 40 68 ?? ?? ?? ?? 50 e8 (ed|ef) 00 00 00 83 85 c0 0f 84 (9f|a0) 00 00 00 8b}  //weight: 1, accuracy: Low
        $x_1_6 = {b2 5c 8d 4c 24 10 e8 d0 01 00 00 ba ?? ?? ?? ?? 8d 48 01 e8 23 01 00 00 85 c0 0f 84 b8 00 00 00 8b 35 38 10 00 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_2147668027_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MT"
        threat_id = "2147668027"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6a 40 6a 01 56 c7 44 24 14 00 00 00 00 ff 15 ?? ?? ?? ?? c6 06 e9 b8 01 00 00 00 8b 4c 24 0c 2b ce 83 e9 05 89 4e 01 5e 59 c2 08 00}  //weight: 2, accuracy: Low
        $x_1_2 = "rundll32.exe %s,DW" ascii //weight: 1
        $x_1_3 = "&a1=%s&a2=%s&a3=%s&a4=%s&a9=%s&a6=%s&a10=%s&a11=%d&a5=%s&a7=%s&pc1=%s&pc2=%s" ascii //weight: 1
        $x_1_4 = "wow.exe" ascii //weight: 1
        $x_1_5 = "Disker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_MW_2147679123_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MW"
        threat_id = "2147679123"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 68 68 66 64 2a 00 00 55 53}  //weight: 1, accuracy: High
        $x_1_2 = {77 69 6e 30 (36|37) 25 30 38 78 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 2e c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 65 [0-6] (6a 3e|f3 ab)}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 0e 57 33 ff 88 08 84 c9 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_MX_2147679160_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MX"
        threat_id = "2147679160"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cG9rZXI3LnxkdWVsUG9r" ascii //weight: 1
        $x_1_2 = "Y21kLiwwLDAsNDUwLDIw" ascii //weight: 1
        $x_1_3 = {77 6d 71 74 73 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_4 = "%99[^,],%d,%d,%d,%d,%d," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_MY_2147680237_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MY"
        threat_id = "2147680237"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 4d c6 05 ?? ?? 01 00 41 c6 05 ?? ?? 01 00 50 68 ?? ?? 01 00 c6 05 ?? ?? 01 00 44 c6 05 ?? ?? 01 00 4e c6 05 ?? ?? 01 00 46 04 00 c6 05}  //weight: 1, accuracy: Low
        $x_1_2 = "AHNLESTORY.EXE" ascii //weight: 1
        $x_1_3 = "WOW.EXE" ascii //weight: 1
        $x_1_4 = "DIABLO III.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_MZ_2147680340_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.MZ"
        threat_id = "2147680340"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?ap=%s&up=%s&pp=%s&ssp=%s" ascii //weight: 1
        $x_1_2 = "%s?up=%s&pp=%s&ssp=%s" ascii //weight: 1
        $x_2_3 = {3d 11 22 33 44 bd 01 00 00 00 0f 85 ?? ?? ?? ?? b9 2c 0b 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = {66 3d 06 00 74 0b 66 3d 05 00 74 05 bd 02 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_NK_2147683702_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NK"
        threat_id = "2147683702"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?zmac=%s&zsp=%s&yhp" ascii //weight: 1
        $x_1_2 = "&p_mny_bal=" ascii //weight: 1
        $x_1_3 = "&p_level=" ascii //weight: 1
        $x_1_4 = "XXYHCINDEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_OnLineGames_NQ_2147687567_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NQ"
        threat_id = "2147687567"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 6e 74 37 2d 62 43 43 37 36 00}  //weight: 1, accuracy: High
        $x_1_2 = "dompage.co.kr/board/data/log/test.php" ascii //weight: 1
        $x_1_3 = {63 3a 5c 61 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 0e 80 e9 03 80 f1 03 88 0e 46 48 75 f2 8b c6 5e c3}  //weight: 1, accuracy: High
        $x_1_5 = "mi~vroti0i~i" ascii //weight: 1
        $x_1_6 = {36 8b 45 14 a3 ?? ?? ?? ?? 36 8b 45 18 a3 ?? ?? ?? ?? 58 60 e8 ?? ?? ?? ?? 61 61 83 ec 44 56 57 ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_OnLineGames_NR_2147691694_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NR"
        threat_id = "2147691694"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svc=PASSWD" ascii //weight: 1
        $x_1_2 = "l.force.value=d+\"cbcb\"+p;/*" ascii //weight: 1
        $x_1_3 = "\\res\\PCOTP.okf" ascii //weight: 1
        $x_1_4 = "GameGuard.des" ascii //weight: 1
        $x_1_5 = "strLeftID+=\";path=/;domain=nexon.com;\";" ascii //weight: 1
        $x_1_6 = "paypal." ascii //weight: 1
        $x_1_7 = "page_gameid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_Lowfi_2147697001_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames!Lowfi"
        threat_id = "2147697001"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 e8 73 05 35 20 83 b8 ed 4a 75 f4 49 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = "NoahSystem" wide //weight: 1
        $x_1_3 = "Knight Online Client" wide //weight: 1
        $x_1_4 = "Warfare" wide //weight: 1
        $x_1_5 = "KnightOnline.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_OnLineGames_NV_2147718013_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NV!bit"
        threat_id = "2147718013"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "taskkill /f /im %s.exe" ascii //weight: 1
        $x_1_3 = "attrib +s +h \"%s\"" ascii //weight: 1
        $x_2_4 = {8a 07 b1 1a f6 e9 8a 4f 01 83 c7 02 02 c1 04 ?? 88 44 34 ?? 46 3b f5 7c}  //weight: 2, accuracy: Low
        $x_2_5 = {8a 02 33 c9 8a cf 32 c8 66 0f b6 c0 03 c3 88 0c 16 bb ?? ?? ?? ?? 8d 0c 40 c1 e1 04 2b c8 8d 0c 49 8d 0c 89 8d 0c c9 8d 04 48 2b d8 42 4f 75 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_NZ_2147719742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NZ!bit"
        threat_id = "2147719742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {54 72 6f 6a 61 6e 44 4c 4c 2e 64 6c 6c [0-16] 48 6f 6f 6b}  //weight: 4, accuracy: Low
        $x_1_2 = {53 65 74 48 6f 6f 6b 00 55 6e 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "?at=lock&s13=" ascii //weight: 1
        $x_1_4 = "&tbBankPwd=" ascii //weight: 1
        $x_1_5 = "\"lbBankMoney\">" ascii //weight: 1
        $x_1_6 = "\"lbBagMoney\">" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_NZ_2147719742_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.NZ!bit"
        threat_id = "2147719742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bns_helper.dll" ascii //weight: 1
        $x_1_2 = "cf_repair.dll" ascii //weight: 1
        $x_1_3 = "dnf_helper.dll" ascii //weight: 1
        $x_1_4 = "lol_tools.dll" ascii //weight: 1
        $x_1_5 = "game_mgr.dll.dll" ascii //weight: 1
        $x_4_6 = {54 72 6f 6a 61 6e 44 4c 4c 2e 64 6c 6c 00 48 61 6e 64 6c 65 48 6f 6f 6b 52 65 63 76 44 61 74 61 5f 46 72 6f 6d 4c 73 70}  //weight: 4, accuracy: High
        $x_1_7 = {53 65 74 48 6f 6f 6b 00 55 6e 48 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZGB_2147733061_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZGB!bit"
        threat_id = "2147733061"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FileCopy, %A_ScriptFullPath%, %A_Startup%\\Microsoft Security.exe" ascii //weight: 2
        $x_1_2 = "RegWrite, REG_SZ, HKCU, Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "FileSetAttrib, +H+S, %A_ScriptFullPath%" ascii //weight: 1
        $x_1_4 = "if clipboard contains /tradeoffer/new/?partner=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_OnLineGames_ZGE_2147733082_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/OnLineGames.ZGE!bit"
        threat_id = "2147733082"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OnClipboardChange" ascii //weight: 1
        $x_1_2 = "FileSetAttrib, +H+S" ascii //weight: 1
        $x_1_3 = "schtasks /create /tn System\\SystemDone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

