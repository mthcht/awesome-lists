rule Backdoor_Win32_Delf_AJ_2147595056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.AJ"
        threat_id = "2147595056"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "width=0 height=0></iframe>\"" ascii //weight: 1
        $x_2_2 = "-port 80 -insert \"<iframe src=" ascii //weight: 2
        $x_1_3 = "-idx 0 -ip " ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\SYSTEM32\\capinstall.exe" ascii //weight: 1
        $x_1_5 = "\\sevices.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_ABA_2147596909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ABA"
        threat_id = "2147596909"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "hackme" ascii //weight: 10
        $x_10_3 = "tggkontakt" ascii //weight: 10
        $x_10_4 = "KONTAKTY" ascii //weight: 10
        $x_10_5 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_6 = "UnhookWindowsHookEx" ascii //weight: 10
        $x_1_7 = "Numer" ascii //weight: 1
        $x_1_8 = "Haslo" ascii //weight: 1
        $x_1_9 = "screen.jpg" ascii //weight: 1
        $x_1_10 = "Wczytany Plik jest niepoprawny lub brak w nim has" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_XC_2147597407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.XC"
        threat_id = "2147597407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 1
        $x_1_5 = "block.intrich.com" ascii //weight: 1
        $x_1_6 = "hahahhohohehehehe" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
        $x_1_8 = "RegDeleteKeyA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_XB_2147597408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.XB"
        threat_id = "2147597408"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {32 32 32 2e 31 32 32 2e 03 00 2e 03 00 2f 64 6f 77 6e 6c 6f 61 64 2f 6d 6f 72 69 7a 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_3 = {32 32 32 2e 31 32 32 2e 03 00 2e 03 00 2f 69 6e 73 74 61 6c 6c 5f 63 6f 75 6e 74 2e 68 74 6d 6c 3f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {32 32 32 2e 31 32 32 2e 03 00 2e 03 00 2f 61 63 63 65 73 73 5f 63 6f 75 6e 74 2e 68 74 6d 6c 3f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "stop_agent.sys" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_XD_2147597521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.XD"
        threat_id = "2147597521"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "452"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 50
        $x_50_2 = "Kaisoft HTTPGet" ascii //weight: 50
        $x_50_3 = "Socket is already connected" wide //weight: 50
        $x_50_4 = "TIdTCPClient" ascii //weight: 50
        $x_50_5 = "Receive message from remote" ascii //weight: 50
        $x_50_6 = "HttpProxy" ascii //weight: 50
        $x_50_7 = "InternetReadFile" ascii //weight: 50
        $x_50_8 = "HttpSendRequestA" ascii //weight: 50
        $x_50_9 = "FtpPutFileA" ascii //weight: 50
        $x_1_10 = "autoruns.exe" ascii //weight: 1
        $x_1_11 = "procexp.exe" ascii //weight: 1
        $x_1_12 = "KavPFW.EXE" ascii //weight: 1
        $x_1_13 = "KPFW32.EXE" ascii //weight: 1
        $x_1_14 = "PFW.exe" ascii //weight: 1
        $x_1_15 = "SysSafe.exe" ascii //weight: 1
        $x_1_16 = "FireWall.exe" ascii //weight: 1
        $x_1_17 = "McAfeeFire.exe" ascii //weight: 1
        $x_1_18 = "FireTray.exe" ascii //weight: 1
        $x_1_19 = "ZoneAlarm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_50_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_ALC_2147597994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ALC"
        threat_id = "2147597994"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 00 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f 00 00 00 ff ff ff ff 0a 00 00 00 68 69 64 65 20 31 30 30 30 30 00 00 ff ff ff ff 38 00 00 00 63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f 5c 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f 2e 65 78 65 00}  //weight: 3, accuracy: High
        $x_3_2 = {68 74 74 70 3a 2f 2f 6e 65 6f 73 61 70 2e 72 75 2f 00 00 00 ff ff ff ff 16 00 00 00 68 74 74 70 3a 2f 2f 73 75 70 65 72 2d 74 64 73 2e 69 6e 66 6f 2f 00 00 ff ff ff ff 17 00 00 00 68 74 74 70 3a 2f 2f 69 31 69 69 31 69 69 31 31 69 2e 69 6e 66 6f 2f 00 ff ff ff ff 16 00 00 00 68 74 74 70 3a 2f 2f 31 69 69 31 69 31 69 69 31 31 2e 63 6f 6d 2f 00 00 ff ff ff ff 15 00 00 00 68 74 74 70 3a 2f 2f 69 75 31 31 75 69 31 69 6c 6c 2e 77 73 2f 00 00 00 ff ff ff ff 0e 00 00 00 68 74 74 70 3a 2f 2f 78 65 70 2e 72 75 2f}  //weight: 3, accuracy: High
        $x_2_3 = {75 69 6e 2e 74 78 74 00 ff ff ff ff 0a 00 00 00 64 64 2e 6d 6d 2e 79 79 79 79 00 00 ff ff ff ff 0b 00 00 00 74 65 73 74 73 70 72 66 31 32 33}  //weight: 2, accuracy: High
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Gay-Lesbian-Photo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_BTP_2147598407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.BTP"
        threat_id = "2147598407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "onsafety.net/xpdemon.php?no=" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\XPDemon" ascii //weight: 1
        $x_1_4 = "TIdTCPClient" ascii //weight: 1
        $x_1_5 = "TPopupList" ascii //weight: 1
        $x_1_6 = "gethostbyname" ascii //weight: 1
        $x_1_7 = "sendto" ascii //weight: 1
        $x_1_8 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_RAK_2147601251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.RAK"
        threat_id = "2147601251"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0x%.2x%.2x%.2x%.2x%.2x%.2x" ascii //weight: 1
        $x_1_2 = "Set cdaudio door open wait" ascii //weight: 1
        $x_1_3 = {44 4f 4d 00 ff ff ff ff 04 00 00 00 46 52 45 45}  //weight: 1, accuracy: High
        $x_5_4 = {89 45 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 33 c9 ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 84 c0 74 0d ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_RAL_2147601365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.RAL"
        threat_id = "2147601365"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 4f 4d 00 ff ff ff ff 04 00 00 00 46 52 45 45}  //weight: 1, accuracy: High
        $x_1_2 = {24 00 00 00 56 49 44 45 4f}  //weight: 1, accuracy: High
        $x_1_3 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 00 00 00 00 ff ff ff ff 1f 00 00 00 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 ff ff ff ff 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 8b ec 83 c4 f8 53 56 33 c0 89 45 fc bb ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 68 60 ea 00 00 e8 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 00 75 0c 8b 03 e8 ?? ?? ?? ?? e9 8b 00 00 00 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 55 fc 66 b8 6d 00 e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 8d 45 fc e8 ?? ?? ?? ?? 8b d0 8b 45 f8 59 8b 30 ff 56 10 eb 14 8b 55 f8 8b 03 e8 ?? ?? ?? ?? 68 c0 d4 01 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {83 38 00 75 0f 68 10 27 00 00 e8 ?? ?? ?? ?? e9 12 02 00 00 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 8b c8 8b 15 ?? ?? ?? ?? 8b 12 8b 45 f0 e8 ?? ?? ?? ?? 8b 45 f0 8a 40 0c 22 45 f7 0f 84 c5 01 00 00 68 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? e9 a9 01 00 00 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_SJ_2147601368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.SJ"
        threat_id = "2147601368"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "92"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\" ascii //weight: 10
        $x_10_2 = "TServerInfoL" ascii //weight: 10
        $x_10_3 = "917744542394704404682954017491" ascii //weight: 10
        $x_10_4 = "127.0.0.1" ascii //weight: 10
        $x_10_5 = ":(Net Disk)" ascii //weight: 10
        $x_10_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\WinOldApp" ascii //weight: 10
        $x_10_8 = "Toolhelp32ReadProcessMemory" ascii //weight: 10
        $x_10_9 = "ChangeServiceConfig2A" ascii //weight: 10
        $x_1_10 = "http://ip.aq138.com/getip.asp?aquser=" ascii //weight: 1
        $x_1_11 = "http://ip.aq138.com/setip.asp" ascii //weight: 1
        $x_1_12 = "http://192.168.1.5/get.asp?user=" ascii //weight: 1
        $x_1_13 = "http://192.168.1.5/set.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_AAE_2147601477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.AAE"
        threat_id = "2147601477"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "C:\\skrin.jpg" ascii //weight: 1
        $x_1_3 = "C:\\host\\log.txt" ascii //weight: 1
        $x_1_4 = "c:\\plik.exe" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\svhosted.exe" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "Tekst w Schowku:" ascii //weight: 1
        $x_1_8 = {6a 00 6a 00 49 75 f9 53 89 45 fc bb ?? ?? 49 00 33 c0 55 68 ?? ?? 48 00 64 ff 30 64 89 20 6a 00 a1 64 f6 48 00 50 68 ?? ?? 48 00 6a 00 e8 ?? ?? f7 ff a3 ?? ?? 49 00 a1 ?? ?? 48 00 8b 00 c6 40 5b 00 6a ff 68 ?? ?? 48 00 8d 55 f8 33 c0 e8 ?? ?? f7 ff 8b 45 f8 e8 ?? ?? f7 ff 50 e8 ?? ?? f7 ff 8d 55 f4}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 ac ba 02 00 00 00 e8 ?? ?? f7 ff 68 ?? ?? 48 00 8d 55 a0 33 c0 e8 ?? ?? f7 ff 8b 45 a0 e8 ?? ?? f7 ff 50 e8 ?? ?? f7 ff b2 01 a1 ?? ?? 42 00 e8 ?? ?? f9 ff a3 ?? ?? 49 00 ba 02 00 00 80 a1 ?? ?? 49 00 e8 ?? ?? f9 ff 33 c0 55 68 ?? ?? 48 00 64 ff 30 64 89 20 b1 01 ba ?? ?? 48 00 a1 ?? ?? 49 00 e8 ?? ?? f9 ff 68 ?? ?? 48 00 8d 55 98 8b 45 fc 8b 80 2c 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_KZ_2147601780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.KZ"
        threat_id = "2147601780"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "331"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "explorerbar" wide //weight: 100
        $x_100_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_3 = "winUpdate - Microsoft Internet Explorer" ascii //weight: 100
        $x_10_4 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_5 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_6 = "InternetGetConnectedState" ascii //weight: 10
        $x_1_7 = "\\Temp\\iexplore.exe" ascii //weight: 1
        $x_1_8 = "\\Temp\\msn.exe" ascii //weight: 1
        $x_1_9 = "\\Temp\\Firewalll.exe" ascii //weight: 1
        $x_1_10 = "http://www.voxcards.com.br" ascii //weight: 1
        $x_1_11 = "http://feliz2008.land.ru/iexplore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_ADE_2147602092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ADE"
        threat_id = "2147602092"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "273"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "remote network & conctrol service" ascii //weight: 100
        $x_10_3 = "DisableRegistryTools" ascii //weight: 10
        $x_10_4 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_5 = "Toolhelp32ReadProcessMemory" ascii //weight: 10
        $x_10_6 = "sysi.dll" ascii //weight: 10
        $x_10_7 = "ServiceDll" ascii //weight: 10
        $x_10_8 = "cmd /c del " ascii //weight: 10
        $x_10_9 = "svchost.exe -k " ascii //weight: 10
        $x_1_10 = "msnmsgr." ascii //weight: 1
        $x_1_11 = "trillian." ascii //weight: 1
        $x_1_12 = "googletalk." ascii //weight: 1
        $x_1_13 = "yahoomessenger." ascii //weight: 1
        $x_1_14 = "svchost." ascii //weight: 1
        $x_1_15 = "avpcc.ex" ascii //weight: 1
        $x_1_16 = "msimn.ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_ALE_2147602201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ALE"
        threat_id = "2147602201"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "explorerbar" wide //weight: 10
        $x_10_2 = "\\wsass32.exe" ascii //weight: 10
        $x_10_3 = "INFECTANDOOO" ascii //weight: 10
        $x_10_4 = "Infectado OnLine" ascii //weight: 10
        $x_10_5 = "OBAAA TEM FESTA HOJEEEE" ascii //weight: 10
        $x_1_6 = "mstxts@gmail.com" ascii //weight: 1
        $x_1_7 = "carderx@gmail.com" ascii //weight: 1
        $x_1_8 = "rafa5633456544@gmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_ALF_2147602203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ALF"
        threat_id = "2147602203"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "explorerbar" wide //weight: 10
        $x_10_2 = "c:\\autoexe.exe" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = "http://207.58.162.237/spy/cartao.scr" ascii //weight: 10
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_ADG_2147603117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ADG"
        threat_id = "2147603117"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 53 68 d8 49 40 00 6a 00 e8 65 fb ff ff 33 c0 e8 b2 e9 ff ff eb 1b 8d 55 c8 b8 01 00 00 00 e8 4f e0 ff ff 8b 45 c8 e8 ff eb ff ff 50 e8 21 f1 ff ff a1 50 69 40 00 ba e8 49 40 00 e8 36 eb ff ff 0f 85 c0 00 00 00 8d 45 c4 e8 90 fb ff ff ff 75 c4 68 c4 49 40 00 8d 55 bc 33 c0 e8 12 e0 ff ff 8b 45 bc 8d 55 c0 e8 e7 fc ff ff ff 75 c0 b8 5c 69 40 00 ba 03 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_3 = "Win32 Service" ascii //weight: 1
        $x_1_4 = "sau=yes???" ascii //weight: 1
        $x_1_5 = "lol.html" ascii //weight: 1
        $x_1_6 = "sys32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Delf_ADH_2147603123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ADH"
        threat_id = "2147603123"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 c4 53 56 57 33 d2 89 55 c4 89 55 c8 89 55 d0 89 55 cc 89 55 d8 89 55 d4 89 45 fc 8b 45 fc e8 e4 b4 ff ff 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 55 d4 b8 01 00 00 00 e8 35 fd ff ff ff 75 d4 ff 75 fc 68 ?? ?? ?? ?? 8d 45 d8 ba 03 00 00 00 e8 25 b4 ff ff 8b 45 d8 e8 b9 b4 ff ff 8b f8 8d 55 cc 33 c0 e8 09 fd ff ff ff 75 cc ff 75 fc 68 ?? ?? ?? ?? 8d 45 d0 ba 03 00 00 00 e8 f9 b3 ff ff 8b 45 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 8d b4 ff ff 89 45 f8 68 3f 00 0f 00 6a 00 6a 00 e8 ?? ?? ?? ?? 8b d8 85 db 0f 84 a0 00 00 00 68 ff 01 0f 00 8b 45 fc e8 65 b4 ff ff 50 53 e8 ?? ?? ?? ?? 8b f0 85 f6 75 08 53 e8 ?? ?? ?? ?? eb 43 8d 45 dc 50 56 e8 ?? ?? ?? ?? 85 c0 74 2f 83 7d e0 01 74 29 8d 45 dc 50 6a 01 56 e8 ?? ?? ?? ?? 85 c0 74 19 eb 11 6a 0a e8 ?? ?? ?? ?? 8d 45 dc 50 56 e8 ?? ?? ?? ?? 83 7d e0 03 74 e9 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 68 dc 05 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "ControlService" ascii //weight: 1
        $x_1_4 = "QueryServiceStatus" ascii //weight: 1
        $x_1_5 = "DeleteService" ascii //weight: 1
        $x_1_6 = "svchost" ascii //weight: 1
        $x_1_7 = "kernl32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_RAN_2147605147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.RAN"
        threat_id = "2147605147"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%SystemRoot%\\System32\\svchost.exe -k krnlsrvc" ascii //weight: 1
        $x_1_2 = "ERASE /F /A \"" ascii //weight: 1
        $x_1_3 = "\" goto TNND" ascii //weight: 1
        $x_10_4 = {8d 45 fc ba 04 00 00 00 e8 ?? ?? ?? ?? 8b 55 fc 8d 85 2c fd ff ff e8 ?? ?? ?? ?? 8d 85 2c fd ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 85 2c fd ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 1c fd ff ff 8d 95 f8 fe ff ff b9 04 01 00 00 e8 ?? ?? ?? ?? ff b5 1c fd ff ff 68 ?? ?? ?? ?? 8d 85 20 fd ff ff ba 03 00 00 00}  //weight: 10, accuracy: Low
        $x_10_5 = {84 c0 74 59 8b 45 f4 e8 ?? ?? ?? ?? 83 fa 00 75 07 83 f8 00 72 39 eb 02 7c 35 ff 36 68 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 52 50 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b c6 ba 04 00 00 00 e8 ?? ?? ?? ?? eb 1a 8b c6 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0c 8b c6 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 5a 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_WC_2147605576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.WC"
        threat_id = "2147605576"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 50 e8 ?? ?? ff ff c6 85 ?? fe ff ff 55 c6 85 ?? fe ff ff 50 c6 85 ?? fe ff ff 58 c6 85 ?? fe ff ff 32 c6 85 ?? fe ff ff 00 c6 85 ?? fe ff ff 00 c6 85 ?? fe ff ff 00 c6 85 ?? fe ff ff 00 8b 85 ?? ff ff ff 89 85 ?? fe ff ff c7 85 ?? fe ff ff 00 04 00 00 c7 85 ?? fe ff ff 00 04 00 00 8b 85 ?? fe ff ff 03 85 ?? fe ff ff 89 85 ?? fe ff ff c7 85 ?? fe ff ff 20 00 00 e6}  //weight: 10, accuracy: Low
        $x_10_2 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c [0-128] 44 65 73 63 72 69 70 74 69 6f 6e [0-128] 5c 50 61 72 61 6d 65 74 65 72 73 [0-128] 53 65 72 76 69 63 65 44 6c 6c}  //weight: 10, accuracy: Low
        $x_5_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 5
        $x_5_4 = "svchost.exe -k netsvcs" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_ADI_2147605932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ADI"
        threat_id = "2147605932"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c4 f8 fe ff ff c6 04 24 00 68 ?? ?? ?? ?? 8d 44 24 04 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 44 24 04 50 e8 ?? ?? ?? ?? 6a 00 8d 44 24 04 50 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 81 c4 08 01 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_3 = "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_5 = "CreateServiceA" ascii //weight: 1
        $x_1_6 = "StartServiceA" ascii //weight: 1
        $x_1_7 = "cmd /c del C:\\myapp.exe" ascii //weight: 1
        $x_1_8 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_NB_2147607602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.NB"
        threat_id = "2147607602"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%SystemRoot%\\System32\\svchost.exe -k krnlsrvc" ascii //weight: 1
        $x_1_2 = {69 66 20 65 78 69 73 74 20 22 00 00 ff ff ff ff 0c 00 00 00 22 20 67 6f 74 6f 20 52 65 64 65 6c}  //weight: 1, accuracy: High
        $x_1_3 = "Capture'Capture" ascii //weight: 1
        $x_1_4 = "ChangeServiceConfigA" ascii //weight: 1
        $x_1_5 = "setsockopt" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_ZSU_2147607786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ZSU"
        threat_id = "2147607786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {75 2c c7 05 ?? ?? 40 00 9f 86 01 00 bb 65 00 00 00 be ?? ?? 40 00 8b 06 85 c0 74 05 e8 ?? ?? ff ff 83 c6 04 4b 75 ef 6a 00}  //weight: 4, accuracy: Low
        $x_2_2 = {50 69 6e 67 [0-16] 43 68 61 74 [0-16] 43 6c 6f 73 65 [0-32] 43 68 61 6e 67 65 4e 61 6d 65 7c}  //weight: 2, accuracy: Low
        $x_2_3 = {25 43 4f 4d 50 55 54 45 52 4e 41 4d 45 25 [0-16] 25 4f 50 45 52 41 54 49 4e 47 53 59 53 54 45 4d 25 [0-16] 25 43 4f 55 4e 54 52 59 25}  //weight: 2, accuracy: Low
        $x_2_4 = {34 2e 30 2e [0-16] 7c 4f 6e 43 6f 6e 6e 65 63 74 7c [0-16] 52 75 6e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 7c}  //weight: 2, accuracy: Low
        $x_2_5 = {73 65 72 76 65 72 2e 65 78 65 00 53 65 6e 64 44 61 74 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_BN_2147607936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.BN"
        threat_id = "2147607936"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {2c 00 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "OpenServiceA" ascii //weight: 1
        $x_1_4 = "Micorsoft Corporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_BO_2147608030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.BO"
        threat_id = "2147608030"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "System\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "\\drivers\\svchost.exe" ascii //weight: 1
        $x_1_4 = "\\wait16.ini" ascii //weight: 1
        $x_1_5 = ":*:Enabled:Test" ascii //weight: 1
        $x_1_6 = "PRIVMSG" ascii //weight: 1
        $x_1_7 = {8b 95 38 fe ff ff 8d 45 f4 59 e8 ?? ?? ff ff 68 ?? ?? 40 00 ff 75 f8 68 ?? ?? 40 00 ff 75 f4 8d 85 2c fe ff ff ba 04 00 00 00 e8 ?? ?? ff ff 8b 95 2c fe ff ff a1 ?? ?? 40 00 e8 ?? ?? ff ff 8b 45 f4 e8 ?? ?? ff ff b9 0a 00 00 00 99 f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_UA_2147609305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.UA"
        threat_id = "2147609305"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 ff ff ff ff 17 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 6d 73 73 79 73 74 65 6d 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "open adres_www -" ascii //weight: 1
        $x_1_3 = "timeshow/timehide - pokazuje" ascii //weight: 1
        $x_1_4 = "pulpitshow/pulpithide -" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Delf_DH_2147609700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.DH"
        threat_id = "2147609700"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "144"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "msupdate.exe" ascii //weight: 10
        $x_10_3 = "erase \"%s\"" ascii //weight: 10
        $x_10_4 = "if exist \"%s\" Goto" ascii //weight: 10
        $x_10_5 = {5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_6 = "WSAStartup" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Runservices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_IM_2147617644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.IM"
        threat_id = "2147617644"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "exe.tsohcvs\\srevird\\" ascii //weight: 10
        $x_10_3 = "nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM\\erawtfoS" ascii //weight: 10
        $x_10_4 = "tsiL\\snoitacilppAdezirohtuA\\eliforPdradnatS\\yciloPllaweriF\\sretemaraP\\sseccAderahS\\secivreS\\100teSlortnoC\\metsyS" ascii //weight: 10
        $x_10_5 = "mail@mail.com" ascii //weight: 10
        $x_10_6 = "NICK " ascii //weight: 10
        $x_10_7 = "USER " ascii //weight: 10
        $x_1_8 = "WCKBSV01" ascii //weight: 1
        $x_1_9 = "Software\\PalTalk" ascii //weight: 1
        $x_1_10 = "ini.61tiaw\\" ascii //weight: 1
        $x_1_11 = "66.102.11.99" ascii //weight: 1
        $x_1_12 = "@hotmail.com" ascii //weight: 1
        $x_1_13 = "7666:131.991.95.212" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_HY_2147619779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.HY"
        threat_id = "2147619779"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRIVMSG _Tiago__ #xpc Ping da morte ativado!! :D" ascii //weight: 1
        $x_1_2 = "PRIVMSG _Tiago__ #xpc Buffer alterado para:" ascii //weight: 1
        $x_1_3 = "taskkill -f -im ping.exe" ascii //weight: 1
        $x_1_4 = "IRC Channel Linker (c) CREEQ" ascii //weight: 1
        $x_1_5 = "yahoobuddymain" ascii //weight: 1
        $x_1_6 = "yahoo! messenger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_IS_2147622081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.IS"
        threat_id = "2147622081"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_2 = {6a 00 6a 00 8d 85 ?? ?? ?? ?? 50 8b 06 83 c0 02 50 6a 00 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 06 0f b6 40 01 50 6a 00 6a 00 8d 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {89 5f 04 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 07 66 c7 44 24 04 02 00 56 e8 ?? ?? ?? ?? 66 89 44 24 06 8b 47 04 50 e8 ?? ?? ?? ?? 8b f0 89 74 24 08 46 75 ?? 8b 47 04 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_IV_2147624275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.IV"
        threat_id = "2147624275"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_2 = {68 3f 00 0f 00 6a 00 6a 00 e8 ?? ?? ?? ?? 89 45 e0 6a 00 6a 00 8d 45 d8 50 8d 45 dc 50 68 00 80 00 00 8d 85 ?? ?? ff ff 50 6a 03 6a 30 6a 00 8b 45 e0 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 00 6a 01 e8 ?? ?? ?? ?? 8b d8 6a 00 53 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 68 88 13 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_IW_2147624276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.IW"
        threat_id = "2147624276"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 5c 5c 2e 5c 53 4d 41 52 54 56 53 44}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 8d 85 ?? ?? ff ff 50 68 10 02 00 00 8d 85 ?? ?? ff ff 50 6a 20 8d 85 ?? ?? ff ff 50 68 88 c0 07 00 8b 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {66 ba 2e 00 66 b8 03 00 e8 ?? ?? ?? ?? 50 6a 00 68 12 03 00 00 68 ff ff 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_IX_2147624554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.IX"
        threat_id = "2147624554"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff ff 12 00 00 00 64 65 6c 20 2e 5c 64 65 6c 6d 65 65 78 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 43 20 b1 45 ba e8 fd 00 00 e8 ?? ?? ?? ?? 0f b7 17}  //weight: 1, accuracy: Low
        $x_1_3 = {89 43 04 8b 45 14 e8 ?? ?? ?? ?? 66 83 c0 1c 66 89 07 66 b8 04 00 66 c7 45 ?? 05 00 c1 e0 04 0a 45 ?? 88 45 ?? c6 45 ?? 00 66 8b 07 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_JC_2147625213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.JC"
        threat_id = "2147625213"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 59 57 53 68 65 6c 6c 20 53 65 72 76 65 72 2e 0d 0a 50 72 65 73 73 20 45 6e 74 65 72 20 74 6f 20 73 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_2 = {89 c7 b8 00 00 00 00 0f a2 89 d8 87 d9 b9 04 00 00 00 aa c1 e8 08 e2 fa 89 d0 b9 04 00 00 00 aa c1 e8 08 e2 fa 89 d8 b9 04 00 00 00 aa c1 e8 08 e2 fa 5f 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_JG_2147626709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.JG"
        threat_id = "2147626709"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 73 76 63 68 6f 73 74 2e 65 78 65 0c 6e 74 64 65 74 65 63 74 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "www.wardomania.com" ascii //weight: 1
        $x_1_3 = {8b 45 fc 0f b6 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 0f b6 44 30 ff 24 0f 32 d8 80 f3 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 3a ff 80 e2 f0 02 d3 88 54 38 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_LB_2147634513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.LB"
        threat_id = "2147634513"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "36%xsvc" ascii //weight: 2
        $x_2_2 = "LsET\\sERVICES\\%s" ascii //weight: 2
        $x_3_3 = {73 63 76 73 74 65 6e ?? 6b 2d}  //weight: 3, accuracy: Low
        $x_2_4 = "hcvs\\23metsyS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_JX_2147636688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.JX"
        threat_id = "2147636688"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Print Screen]" ascii //weight: 1
        $x_2_2 = "\\wauaclt.lnk" ascii //weight: 2
        $x_1_3 = "webcamfail" ascii //weight: 1
        $x_1_4 = ":Online:" ascii //weight: 1
        $x_1_5 = "firstbmp" ascii //weight: 1
        $x_2_6 = "wauaclt-.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Delf_LE_2147651362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.LE"
        threat_id = "2147651362"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "{6ADE9596-9FB4-426A-AC6B-DAE5BA95C49A}" ascii //weight: 4
        $x_4_2 = "PlusCmdConstUnit" ascii //weight: 4
        $x_2_3 = "UrlJudge" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_LY_2147654033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.LY"
        threat_id = "2147654033"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii //weight: 1
        $x_1_2 = "receber" ascii //weight: 1
        $x_2_3 = "Logon User Name" ascii //weight: 2
        $x_6_4 = "C:\\Windows\\System\\basilisco.exe" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_MN_2147670639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.MN"
        threat_id = "2147670639"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 56 b3 01 b8 50 c3 00 00 e8 ?? ?? ?? ?? 66 05 dc 05 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {56 8d 7e 4a 8d 75 e8 a5 a5 a5 a5 5e 8d 55 e4 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {7c 12 43 8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Delf_ZSW_2147711721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.ZSW!bit"
        threat_id = "2147711721"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 10
        $x_10_2 = {77 69 6e 64 69 72 [0-16] 70 72 6f 67 72 61 6d [0-16] 50 72 6f 67 72 61 6d 46 69 6c 65 73}  //weight: 10, accuracy: Low
        $x_10_3 = {5b 50 61 67 65 20 44 6f 77 6e 5d [0-16] 5b 45 6e 64 5d [0-16] 5b 48 6f 6d 65 5d [0-16] 5b 4c 65 66 74 5d [0-16] 5b 55 70 5d}  //weight: 10, accuracy: Low
        $x_1_4 = "sdn=" ascii //weight: 1
        $x_1_5 = "sco=" ascii //weight: 1
        $x_1_6 = "sna=" ascii //weight: 1
        $x_1_7 = "spa=" ascii //weight: 1
        $x_1_8 = "sln=" ascii //weight: 1
        $x_1_9 = "spo=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_PF_2147733155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.PF"
        threat_id = "2147733155"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYS_INFO" ascii //weight: 1
        $x_1_2 = "GET_NETWORK" ascii //weight: 1
        $x_1_3 = "KEYLOG" ascii //weight: 1
        $x_1_4 = "scan {all} *.docx, *.xlsx, *.pdf," ascii //weight: 1
        $x_1_5 = "FOR /F \"tokens=2 delims=[]\" %%i IN ('ping -a -n 1 -w 0 %%n" ascii //weight: 1
        $x_1_6 = "C:\\Users\\Public\\officeexcp.bin" ascii //weight: 1
        $x_1_7 = "C:\\Users\\Public\\dset.ini" ascii //weight: 1
        $x_1_8 = "C:\\Users\\Public\\kla.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Delf_PG_2147733156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.PG"
        threat_id = "2147733156"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\dset.ini" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\boot.ini" ascii //weight: 1
        $x_1_3 = "SYS_INFO" ascii //weight: 1
        $x_1_4 = "EG_EXPAND" ascii //weight: 1
        $x_1_5 = "UserInitMprLogonScript" ascii //weight: 1
        $x_1_6 = "HKCU\\Environment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Delf_BA_2147834218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Delf.BA!MTB"
        threat_id = "2147834218"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b d3 8b da d1 eb 33 98 34 06 00 00 83 e2 01 33 1c 95 b0 90 40 00 89 18 83 c0 04 49 75}  //weight: 2, accuracy: High
        $x_2_2 = {88 c3 32 1e c1 e8 08 46 33 04 9d 94 b6 40 00 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

