rule Worm_Win32_VB_EB_2147575487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.EB"
        threat_id = "2147575487"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 00 4b 00 45 00 59 00 47 00 45 00 4e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 20 00 47 00 75 00 61 00 72 00 64 00 3a 00 20 00 41 00 74 00 74 00 65 00 6e 00 74 00 69 00 6f 00 6e 00 2c 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 70 00 72 00 65 00 61 00 64 00 62 00 79 00 6c 00 61 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_ZC_2147582719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.ZC"
        threat_id = "2147582719"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\NOHIDDEN" wide //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 10
        $x_10_4 = "DisableRegistryTools" wide //weight: 10
        $x_1_5 = "COBA WORM\\Pictures\\Text.ico" wide //weight: 1
        $x_1_6 = "\\Project\\VB\\COBA WORM\\SYSTEMIL.vbp" wide //weight: 1
        $x_1_7 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 41 00 6c 00 6c 00 20 00 55 00 73 00 65 00 72 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 49 00 4c 00 ?? 2e 00 45 00 58 00 45 00}  //weight: 1, accuracy: Low
        $x_1_8 = "E:\\Didi Iswad" wide //weight: 1
        $x_1_9 = "Documents.exe" wide //weight: 1
        $x_1_10 = "Pictures.exe" wide //weight: 1
        $x_1_11 = "Photos.exe" wide //weight: 1
        $x_1_12 = "Games.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_2147594069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB"
        threat_id = "2147594069"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "740"
        strings_accuracy = "High"
    strings:
        $x_500_1 = "\\Lucky\\My Document\\Visual Basic 6.0\\Downloader\\worm2007.vbp" wide //weight: 500
        $x_100_2 = "http://rapidnews.org/worm2007.exe" wide //weight: 100
        $x_100_3 = "http://www.xmas4u.net/update.dat" wide //weight: 100
        $x_100_4 = "http://64.26.25.75/zin.exe" wide //weight: 100
        $x_10_5 = "taskkill /im firefox.exe" wide //weight: 10
        $x_10_6 = "lsass.exe" wide //weight: 10
        $x_10_7 = "MSconfig.exe" wide //weight: 10
        $x_10_8 = "open=boot.exe" wide //weight: 10
        $x_10_9 = "shellexecute=boot.exe" wide //weight: 10
        $x_10_10 = "shell\\Auto\\command=boot.exe" wide //weight: 10
        $x_10_11 = "New Folder.exe" wide //weight: 10
        $x_10_12 = "userinit.exe" wide //weight: 10
        $x_10_13 = "Program Files\\Mozilla Firefox\\firefox.exe" wide //weight: 10
        $x_10_14 = "WINDOWS\\pchealth\\helpctr\\binaries\\msconfig.exe" wide //weight: 10
        $x_10_15 = "\\system32\\restore\\rstrui.exe" wide //weight: 10
        $x_10_16 = "Software\\Yahoo\\pager\\View\\YMSGR_buzz" wide //weight: 10
        $x_10_17 = "Software\\Yahoo\\pager\\View\\YMSGR_Launchcast" wide //weight: 10
        $x_10_18 = "DisableTaskMgr" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_500_*) and 1 of ($x_100_*) and 14 of ($x_10_*))) or
            ((1 of ($x_500_*) and 2 of ($x_100_*) and 4 of ($x_10_*))) or
            ((1 of ($x_500_*) and 3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_AT_2147594780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.AT"
        threat_id = "2147594780"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~C:\\Program Files\\Messenger\\msmsgs.exe\\3" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\system32\\MSVBVM60.DLL\\3" ascii //weight: 1
        $x_1_3 = "WritePrivateProfileStringA" ascii //weight: 1
        $x_1_4 = "Zombie_GetTypeInfoCount" ascii //weight: 1
        $x_1_5 = "@udio\\VB98\\" wide //weight: 1
        $x_1_6 = "\\snew.exe" wide //weight: 1
        $x_1_7 = "\\sold.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_VB_AT_2147594780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.AT"
        threat_id = "2147594780"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schedule" wide //weight: 1
        $x_1_2 = "hklm\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Sysinf.bat" wide //weight: 1
        $x_1_4 = "cmd /sc at" wide //weight: 1
        $x_1_5 = "INCUBUS" ascii //weight: 1
        $x_1_6 = "WINORD" wide //weight: 1
        $x_1_7 = "date %date%" wide //weight: 1
        $x_1_8 = "c:\\ntldr" wide //weight: 1
        $x_1_9 = "Office User ID " wide //weight: 1
        $x_1_10 = "del %0" wide //weight: 1
        $x_1_11 = "8.exe" wide //weight: 1
        $x_1_12 = "set date=2003-02-10" wide //weight: 1
        $x_1_13 = "UserInit.exe," wide //weight: 1
        $x_1_14 = "At.exe" wide //weight: 1
        $x_1_15 = "KavUpda.exe" wide //weight: 1
        $x_1_16 = "Help\\HelpCat.exe" wide //weight: 1
        $x_1_17 = "dllcache\\sol.exe" wide //weight: 1
        $x_1_18 = "Option.bat" wide //weight: 1
        $x_1_19 = "D:\\RECYCLER\\" wide //weight: 1
        $x_1_20 = "net.exe" wide //weight: 1
        $x_1_21 = "reg.exe" wide //weight: 1
        $x_1_22 = "ping -n 10 localhost > nul " wide //weight: 1
        $x_1_23 = "copyme" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (18 of ($x*))
}

rule Worm_Win32_VB_CB_2147594860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.CB"
        threat_id = "2147594860"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "226"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MSVBVM60.DLL" ascii //weight: 100
        $x_100_2 = "DllFunctionCall" ascii //weight: 100
        $x_10_3 = "\\SourceDungcoi\\Dung_DakNong.vbp" wide //weight: 10
        $x_10_4 = "I am DungCoi by DungCoiDakNong" wide //weight: 10
        $x_10_5 = "http://dungcoivb.googlepages.com/NWB.txt" wide //weight: 10
        $x_10_6 = "Chuc mung, ban da tam thoi thoat khoi Worm DungCoi" wide //weight: 10
        $x_10_7 = "Olalala, may tinh cua ban da dinh Worm DungCoi" wide //weight: 10
        $x_5_8 = "dungcoi_vb" wide //weight: 5
        $x_5_9 = "yahoobuddymain" wide //weight: 5
        $x_5_10 = "ymsgr:sendIM?" wide //weight: 5
        $x_1_11 = "ShellExecuteA" ascii //weight: 1
        $x_1_12 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_13 = "InternetGetConnectedStateEx" ascii //weight: 1
        $x_1_14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_BCA_2147595732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.BCA"
        threat_id = "2147595732"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\All Users\\Start Menu\\Start Menu.exe" wide //weight: 5
        $x_5_2 = "\\All Users\\Start Menu\\Programs\\Startup\\Startup.exe" wide //weight: 5
        $x_5_3 = "\\All Users\\Start Menu\\Programs\\Programs.exe" wide //weight: 5
        $x_5_4 = "\\My Documents\\My Ducuments.exe" wide //weight: 5
        $x_10_5 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide //weight: 10
        $x_10_6 = "SeShutdownPrivilege" wide //weight: 10
        $x_10_7 = "wscript.shell" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_ZE_2147595958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.ZE"
        threat_id = "2147595958"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "c:\\windows\\zistro.exe" wide //weight: 20
        $x_20_2 = "Tiara Lestari.exe" wide //weight: 20
        $x_20_3 = "Removable Drive" wide //weight: 20
        $x_20_4 = "Fixed Drive" wide //weight: 20
        $x_20_5 = "Remote Drive" wide //weight: 20
        $x_1_6 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden" wide //weight: 1
        $x_1_7 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\\CheckedValue" wide //weight: 1
        $x_1_8 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\\DefaultValue" wide //weight: 1
        $x_1_9 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\NOHIDDEN\\CheckedValue" wide //weight: 1
        $x_1_10 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\NOHIDDEN\\DefaultValue" wide //weight: 1
        $x_1_11 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_12 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegedit" wide //weight: 1
        $x_1_13 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt" wide //weight: 1
        $x_1_14 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\test" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_FP_2147597941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FP"
        threat_id = "2147597941"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "208"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\server\\Project1.vbp" wide //weight: 1
        $x_1_2 = "http://man-u.net/vb/send.php" wide //weight: 1
        $x_1_3 = "?mail=" wide //weight: 1
        $x_1_4 = "&subject=" wide //weight: 1
        $x_1_5 = "&body=" wide //weight: 1
        $x_1_6 = "C:\\Program Files\\Internet Explorer\\iexplore.exe memberservices.passport.net/memberservice.srf" wide //weight: 1
        $x_1_7 = {6d 73 6e 31 00 42 61 7a 6f 6f 6b 61 20 76 33 2e 30 00 00 50 72 6f 6a 65 63 74 31}  //weight: 1, accuracy: High
        $x_1_8 = "LEAD Technologies Inc. V1.01" ascii //weight: 1
        $x_1_9 = "August 1 2000" wide //weight: 1
        $x_100_10 = "C:\\WINDOWS\\system32\\shdocvw.oca" ascii //weight: 100
        $x_100_11 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_GA_2147597965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.GA"
        threat_id = "2147597965"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "Virus\\lsass.vbp" wide //weight: 1
        $x_1_3 = "PCTeam Rulez" ascii //weight: 1
        $x_1_4 = "CurrentVersion\\Run /v (Default) /t REG_SZ /d C:\\WINDOWS\\System32\\drivers" wide //weight: 1
        $x_1_5 = "CurrentVersion\\Run /v WindowsLogon /t REG_SZ /d C:\\WINDOWS\\winlogon.exe /" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_FS_2147600336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FS"
        threat_id = "2147600336"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "B*\\AD:\\GOOGLE ADSENSE\\280507 DENGAN EMAIL\\JPEG.vbp" wide //weight: 6
        $x_1_2 = ":ClickX1:" wide //weight: 1
        $x_1_3 = ":Winfo1:" wide //weight: 1
        $x_1_4 = ":WTarget1:" wide //weight: 1
        $x_1_5 = ":StatDR:" wide //weight: 1
        $x_1_6 = ":DownloadX:" wide //weight: 1
        $x_1_7 = ":AddressX:" wide //weight: 1
        $x_1_8 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SysPrnt" wide //weight: 1
        $x_1_9 = "Fw: Response Urgent.." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_FS_2147600515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FS"
        threat_id = "2147600515"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\vemo code.vbp" wide //weight: 2
        $x_1_2 = "sebarFlashDisk" ascii //weight: 1
        $x_3_3 = "eksploitasi_folder_htt" ascii //weight: 3
        $x_2_4 = "document.writeln(runexe);" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_BS_2147601202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.BS"
        threat_id = "2147601202"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "126"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
        $x_1_2 = "wsshell.RegWrite \"HKCU\"&Smwc&\"Policies\\System\\DisableRegistryTools\", \"0\", rdw" ascii //weight: 1
        $x_1_3 = "wsshell.RegWrite \"HKCU\"&Smwc&\"Policies\\System\\DisableTaskMgr\", \"0\", rdw" ascii //weight: 1
        $x_1_4 = "Set Scut1 = wsshell.CreateShortcut(DesPath1 & \"\\Harry Potter.lnk\")" ascii //weight: 1
        $x_1_5 = "Set Scut2 = wsshell.CreateShortcut(DesPath2 & \"\\Bogor Kota Hujan.lnk\")" ascii //weight: 1
        $x_1_6 = "Scut1.TargetPath = wsshell.ExpandEnvironmentStrings(sispath&\"\\iexplore.vbs\")" ascii //weight: 1
        $x_1_7 = "Fileke2.Write tekvir" ascii //weight: 1
        $x_1_8 = "wsshell.regwrite Hsmwci&\"viremoval.exe\\Debugger" ascii //weight: 1
        $x_10_9 = "\\AzVirGen\\VB\\4n133\\Project1.vbp" wide //weight: 10
        $x_1_10 = "aniee.exe" wide //weight: 1
        $x_1_11 = "hanny.exe" wide //weight: 1
        $x_1_12 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\winsystem" wide //weight: 1
        $x_1_13 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Microfost" wide //weight: 1
        $x_1_14 = "winsys.exe" wide //weight: 1
        $x_1_15 = "[autorun]" wide //weight: 1
        $x_1_16 = "C:\\Tunggul.vbs" wide //weight: 1
        $x_1_17 = "\\ADMIN$" wide //weight: 1
        $x_1_18 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden" wide //weight: 1
        $x_1_19 = "ansav.exe" wide //weight: 1
        $x_1_20 = "ansavgd.exe" wide //weight: 1
        $x_1_21 = "PCMAV-CLN.exe" wide //weight: 1
        $x_1_22 = "ViRemoval.exe" wide //weight: 1
        $x_1_23 = "ShowKillProcess.exe" wide //weight: 1
        $x_1_24 = "Avguard.exe" wide //weight: 1
        $x_1_25 = "Avscan.exe" wide //weight: 1
        $x_1_26 = "ClamWinPortable.exe" wide //weight: 1
        $x_1_27 = "Winamp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 16 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_FV_2147605928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FV"
        threat_id = "2147605928"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Load Main Window" ascii //weight: 1
        $x_1_2 = "Exit CC Antivir" ascii //weight: 1
        $x_1_3 = {41 6e 74 69 56 69 72 75 73 00 48 65 72 6f 65 73 00 00 53 75 72 61 62 61 79 61}  //weight: 1, accuracy: High
        $x_1_4 = "Anti Antivirus" wide //weight: 1
        $x_1_5 = "Y479C6D0-OTRW-U5GH-S1EE-E0AC10B4E666" wide //weight: 1
        $x_1_6 = "NOTHING" wide //weight: 1
        $x_1_7 = "VBA6.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_FT_2147606004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FT"
        threat_id = "2147606004"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\New Sender\\Project1.vbp" wide //weight: 2
        $x_1_2 = "nsito com o Live Search Maps! <a href='http://www.livemaps.com.br/index.aspx?tr=true'>Experimente ja!</a>" wide //weight: 1
        $x_1_3 = "     From: daiane.fadas@hotmail.com" wide //weight: 1
        $x_1_4 = "\\LiveContacts.ini" wide //weight: 1
        $x_1_5 = "smtps.uol.com.br" wide //weight: 1
        $x_1_6 = "@uol.com.br" wide //weight: 1
        $x_1_7 = "http://www.geocities.com/superdown2008" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_YBT_2147606184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.YBT"
        threat_id = "2147606184"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2f 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 2f 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 2f 00 53 00 74 00 61 00 72 00 74 00 55 00 70 00 2f 00 00 00 14 00 00 00 2f 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 2f 00 00 00 00 00 16 00 00 00 53 00 56 00 43 00 48 00 30 00 53 00 54 00 2e 00 45 00 58 00 45 00}  //weight: 10, accuracy: High
        $x_2_2 = "\\Stuffs\\w32.AntiAnarchy.E@mm\\Havoc.Worm.vbp" wide //weight: 2
        $x_1_3 = "Britney,Madonna,Pink,girls,www.MilfHunter.com Porn Exposed+hot+sex+pictures.pif" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICESONCEEX\\000x\\" wide //weight: 1
        $x_1_5 = "\\system32\\svch0st.exe" wide //weight: 1
        $x_1_6 = "/system/wincirl.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_YBW_2147607739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.YBW"
        threat_id = "2147607739"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\M\\M\\Bush v10\\Project1.vbp" wide //weight: 2
        $x_1_2 = "it watches this animation of bush :P" wide //weight: 1
        $x_1_3 = "IMWindowClass" wide //weight: 1
        $x_1_4 = "\\Media\\Inicio de Windows XP.wav" wide //weight: 1
        $x_1_5 = "MSNCleaner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_AQ_2147609208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.AQ"
        threat_id = "2147609208"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "\\Didi Iswadi\\Project\\VB\\COBA WORM\\SYSTEMIL.vbp" wide //weight: 10
        $x_1_3 = "Documents.exe" wide //weight: 1
        $x_1_4 = "Pictures.exe" wide //weight: 1
        $x_1_5 = "Photos.exe" wide //weight: 1
        $x_1_6 = "Games.exe" wide //weight: 1
        $x_1_7 = "SYSTEMIL.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_AS_2147609913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.AS"
        threat_id = "2147609913"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "documentos\\H4CK3R\\Projeto RP_Win32\\Virus.vbp" wide //weight: 10
        $x_1_3 = "Arquivos de programas\\Messenger\\msmsgs.exe\\3" ascii //weight: 1
        $x_1_4 = "MessengerAPI" ascii //weight: 1
        $x_1_5 = "NetShareAdd" ascii //weight: 1
        $x_1_6 = "WNetEnumResourceA" ascii //weight: 1
        $x_1_7 = "NetServerEnum" ascii //weight: 1
        $x_1_8 = "netsh firewall set opmode disable" wide //weight: 1
        $x_1_9 = "system32\\Sys\\root\\" wide //weight: 1
        $x_1_10 = "Win24DLL.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_GC_2147611494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.GC"
        threat_id = "2147611494"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_2 = "G:\\Vrus 2009\\Project1.vbp" wide //weight: 10
        $x_10_3 = "karshenasi" wide //weight: 10
        $x_10_4 = "HideFileExt" wide //weight: 10
        $x_10_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" wide //weight: 10
        $x_1_6 = "ultrapeyman@" wide //weight: 1
        $x_1_7 = "smtpserver" wide //weight: 1
        $x_1_8 = "Peyman_ahwaz@yahoo.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_UJ_2147614207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.UJ"
        threat_id = "2147614207"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wintray.vbp" wide //weight: 1
        $x_1_2 = "Outlook.Application" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "WINDOWS.exe" wide //weight: 1
        $x_1_5 = "Ghost.bat" wide //weight: 1
        $x_1_6 = "cmd /c net share C$" wide //weight: 1
        $x_1_7 = "@163.com" wide //weight: 1
        $x_1_8 = "attachments" wide //weight: 1
        $x_1_9 = "getspecialfolder" wide //weight: 1
        $x_1_10 = "This Folder Has Been Damage!" wide //weight: 1
        $x_1_11 = "sd.run(Path + exename" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_UL_2147621039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.UL"
        threat_id = "2147621039"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\izun_data\\Latih\\vb\\Gagal\\Project1.vbp" wide //weight: 10
        $x_10_2 = ":\\Autorun.inf" wide //weight: 10
        $x_10_3 = "Shellexecute=%explorer.exe%" wide //weight: 10
        $x_10_4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCMD" wide //weight: 10
        $x_10_5 = "resource hacker" wide //weight: 10
        $x_1_6 = "svchost.exe" wide //weight: 1
        $x_1_7 = "open=%explorer.exe%" wide //weight: 1
        $x_1_8 = "HKLM\\Software\\Microsoft\\windows NT\\CurrentVersion\\winlogon\\userinit" wide //weight: 1
        $x_1_9 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\advanced\\hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_XFX_2147621431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.XFX"
        threat_id = "2147621431"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "D*\\AC:\\deny\\wayang.vbp" wide //weight: 100
        $x_1_2 = "Kujumpai pula sekelompok pemuda tunduk di rumah-Mu." wide //weight: 1
        $x_1_3 = "shutdown -r -f -t 0" wide //weight: 1
        $x_1_4 = "killbox.exe" wide //weight: 1
        $x_1_5 = "\\daLang MistiQ.exe" wide //weight: 1
        $x_1_6 = "\\Application Data\\SMA Negeri 4.exe" wide //weight: 1
        $x_1_7 = "wayangpaper" wide //weight: 1
        $x_1_8 = "Hanuman.exe" wide //weight: 1
        $x_1_9 = "\\w32 Wayang.exe" wide //weight: 1
        $x_1_10 = "Majnun was H3re.exe" wide //weight: 1
        $x_1_11 = "nakula sadewa\\svchost.exe" wide //weight: 1
        $x_1_12 = "*.doc" wide //weight: 1
        $x_1_13 = "killermachine.exe" wide //weight: 1
        $x_1_14 = "SCRNSAVE.EXE" wide //weight: 1
        $x_1_15 = "pcmav.exe" wide //weight: 1
        $x_1_16 = "\\Application Data\\Kota P4hlawan.exe" wide //weight: 1
        $x_1_17 = "My Documents\\majnun.txt" wide //weight: 1
        $x_1_18 = "x-raypc.exe" wide //weight: 1
        $x_1_19 = "C:\\deny" wide //weight: 1
        $x_1_20 = "durjana\\csrss.exe" wide //weight: 1
        $x_1_21 = "durjana\\smss.exe" wide //weight: 1
        $x_1_22 = "durjana\\lsass.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_UM_2147623121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.UM"
        threat_id = "2147623121"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VBMsoStdCompMgr" ascii //weight: 1
        $x_1_2 = "InfeksiFolder" ascii //weight: 1
        $x_1_3 = "\\Visual Basic Virus Code\\" wide //weight: 1
        $x_1_4 = "E:\\msvbvm60.dll" wide //weight: 1
        $x_1_5 = "C:\\Documents and Settings\\All Users\\Documents\\My Videos\\msvbvm60.dll" wide //weight: 1
        $x_1_6 = {4e 00 65 00 77 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 28 00 [0-2] 29 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = "My Pictures.exe" wide //weight: 1
        $x_1_8 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_VB_BT_2147624071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.BT"
        threat_id = "2147624071"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "autotxt" ascii //weight: 1
        $x_1_2 = "[AutoRun]" ascii //weight: 1
        $x_1_3 = "ieproloader.exe" wide //weight: 1
        $x_1_4 = "shell\\open\\Command=lovebzihui.exe" ascii //weight: 1
        $x_1_5 = {8b 55 d4 52 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 f7 d8 1b c0 40 f7 d8 66 89 85 70 ff ff ff c7 85 68 ff ff ff 0b 00 00 00 8d 45 ac 50 8d 8d 78 ff ff ff 51 8d 55 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_VX_2147627494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.VX"
        threat_id = "2147627494"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\\start page" wide //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\explorer\\NoFolderOptions" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden" wide //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\DisableThumbnailCache" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\DisableTaskMgr" wide //weight: 1
        $x_1_7 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_8 = "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System\\disableCMD" wide //weight: 1
        $x_1_9 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_10 = "MyDocuments.exe" wide //weight: 1
        $x_1_11 = "Recycle Bin.exe" wide //weight: 1
        $x_1_12 = "Fonts.exe" wide //weight: 1
        $x_1_13 = "pikirrr.exe" wide //weight: 1
        $x_1_14 = "window.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Worm_Win32_VB_CM_2147628936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.CM"
        threat_id = "2147628936"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Abrir Pantalla de Mensaje" ascii //weight: 1
        $x_1_2 = "txtdisableUAC" ascii //weight: 1
        $x_1_3 = "blanco si icono -Spradea USB" wide //weight: 1
        $x_1_4 = "damemails" wide //weight: 1
        $x_1_5 = "-/mails-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_VB_FX_2147629320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FX"
        threat_id = "2147629320"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" wide //weight: 1
        $x_1_3 = "[autorun]" wide //weight: 1
        $x_1_4 = "DRAGONOUV" wide //weight: 1
        $x_1_5 = "shell\\open\\Command=Spenser.exe" wide //weight: 1
        $x_1_6 = "action = Open In Explorer With NK" wide //weight: 1
        $x_1_7 = ":\\Copy of mon\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_A_2147629625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.gen!A"
        threat_id = "2147629625"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "scripting.filesystemobject" wide //weight: 1
        $x_1_4 = "\\AUTORUN.INF" wide //weight: 1
        $x_1_5 = "[AutoRun]" wide //weight: 1
        $x_1_6 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6f 00 70 00 65 00 6e 00 3d 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_FY_2147630049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.FY"
        threat_id = "2147630049"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Studio\\VB98\\" ascii //weight: 1
        $x_1_2 = "[AutoRun]" wide //weight: 1
        $x_1_3 = "shell\\open=Ouvrir" wide //weight: 1
        $x_1_4 = "Wscript.Shell" wide //weight: 1
        $x_1_5 = "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\userinit" wide //weight: 1
        $x_1_6 = "shell\\open\\Command=.X" wide //weight: 1
        $x_1_7 = "tskill explorer" wide //weight: 1
        $x_1_8 = "YouneX HackeR" wide //weight: 1
        $x_1_9 = "IdonTPlay.vbp" wide //weight: 1
        $x_1_10 = "G:\\autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_VB_DZ_2147630764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.DZ"
        threat_id = "2147630764"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74}  //weight: 10, accuracy: High
        $x_1_3 = {43 00 3a 00 5c 00 [0-8] 5c 00 53 00 45 00 52 00 56 00 45 00 52 00 [0-2] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "msn.pass" wide //weight: 1
        $x_1_5 = "ff.pass" wide //weight: 1
        $x_1_6 = "Screenshot_DesktopWindow" wide //weight: 1
        $x_1_7 = "ini.seliforp\\xoferiF\\allizoM\\" wide //weight: 1
        $x_1_8 = "PK11_Authenticate" wide //weight: 1
        $x_1_9 = "Del Uninstall.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_VB_JK_2147648878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.JK"
        threat_id = "2147648878"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 [0-32] 6d 00 6f 00 72 00 74 00 65 00 7a 00 61 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "shell\\explore\\Command=iran.exe EXPLORE" ascii //weight: 1
        $x_1_3 = "Start Menu\\Programs\\Startup\\winlogon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_JL_2147649481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.JL"
        threat_id = "2147649481"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attrib +h +s +r f:\\Autorun.inf" ascii //weight: 1
        $x_1_2 = {3a 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 [0-10] 63 00 3a 00 5c 00 62 00 6f 00 6f 00 74 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2f 00 6d 00 6d 00 2f 00 30 00 33 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_JN_2147652811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.JN"
        threat_id = "2147652811"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YahooBuddyMain" wide //weight: 1
        $x_1_2 = "shell\\open\\command" wide //weight: 1
        $x_1_3 = "shell\\print\\command" wide //weight: 1
        $x_1_4 = "fuckme~~" wide //weight: 1
        $x_1_5 = "{HOME}" wide //weight: 1
        $x_1_6 = "/adult" wide //weight: 1
        $x_1_7 = "\\autorun.inf" wide //weight: 1
        $x_1_8 = "drivekill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_VB_P2P_2147653396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB@P2P.A"
        threat_id = "2147653396"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 4d 00 ?? ?? ?? ?? 45 00 61 00 72 00 6e 00 69 00 6e 00 67 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "WebMoney Earnings" wide //weight: 1
        $x_1_3 = "Webmail crack" wide //weight: 1
        $x_1_4 = "wmk:payto?Purse=" wide //weight: 1
        $x_1_5 = "\\limewire\\" wide //weight: 1
        $x_1_6 = "\\BearShare\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_XA_2147655131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.XA"
        threat_id = "2147655131"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wintray.vbp" wide //weight: 1
        $x_1_2 = "c:\\net.txt" wide //weight: 1
        $x_1_3 = "Ghost.bat" wide //weight: 1
        $x_1_4 = "A:\\Explorer.EXE" wide //weight: 1
        $x_1_5 = "A:\\WINDOWS.EXE" wide //weight: 1
        $x_1_6 = "A:\\NetHood.htm" wide //weight: 1
        $x_1_7 = "KaV300XP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_VB_AA_2147745431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VB.AA!MTB"
        threat_id = "2147745431"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SHELL32.DLL" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = {8b 45 08 ff 30 e8 ?? ?? ?? ?? 8b 4d 80 03 8d ?? ?? ff ff 8a 18 32 19 ff b5 ?? ?? ff ff 8b 45 08 ff 30 e8 ?? ?? ?? ?? 88 18 eb 02 eb ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

