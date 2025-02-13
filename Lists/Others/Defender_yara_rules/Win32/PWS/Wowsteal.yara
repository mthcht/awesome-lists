rule PWS_Win32_Wowsteal_A_2147572245_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.gen!A"
        threat_id = "2147572245"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "c:\\w3o4w.txt" ascii //weight: 2
        $x_2_2 = "Yulgang_File_Update" ascii //weight: 2
        $x_2_3 = "GameMuma" ascii //weight: 2
        $x_3_4 = "c:\\FindErrLongForGame.txt" ascii //weight: 3
        $x_2_5 = "^nGaMYW4wXBHjAK" wide //weight: 2
        $x_2_6 = "i$AtG^x_JrC" wide //weight: 2
        $x_2_7 = "ifyoudothatagainiwillkickyourass" ascii //weight: 2
        $x_1_8 = "Private_Wow_Data" ascii //weight: 1
        $x_2_9 = "FuckShanda" ascii //weight: 2
        $x_3_10 = "risnifdsaf9hfdsaof3fmdosighgfdsg" ascii //weight: 3
        $x_3_11 = "Microsoft Soft Debuger" ascii //weight: 3
        $x_2_12 = "\\data\\woool.dat" ascii //weight: 2
        $x_1_13 = "woool88.dat" ascii //weight: 1
        $x_2_14 = "-08002B30309D}\\shell\\OpenHomePage\\" ascii //weight: 2
        $x_2_15 = "EXP10RER.com" ascii //weight: 2
        $x_4_16 = {a0 e7 ef f4 ef a0 f4 f2 f9}  //weight: 4, accuracy: High
        $x_4_17 = {d2 e1 f6 cd ef ee ae e5 f8 e5}  //weight: 4, accuracy: High
        $x_2_18 = {d9 e1 e8 ef ef}  //weight: 2, accuracy: High
        $x_2_19 = {cc e9 ee e5 e1 e7 e5}  //weight: 2, accuracy: High
        $x_3_20 = "E-China_WowExec-" ascii //weight: 3
        $x_2_21 = ".wow.QOMX\\" wide //weight: 2
        $x_3_22 = "qinglanzx911@16" ascii //weight: 3
        $x_1_23 = "\\svchqs.exe" ascii //weight: 1
        $x_3_24 = "ibm-xp/hz/wow2.asp" ascii //weight: 3
        $x_1_25 = "\\svchpst.exe" ascii //weight: 1
        $x_3_26 = "&subject=wowpass" ascii //weight: 3
        $x_1_27 = "woool" ascii //weight: 1
        $x_2_28 = "MoonHook" ascii //weight: 2
        $x_1_29 = "&pass=" ascii //weight: 1
        $x_2_30 = "&beizhu=" ascii //weight: 2
        $x_1_31 = "&pcname=" ascii //weight: 1
        $x_2_32 = "CheckBoxHackFirewall" ascii //weight: 2
        $x_2_33 = "CheckBoxHackHYJLT" ascii //weight: 2
        $x_1_34 = "Send OK!" ascii //weight: 1
        $x_2_35 = "num=1234567&pass=password" ascii //weight: 2
        $x_1_36 = "666667776666666666effee" ascii //weight: 1
        $x_1_37 = "if exist \"" ascii //weight: 1
        $x_1_38 = "goto try" ascii //weight: 1
        $x_1_39 = "C:\\WINDOWS\\Debug\\1D54BD5BC206.dll" ascii //weight: 1
        $x_1_40 = "1D54BD5BC206.exe" ascii //weight: 1
        $x_1_41 = {32 2e 62 61 74 00 00 00 ff ff ff ff 0f 00 00 00 6e 6e 6e 6b 6c 6c 6c 64 66 73 66 64 64 64 64}  //weight: 1, accuracy: High
        $x_1_42 = ".logon.worldofwarcraft.com" ascii //weight: 1
        $x_1_43 = "World of Warcraft" ascii //weight: 1
        $x_1_44 = "GxWindowClassD3d" ascii //weight: 1
        $x_1_45 = "realmlist.wtf" ascii //weight: 1
        $x_1_46 = "wow.exe" ascii //weight: 1
        $x_3_47 = "%s?MailBody=%s" ascii //weight: 3
        $x_1_48 = "GetKeyboardType" ascii //weight: 1
        $x_1_49 = "pass:%s" ascii //weight: 1
        $x_1_50 = "EHLO %s" ascii //weight: 1
        $x_1_51 = "application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_52 = "GameID=" ascii //weight: 1
        $x_1_53 = "&PassWord=" ascii //weight: 1
        $x_3_54 = "&Wowserver=" ascii //weight: 3
        $x_1_55 = "&SystemName=" ascii //weight: 1
        $x_3_56 = ".com.cn/upd/wow" ascii //weight: 3
        $x_3_57 = ".com.cn/upd/xyqupdate.asp?" ascii //weight: 3
        $x_2_58 = ".etsoft.com.cn/" ascii //weight: 2
        $x_3_59 = "cn1.grunt.wowchina.com" ascii //weight: 3
        $x_3_60 = "cn2.grunt.wowchina.com" ascii //weight: 3
        $x_4_61 = "GetHookStatus.asp?GUID=" wide //weight: 4
        $x_2_62 = "&WinName=" ascii //weight: 2
        $x_2_63 = "User:%s|Pass:%s" ascii //weight: 2
        $x_2_64 = "Message-Id: <" ascii //weight: 2
        $x_2_65 = {65 68 6c 6f 20 76 69 70 0d 0a}  //weight: 2, accuracy: High
        $x_1_66 = "<vip@microsoft." ascii //weight: 1
        $x_1_67 = "; filename=\"c:\\" ascii //weight: 1
        $x_3_68 = "X-Mailer: <FOXMAIL " ascii //weight: 3
        $x_3_69 = {44 41 54 41 0d 0a 00 00 ff ff ff ff ?? 00 00 00 46 72 6f 6d 3a 20 3c}  //weight: 3, accuracy: Low
        $x_2_70 = "HookProc" ascii //weight: 2
        $x_2_71 = "InstallHook" ascii //weight: 2
        $x_2_72 = "StartHook" ascii //weight: 2
        $x_1_73 = "StopHook" ascii //weight: 1
        $x_1_74 = "UnHook" ascii //weight: 1
        $x_1_75 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_76 = "JumpHookOn" ascii //weight: 1
        $x_1_77 = "JumpHookOff" ascii //weight: 1
        $x_2_78 = {4a 75 24 6d 70 48 6f 6f 23 6b 4f 66 40 66 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|41|2d|5a) (30|2d|39|41|2d|5a) 00}  //weight: 2, accuracy: Low
        $x_3_79 = "WSXIHUDS" ascii //weight: 3
        $x_3_80 = {1c ff ff 8b d8 c6 44 24 04 00 68 00 01 00 00 8d 44 24 08 50 53 e8 ?? ?? ff ff c6 84 24 04 01 00 00 00 68 00 01 00 00 8d 84 24 08 01 00 00 50 53}  //weight: 3, accuracy: Low
        $x_3_81 = {c6 06 b8 c6 46 05 ff c6 46 06 e0 c6 46 07 00 c6 07 b8 c6 47 05 ff c6 47 06 e0 c6 47 07 00}  //weight: 3, accuracy: High
        $x_3_82 = {41 00 33 d2 89 10 6a 00 8b 45 08 50 e8 ?? fc fe ff 8b f8 57 a1 ?? ?? 41 00 50 b8 ?? ?? 41 00 50 6a 03 e8 ?? fc fe ff 8b f0 a1 ?? ?? 41 00 89 30 85 f6 76 02 b3 01 8b c3}  //weight: 3, accuracy: Low
        $x_2_83 = {ff ff 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 02 b3 01 8b c3 90 55}  //weight: 2, accuracy: High
        $x_5_84 = {8b 7c 24 1c 56 68 48 01 00 00 6a 01 57 e8 ?? ?? 00 00 56 e8 ?? ?? 00 00 83 c4 20 33 c0 eb 06 8d 9b 00 00 00 00 fe 0c 38 40 3d 48 01 00 00 72 f5 5f b0 01 5e c3 53 8b 5c 24 0c 56 8b c3 57}  //weight: 5, accuracy: Low
        $x_3_85 = {50 8d 3c cd 00 00 00 00 8b 4e 0c 8a 54 39 04 8b 4e 2c 6a 04 6a 01 53 51 88 54 24 2c ff d5 8b 46 2c 6a 00 6a 01 8d 54 24 20 52 53 50 ff 15 54 c1}  //weight: 3, accuracy: High
        $x_4_86 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 ?? 8d 45 f4 8b d3 e8 ?? ?? ff ff 8b 55 f4 8b c7 e8 ?? ?? ff ff ff 45 f8 4e 75 d9}  //weight: 4, accuracy: Low
        $x_2_87 = {8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8}  //weight: 2, accuracy: High
        $x_2_88 = {74 11 6a 00 6a 00 68 f5 00 00 00 53 e8}  //weight: 2, accuracy: High
        $x_2_89 = {33 d2 89 50 05 8b 03 8b 40 09 85 c0 74 06 50 e8 ?? ?? ff ff 8b 03 33 d2 89 50 09 8b 03 8b 40 01 85 c0 74 06 50 e8 8e 96 ff ff 8b 03 33 d2 89 50}  //weight: 2, accuracy: Low
        $x_1_90 = {6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68}  //weight: 1, accuracy: High
        $x_1_91 = {c7 44 24 10 33 7d 79 00}  //weight: 1, accuracy: High
        $x_1_92 = {50 68 00 01 00 00 6a 0d 53}  //weight: 1, accuracy: High
        $x_2_93 = {8b 54 24 18 8b f0 8b c2 83 c4 0c 8d 78 01 eb 03 8d 49 00 8a 08 40 84 c9 75 f9 56 2b c7 6a 01 50}  //weight: 2, accuracy: High
        $n_5_94 = "B1AG_WINDOW" ascii //weight: -5
        $n_2_95 = "ACDSee4.exe" ascii //weight: -2
        $n_4_96 = "\\Soft\\Download" ascii //weight: -4
        $n_100_97 = {e3 ba dc b1 ae f4 f8 f4 00}  //weight: -100, accuracy: High
        $n_100_98 = {8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3}  //weight: -100, accuracy: High
        $n_5_99 = "wowshell.com" ascii //weight: -5
        $n_5_100 = "WowShell.ini" ascii //weight: -5
        $n_3_101 = "wowhead.com" ascii //weight: -3
        $n_3_102 = "thottbot.com" ascii //weight: -3
        $n_3_103 = "wowhead client" ascii //weight: -3
        $n_4_104 = "gamania.com" ascii //weight: -4
        $n_30_105 = "www.wowinside.net" ascii //weight: -30
        $n_30_106 = "ui.the9.com" ascii //weight: -30
        $n_30_107 = "TitleBarDrawAppIcon" ascii //weight: -30
        $n_30_108 = "mainBrowserTitleChange" ascii //weight: -30
        $n_30_109 = "Effect.Shadow." ascii //weight: -30
        $n_20_110 = ".wowchina.com" ascii //weight: -20
        $n_20_111 = "www.the9.com" ascii //weight: -20
        $n_20_112 = "ccm.gov.cn" ascii //weight: -20
        $n_150_113 = "Only registered version of Iparmor can clean" ascii //weight: -150
        $n_150_114 = "ScrapeBox is accessing" ascii //weight: -150
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_S_2147584525_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.S"
        threat_id = "2147584525"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 6f 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_5 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_6 = "Accept-Language: zh-cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_T_2147584526_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.T"
        threat_id = "2147584526"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "World of Warcraft" ascii //weight: 1
        $x_1_2 = "GxWindowClassD3d" ascii //weight: 1
        $x_1_3 = "&pass=" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_5 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_U_2147584527_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.U"
        threat_id = "2147584527"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Software\\Borland\\Delphi" ascii //weight: 5
        $x_5_2 = "SeDebugPrivilege" ascii //weight: 5
        $x_5_3 = ".asp?" ascii //weight: 5
        $x_5_4 = "&pas" ascii //weight: 5
        $x_5_5 = "SetWindowsHookExA" ascii //weight: 5
        $x_1_6 = "WoW.exe" ascii //weight: 1
        $x_1_7 = "World of Warcraft" ascii //weight: 1
        $x_1_8 = "realmlist.wtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_V_2147584628_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.V"
        threat_id = "2147584628"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_2 = "if exist" ascii //weight: 1
        $x_1_3 = "World of Warcraft" ascii //weight: 1
        $x_1_4 = "WOW.EXE" ascii //weight: 1
        $x_1_5 = "GxWindowClassD3d" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_W_2147593186_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.W"
        threat_id = "2147593186"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib -a -r -s -h" wide //weight: 1
        $x_1_2 = "goto selfkill" wide //weight: 1
        $x_1_3 = "del winroot.bat" wide //weight: 1
        $x_1_4 = "winwork" wide //weight: 1
        $x_1_5 = "QQ.exe" wide //weight: 1
        $x_1_6 = "PFW.exe" wide //weight: 1
        $x_1_7 = "bdscheca001.dll" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Internet Explorer\\Explorer Bars\\{C4EE31F3-4768-11D2-BE5C-00A0C9A83DA1}" wide //weight: 1
        $x_1_9 = "SOFTWARE\\Classes\\CLSID\\{9C0CFA58-3A6F-51ba-9EFE-5320F4F621BA}" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" wide //weight: 1
        $x_1_11 = "svchqs.exe" wide //weight: 1
        $x_1_12 = "jiahus" wide //weight: 1
        $x_1_13 = "World of Warcraft" wide //weight: 1
        $x_1_14 = "\\realmlist.wtf" wide //weight: 1
        $x_1_15 = "GxWindowClassD3d" wide //weight: 1
        $x_1_16 = "WOW.EXE" wide //weight: 1
        $x_1_17 = "&totamm=" wide //weight: 1
        $x_1_18 = "&totalr=" wide //weight: 1
        $x_1_19 = "&totalaccess=" wide //weight: 1
        $x_1_20 = "C:\\tmpsss.log" wide //weight: 1
        $x_1_21 = "Accept-Language: zh-cn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_XQ_2147596916_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.XQ"
        threat_id = "2147596916"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LaTaleClient.EXE" ascii //weight: 1
        $x_1_2 = "gameclient.exe" ascii //weight: 1
        $x_1_3 = "cabalmain.exe" ascii //weight: 1
        $x_1_4 = "WOW.EXE" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_ZA_2147596930_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.ZA"
        threat_id = "2147596930"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "CRACKING" ascii //weight: 1
        $x_1_3 = "wow.exe" ascii //weight: 1
        $x_1_4 = "WQW.exe" ascii //weight: 1
        $x_1_5 = "WvW.exe" ascii //weight: 1
        $x_1_6 = "action=getuser" ascii //weight: 1
        $x_1_7 = "GameHMOver" ascii //weight: 1
        $x_1_8 = "ThreadFalse" ascii //weight: 1
        $x_1_9 = "RavRuneip" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_11 = "JumpHookOn" ascii //weight: 1
        $x_1_12 = "action=getyxlogin&u=" ascii //weight: 1
        $x_1_13 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_ZB_2147596931_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.ZB"
        threat_id = "2147596931"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CRACKING" ascii //weight: 1
        $x_1_2 = "wow.exe" ascii //weight: 1
        $x_1_3 = "DEVICEDATA" ascii //weight: 1
        $x_1_4 = "SYSTEM\\MountedDevices" ascii //weight: 1
        $x_1_5 = "action=getpos&u=%s" ascii //weight: 1
        $x_1_6 = "action=postmb&u=%s&mb=%s" ascii //weight: 1
        $x_1_7 = "WTF\\config.wtf" ascii //weight: 1
        $x_1_8 = "realmName" ascii //weight: 1
        $x_1_9 = "CallNextHookEx" ascii //weight: 1
        $x_10_10 = {8d 4d cc 8d 55 e8 b0 6c b3 64 51 52 c6 45 e8 75 c6 45 e9 72 88 45 ea c6 45 eb 6d c6 45 ee 2e 88 5d ef 88 45 f0 88 45 f1 c6 45 f2 00 c6 45 cc 55 c6 45 cd 52 c6 45 ce 4c c6 45 cf 44 c6 45 d1 77 88 45 d3 88 5d d6 c6 45 d7 54 c6 45 d9 43 c6 45 db 63 c6 45 dc 68 c6 45 de 46 c6 45 df 69 88 45 e0 c6 45 e2 41 c6 45 e3 00 ff 15 70 60 00 25 50 ff 15 74 60 00 25}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_ZE_2147597228_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.ZE"
        threat_id = "2147597228"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VirtualAllocEx" ascii //weight: 10
        $x_10_2 = "WriteProcessMemory" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = "This prokkki must be run under Win32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_ZF_2147602195_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.ZF"
        threat_id = "2147602195"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\NewProject.vbp" wide //weight: 10
        $x_10_2 = "MoonHook" ascii //weight: 10
        $x_10_3 = "webUpdate" ascii //weight: 10
        $x_10_4 = "FuckShanda" ascii //weight: 10
        $x_10_5 = "ifyoudothatagainiwillkickyourass" ascii //weight: 10
        $x_1_6 = "timMonHook" ascii //weight: 1
        $x_1_7 = "timMonWindow" ascii //weight: 1
        $x_1_8 = "SE_DEBUG_NAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_ZG_2147606906_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.ZG"
        threat_id = "2147606906"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 f8 00 74 28 81 78 0c 46 30 30 46 75 1f 60 80 78 15 7c 75 0d 0f b7 58 13}  //weight: 3, accuracy: High
        $x_3_2 = {6a 00 68 66 66 66 66 68 ?? ?? 40 00 6a 00 6a 00 e8 ?? ?? ff ff [0-5] b8 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0}  //weight: 3, accuracy: Low
        $x_1_3 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 [0-32] 57 6f 57 2e 65 78 65 [0-32] 47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64}  //weight: 1, accuracy: Low
        $x_1_4 = {26 70 61 73 73 3d [0-32] 26 73 65 72 3d [0-32] 26 63 61 6e 67 6b 75 3d [0-32] 26 62 65 69 7a 68 75 3d [0-80] 26 70 63 6e 61 6d 65 [0-32] 53 65 6e 64 20 4f 4b}  //weight: 1, accuracy: Low
        $x_1_5 = {4d 79 41 70 70 [0-32] 41 63 63 65 70 74 3a [0-32] 50 4f 53 54 [0-32] 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64}  //weight: 1, accuracy: Low
        $x_1_6 = "TCnMethodHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_J_2147609311_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.J"
        threat_id = "2147609311"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "351"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Automatic Updates" wide //weight: 100
        $x_100_2 = "http://204.13.69.12/fg" wide //weight: 100
        $x_100_3 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide //weight: 100
        $x_10_4 = "ServiceMain" ascii //weight: 10
        $x_10_5 = "InjectService" ascii //weight: 10
        $x_10_6 = "URLDownloadToFileW" ascii //weight: 10
        $x_10_7 = "WriteProcessMemory" ascii //weight: 10
        $x_10_8 = "CreateRemoteThread" ascii //weight: 10
        $x_1_9 = "pol.exe" wide //weight: 1
        $x_1_10 = "polcore.dll" wide //weight: 1
        $x_1_11 = "FFXIService.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_B_2147609620_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.gen!B"
        threat_id = "2147609620"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 e4 3c 41 72 3c 3c 5a 76 3a 3c 61 72 34 3c 7a 76 32 3c 80 72 2c 3c 83 72 2a 74 26 3c 85 72 24 74 20 3c 87 76 1e 3c 8e 72 18 3c 90 76 16 3c 94 74 12 3c 99 74 0e 3c 9a 74 0a 3c a4 74 06 3c a5 74 02 f6 d4 c3}  //weight: 5, accuracy: High
        $x_5_2 = {3c 41 72 37 3c 5a 76 31 3c 8e 74 1b 3c 99 74 1a 3c 9a 74 19 3c 90 74 18 3c a5 74 17 3c 8f 74 16 3c 80 75 17 b0 87 c3 b0 84 c3 b0 94 c3 b0 81 c3 b0 82 c3 b0 a4 c3 b0 86 c3 34 20 c3}  //weight: 5, accuracy: High
        $x_5_3 = {56 49 75 fc 8d 9d 74 ff ff ff 89 33 53 df 05 ?? ?? ?? ?? df 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b b5 74 ff ff ff e8 ?? ?? ?? ?? 85 c0 0f 84 e0 00 00 00 6a 00 6a 00 8d 9d 6c ff ff ff 53 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b dc 83 c3 08 e8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b dc 83 c3 08}  //weight: 5, accuracy: Low
        $x_1_4 = "@Vision@" ascii //weight: 1
        $x_1_5 = "WoW.exe" ascii //weight: 1
        $x_1_6 = "GamePass" ascii //weight: 1
        $x_1_7 = "LovEf3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AA_2147609942_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AA"
        threat_id = "2147609942"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "223"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_1_3 = "\\AppEvents\\Schemes\\Apps\\Explorer\\Navigating\\.current" ascii //weight: 1
        $x_1_4 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_5 = "UtilMind HTTPGet" ascii //weight: 1
        $x_1_6 = "\\Local Settings\\Temp\\update.exe" ascii //weight: 1
        $x_1_7 = "BlackSunDomains" ascii //weight: 1
        $x_1_8 = "BlackSunNextServer" ascii //weight: 1
        $x_1_9 = "BlackSunNextServerTimer" ascii //weight: 1
        $x_1_10 = "BlackSunGatewayDoneString" ascii //weight: 1
        $x_1_11 = "/void.php" ascii //weight: 1
        $x_1_12 = "(CRACK) " ascii //weight: 1
        $x_1_13 = "(KEY GEN) " ascii //weight: 1
        $x_1_14 = "(PATCH) " ascii //weight: 1
        $x_1_15 = "(FULL) " ascii //weight: 1
        $x_1_16 = "<Share>" ascii //weight: 1
        $x_1_17 = "[!!^**]" ascii //weight: 1
        $x_1_18 = "Common Files" ascii //weight: 1
        $x_1_19 = "Application Data" ascii //weight: 1
        $x_1_20 = "Favorites" ascii //weight: 1
        $x_1_21 = "My Documents" ascii //weight: 1
        $x_1_22 = "Local Settings" ascii //weight: 1
        $x_1_23 = "Default User" ascii //weight: 1
        $x_1_24 = "All Users" ascii //weight: 1
        $x_1_25 = "DCPlusPlus.xml" ascii //weight: 1
        $x_1_26 = "traynotify" wide //weight: 1
        $x_1_27 = "http://www.google.com/" wide //weight: 1
        $x_1_28 = "HOMEPATH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 23 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_C_2147610035_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.gen!C"
        threat_id = "2147610035"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "InternetReadFile" ascii //weight: 10
        $x_10_2 = "InternetOpenUrlA" ascii //weight: 10
        $x_1_3 = {b8 65 78 65 00 8b 35 ?? ?? ?? ?? 89 45 f8 89 45 c8 8d 45 f0 33 db 50 c7 45 f0 33 36 30 54 ff 75 08 c7 45 f4 72 61 79 2e 89 5d fc c7 45 c0 33 36 30 53 c7 45 c4 61 66 65 2e 89 5d cc ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 d0 76 65 72 63 50 c7 45 d4 6c 73 69 64 ff 75 08 89 5d dc c7 45 e0 45 78 70 6c c7 45 e4 6f 72 65 72 89 5d ec ff d6}  //weight: 1, accuracy: High
        $x_1_5 = {c7 85 3c ff ff ff 6e 5c 53 68 c7 85 40 ff ff ff 65 6c 6c 53 c7 85 44 ff ff ff 65 72 76 69 c7 85 48 ff ff ff 63 65 4f 62 c7 85 4c ff ff ff 6a 65 63 74 c7 85 50 ff ff ff 44 65 6c 61 c7 85 54 ff ff ff 79 4c 6f 61 c7 85 58 ff ff ff 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 dc 65 72 4e 61 50 c7 45 e0 6d 65 00 00 89 5d e4 c7 45 e8 4c 61 73 74 c7 45 ec 4e 61 6d 65 89 5d f0 c7 45 b0 2e 5c 65 63 c7 45 b4 74 5c 68 6f c7 45 b8 6d 65 2e 69 c7 45 bc 6e 69 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 c8 3f 62 3d 25 c7 45 cc 73 26 63 3d c7 45 d0 25 73 26 65 c7 45 d8 66 3d 25 73 c7 45 dc 26 69 3d 25 c7 45 e0 73 26 6b 3d c7 45 e4 25 73 26 6d c7 45 ec 6e 3d 25 73 89 75 f0}  //weight: 1, accuracy: High
        $x_1_8 = {33 db c7 45 e4 54 41 32 45 c7 45 e8 64 69 74 00 89 5d ec c7 45 d4 54 46 72 6d c7 45 d8 4c 6f 67 4f c7 45 dc 6e 00 00 00 89 5d e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_Z_2147611486_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.Z"
        threat_id = "2147611486"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 68 de fd ff ff 53 e8 ?? ?? ?? ?? 8d 45 80 e8 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 22 02 00 00 a1 ?? ?? ?? ?? 50 53 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 18 80 c3 23 80 f3 17 80 eb 23 88 1a 42 40 49 75 ee}  //weight: 1, accuracy: High
        $x_1_3 = {8a 0c 10 80 c1 88 80 f1 77 80 e9 88 8b 1d 08 a1 40 00 88 0c 13 42 81 fa 22 02 00 00 75 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AB_2147612385_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AB"
        threat_id = "2147612385"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".worldofwarcraft." ascii //weight: 10
        $x_10_2 = "NtUnmapViewOfSection" ascii //weight: 10
        $x_10_3 = {47 45 54 00 6f 6e 6c 69 6e 65 67 61 6d 65}  //weight: 10, accuracy: High
        $x_10_4 = "SeDebugPrivilege" ascii //weight: 10
        $x_10_5 = "www.shehaea.com" ascii //weight: 10
        $x_1_6 = {77 6f 77 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_7 = "WritePrivateProfileStringA" ascii //weight: 1
        $x_1_8 = "secretQuestionAnswer" ascii //weight: 1
        $x_1_9 = "wowinfo" wide //weight: 1
        $x_1_10 = "grunt.wowchina.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_ZI_2147614419_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.ZI"
        threat_id = "2147614419"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 69 76 78 44 65 63 6f 64 65 [0-2] 48 6f 6f 6b 6f 66 66 [0-2] 48 6f 6f 6b 6f 6e}  //weight: 2, accuracy: Low
        $x_1_2 = "\\wow.exe" ascii //weight: 1
        $x_1_3 = "wow080911" ascii //weight: 1
        $x_2_4 = "C:\\WindoDivxDecoder.dll" ascii //weight: 2
        $x_2_5 = "123expolorer.exe" ascii //weight: 2
        $x_8_6 = {69 6d 6d 71 37 32 32 ?? ?? ?? 33 70 78 5e 69 68 6e 68 33 5e 73 32 7a 30}  //weight: 8, accuracy: Low
        $x_7_7 = {46 43 4f 75 e1 12 00 8a 03 04 ?? 34 ?? 2c ?? 88 06 8d 45 f4 e8 ?? ?? ff ff}  //weight: 7, accuracy: Low
        $x_6_8 = {ff 53 56 e8 ?? ?? ff ff 53 e8 ?? ?? ff ff c6 44 06 ?? 44 53 e8 ?? ?? ff ff c6 44 06 ?? 69 53 e8 ?? ?? ff ff c6 44 06 ?? 76 53 e8 ?? ?? ff ff c6 44 06 ?? 78 53 e8 ?? ?? ff ff c6 44 06 ?? 44 53 e8 ?? ?? ff ff c6 44 06 ?? 65 53 e8 ?? ?? ff ff c6 44 06 ?? 63 53 e8 ?? ?? ff ff c6 44 06 ?? 6f 53 e8 ?? ?? ff ff c6 44 06 ?? 64 53 e8 ?? ?? ff ff c6 44 06 ?? 65 53 e8 ?? ?? ff ff c6 44 06 ?? 72 53 e8 ?? ?? ff ff c6 44 06 ?? 2e 53 e8 ?? ?? ff ff c6 44 06 ?? 64 53 e8 ?? ?? ff ff c6 44 06 ?? 6c 53 e8 ?? ?? ff ff c6 44 06 ?? 6c}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AE_2147615997_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AE"
        threat_id = "2147615997"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "yilu777" ascii //weight: 4
        $x_3_2 = "/sxxx/zh/get.asp" ascii //weight: 3
        $x_2_3 = "%s?us=%s&ps=" ascii //weight: 2
        $x_2_4 = {25 73 5c 25 73 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_5 = "wtf\\config.wtf" ascii //weight: 1
        $x_1_6 = "wowsystemcode" ascii //weight: 1
        $x_1_7 = "logon.worldofwarcraft.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AK_2147618725_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AK"
        threat_id = "2147618725"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 10 50 6a 00 c7 45 e0 01 00 00 00 ff 75 fc c7 45 ec 02 00 00 00 ff 15 ?? ?? 00 10 85 c0}  //weight: 10, accuracy: Low
        $x_10_2 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 10
        $x_10_3 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}  //weight: 10, accuracy: High
        $x_1_4 = "%s\\WTF\\config.wtf" ascii //weight: 1
        $x_1_5 = {6c 6f 67 69 6e [0-6] 46 46 58 69}  //weight: 1, accuracy: Low
        $x_1_6 = "secretQuestionAnswer" ascii //weight: 1
        $x_1_7 = "[accountName:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AL_2147621654_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AL"
        threat_id = "2147621654"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "action=domod&zt=" ascii //weight: 1
        $x_1_2 = "data\\enUS\\realmlist.wtf" ascii //weight: 1
        $x_1_3 = "action=ok&u=" ascii //weight: 1
        $x_1_4 = "/wowReadMb.asp" ascii //weight: 1
        $x_1_5 = "/loginip.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_D_2147622473_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.gen!D"
        threat_id = "2147622473"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 30 08 01 10 8d 85 ?? ?? ff ff 6a 64 50 56 68 ?? 06 01 10 53 ff d7}  //weight: 10, accuracy: Low
        $x_2_2 = "softyinforwow" ascii //weight: 2
        $x_1_3 = "%s?us=%s&ps=%s&lv=%s&se=%s&qu=%s&os=%s" ascii //weight: 1
        $x_1_4 = "RegSetValueEx(start)" ascii //weight: 1
        $x_1_5 = ".worldofwarcraft.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AM_2147622701_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AM"
        threat_id = "2147622701"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&u=%s&p=%s&pin=%s&r=%s" ascii //weight: 1
        $x_1_2 = "%s?user=%s&pass=%s&jumin1=%s&jumin2=%s&name=%s" ascii //weight: 1
        $x_2_3 = {8a 18 32 da 88 18 40 49 75 f6 5b}  //weight: 2, accuracy: High
        $x_2_4 = {81 fe 96 00 00 00 7e 35 81 fe e8 03 00 00 7d 2d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AO_2147622808_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AO"
        threat_id = "2147622808"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\progra~1\\" ascii //weight: 1
        $x_1_2 = {73 76 63 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = {73 75 62 6d 69 74 00 00 70 61 73 73 77 6f 72 64 00 00 00 00 57 6f 57 2e 63 6f 6d 20 41 63 63 6f 75 6e 74 2f 50 61 73 73 77 6f 72 64 20 52 65 74 72 69 65 76 61 6c 00 00 65 6d 61 69 6c 00 00 00 61 63 63 6f 75 6e 74 4e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_AO_2147622808_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AO"
        threat_id = "2147622808"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "softyinforwow1" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\OKME\\%s" ascii //weight: 2
        $x_1_3 = "worldofwarcraft" ascii //weight: 1
        $x_1_4 = "secretQuestionAnswer" ascii //weight: 1
        $x_1_5 = "/get.asp" ascii //weight: 1
        $x_1_6 = "%s?u=%s&p=%s&action=%s" ascii //weight: 1
        $x_1_7 = "%s?u=%s&p=%s&url=%s&action=%s" ascii //weight: 1
        $x_1_8 = "%s?u=%s&a=%s&m=%s&url=%s&action=%s" ascii //weight: 1
        $x_1_9 = "%s?us=%s&ps=%s&lv=%s&se=%s&qu=%s&os=%s" ascii //weight: 1
        $x_1_10 = "%s?us=%s&ps=%s&lv=%s&se=%s&qu=%s&os=%s&mo=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AQ_2147624743_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AQ"
        threat_id = "2147624743"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data\\zhTW\\realmlist.wtf" ascii //weight: 1
        $x_1_2 = "action=ok&u=" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Blizzard Entertainment\\Wo" ascii //weight: 1
        $x_1_4 = "DivxDecoder.dll" ascii //weight: 1
        $x_1_5 = "/wowReadMb.as" ascii //weight: 1
        $x_3_6 = {50 50 68 60 9c 5b 00 56 89 44 24}  //weight: 3, accuracy: High
        $x_3_7 = {51 51 68 e2 12 61 00 56 89 4c 24}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AR_2147625250_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AR"
        threat_id = "2147625250"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wtf\\config.wtf" ascii //weight: 10
        $x_10_2 = "%s?u=%s&a=%s&m=%s&url=%s&action=%s" ascii //weight: 10
        $x_10_3 = "wowsystemcode" ascii //weight: 10
        $x_1_4 = "/get.asp" ascii //weight: 1
        $x_1_5 = "RegSetValueEx(start)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AO_2147625295_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AO!dll"
        threat_id = "2147625295"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 01 61 75 ?? 80 78 02 75 75 ?? 80 78 03 6e}  //weight: 1, accuracy: Low
        $x_2_2 = {8d 54 24 04 2b c8 6a 06 52 83 e9 05 50 6a ff c6 44 24 14 e9 89 4c 24 15}  //weight: 2, accuracy: High
        $x_2_3 = {b9 09 00 00 00 bf ?? ?? 00 10 8d 34 10 33 db f3 a6 74 0f 42 81 fa 00 00 08 00 72}  //weight: 2, accuracy: Low
        $x_2_4 = {33 db b0 90 68 00 a0 57 00 c6 44 24 10 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AS_2147625932_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AS"
        threat_id = "2147625932"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 24 08 00 00 50 ff 15 ?? ?? ?? ?? 8a 45 0b 83 c4 14 8d 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {80 7d de e8 74 18 80 7d de e9 74 12 0f b6 45 de 3d 84 0f 00 00 74 07 3d 85 0f 00 00 75 13}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 2f 63 2e 61 73 70 3f 63 3d 71 26 69 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 75 3d 25 73 26 70 3d 25 73 26 73 70 3d 25 73 26 6d 62 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 3d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Wowsteal_E_2147627450_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.gen!E"
        threat_id = "2147627450"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 64}  //weight: 10, accuracy: High
        $x_10_2 = {73 76 63 68 6f 73 74 2e 64 6c 6c 00 41 52 00 47 65 74 56 65 72 00}  //weight: 10, accuracy: High
        $x_10_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00}  //weight: 10, accuracy: High
        $x_5_4 = {20 25 73 28 42 75 69 6c 64 5f 25 64 29 00 00 00 20 53 50 36 61 28 42 75 69 6c 64 5f 25 64 29 00 53 50 36 00 57 49 4e 4e 54 00 00 00 57 49 4e 32 30 30 30 00}  //weight: 5, accuracy: High
        $x_5_5 = {53 50 36 00 57 49 4e 4e 54 00 00 00 57 49 4e 32 30 30 30 00 57 49 4e 58 50 00 00 00 57 49 4e 32 30 30 33 00 58 50 5f 50 72 6f 66 65 73 73 69 6f 6e 61 6c 5f 78 36 34 5f 45 64 69 74 69 6f 6e 20 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_UV_2147631309_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.UV"
        threat_id = "2147631309"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4a 50 c6 45 ?? 53 ff 75 e8 c6 45 ?? 5a c6 45 ?? 4c c6 45 ?? 2a c6 45 ?? 2a c6 45 ?? 2a}  //weight: 4, accuracy: Low
        $x_4_2 = {6a 09 50 ff 35 ?? ?? ?? ?? c6 45 ?? 4d c6 45 ?? 5a c6 45 ?? 90 88 5d ?? c6 45 f0 03 88 5d f1}  //weight: 4, accuracy: Low
        $x_2_3 = {25 64 25 64 78 78 78 2e 64 6c 6c 00 78 78 78 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_2_4 = {6b 61 2e 69 6e 69 [0-5] 71 72 77 6f 77}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AV_2147631845_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AV"
        threat_id = "2147631845"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%d%dymg.dll" ascii //weight: 2
        $x_1_2 = "GxWindowClassD3d" ascii //weight: 1
        $x_1_3 = "AppInit_DLLs" ascii //weight: 1
        $x_2_4 = "daerhtetomeretaerc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AX_2147641107_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AX"
        threat_id = "2147641107"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {bf 20 14 86 00 6a 09 57 c6 45 ?? 89 c6 45 ?? 48 c6 45 ?? 04}  //weight: 3, accuracy: Low
        $x_1_2 = {b8 a7 d2 41 00 89 20}  //weight: 1, accuracy: High
        $x_2_3 = {2b f7 8d 04 1f 2b f3 83 c4 0c 83 ee 05 c6 00 e9 89 70 01}  //weight: 2, accuracy: High
        $x_1_4 = {00 77 6f 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64 00}  //weight: 1, accuracy: High
        $x_1_6 = ":65151/djbzcd/i.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Wowsteal_AY_2147641418_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.AY"
        threat_id = "2147641418"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 7d ?? e8 43 05 00 0f 94 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 6a 05 68 ?? ?? 04 00 ff 75 ?? c6 45 ?? 67 c6 45 ?? e4}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 05 50 68 ?? ?? 40 00 ff 75 08 ff ?? 8d 45 ?? c6 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Wowsteal_BC_2147655164_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wowsteal.BC"
        threat_id = "2147655164"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rundll32.exe %s,DW" ascii //weight: 2
        $x_2_2 = "wow.exe" ascii //weight: 2
        $x_2_3 = "LiuMazi" ascii //weight: 2
        $x_2_4 = "http://98.126.48.124/wowpin/mail.asp" ascii //weight: 2
        $x_1_5 = "http://www.1111.com/post.asp" ascii //weight: 1
        $x_1_6 = ".com/mibao.asp" ascii //weight: 1
        $x_1_7 = "http://gmnb.info/bbqcc/mail.asp" ascii //weight: 1
        $x_1_8 = "%s?f1=getpos&f2=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

