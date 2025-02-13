rule PWS_Win32_Lineage_A_2147573987_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!A"
        threat_id = "2147573987"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_2_2 = "name=\"file1\"; filename=\"c:" ascii //weight: 2
        $x_2_3 = "-7d56b1cf06a6" ascii //weight: 2
        $x_1_4 = "X-Mailer: <FOXMAIL" ascii //weight: 1
        $x_1_5 = "; charset=\"GB2312\"" ascii //weight: 1
        $x_1_6 = "&subject=" ascii //weight: 1
        $x_1_7 = "&sender=" ascii //weight: 1
        $x_1_8 = "Connection: Close" ascii //weight: 1
        $x_2_9 = "Lineage Windows Client" ascii //weight: 2
        $x_2_10 = "serverListWnd" ascii //weight: 2
        $x_1_11 = "Lineage.exe" ascii //weight: 1
        $x_2_12 = "MapleStoryClass" ascii //weight: 2
        $x_1_13 = "lin.bin" ascii //weight: 1
        $x_1_14 = "YB_OnlineClient" ascii //weight: 1
        $x_1_15 = "D3D Window" ascii //weight: 1
        $x_1_16 = "QElementClient Window" ascii //weight: 1
        $x_1_17 = "Element Client" ascii //weight: 1
        $x_1_18 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_19 = "IEFrame" ascii //weight: 1
        $x_1_20 = "Software\\Hacker" ascii //weight: 1
        $x_1_21 = "Shell_TrayWnd" ascii //weight: 1
        $x_1_22 = "c:\\game" ascii //weight: 1
        $x_1_23 = "JumpHookOn" ascii //weight: 1
        $x_1_24 = "JumpHookOff" ascii //weight: 1
        $x_2_25 = "lockpass:" ascii //weight: 2
        $x_2_26 = "game:TianTang" ascii //weight: 2
        $x_1_27 = {73 65 72 76 65 72 3a 00}  //weight: 1, accuracy: High
        $x_2_28 = ".gamania.com" ascii //weight: 2
        $x_1_29 = "Yulgang_File" ascii //weight: 1
        $x_1_30 = "&Server=" ascii //weight: 1
        $x_1_31 = "&UserName=" ascii //weight: 1
        $x_1_32 = "&Password=" ascii //weight: 1
        $x_1_33 = "&Role3=" ascii //weight: 1
        $x_1_34 = "&Role4=" ascii //weight: 1
        $x_1_35 = "&Role1=" ascii //weight: 1
        $x_1_36 = "&Role2=" ascii //weight: 1
        $x_1_37 = "&PCName=" ascii //weight: 1
        $x_1_38 = "&Money=" ascii //weight: 1
        $x_1_39 = "&SBody=" ascii //weight: 1
        $x_1_40 = "&ToMail=" ascii //weight: 1
        $x_1_41 = ".cgi?uin1=" ascii //weight: 1
        $x_1_42 = "&pay_select=" ascii //weight: 1
        $x_1_43 = "&pay_card_no=" ascii //weight: 1
        $x_1_44 = "&pay_card_sn=" ascii //weight: 1
        $x_1_45 = "name=\"account\"" ascii //weight: 1
        $x_2_46 = {41 00 50 b8 ?? ?? 41 00 50 6a 03 e8}  //weight: 2, accuracy: Low
        $x_3_47 = {68 00 01 00 00 8d 85 ?? ?? ?? ff 50 53 e8 ?? ?? ?? ff c6 85 ?? ?? ?? ff 00 68 00 01 00 00 8d 85 ?? ?? ?? ff 50 53}  //weight: 3, accuracy: Low
        $x_4_48 = {8b 45 fc 8b 55 f8 8a 5c 10 ff [0-3] 8d 45 f4 8b d3 e8 ?? ?? ?? ff 8b 55 f4 8b c7 e8 ?? ?? ?? ff ff 45 f8 4e 75 d9}  //weight: 4, accuracy: Low
        $x_1_49 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_50 = "GetWindowTextA" ascii //weight: 1
        $x_1_51 = "GetKeyboardType" ascii //weight: 1
        $x_1_52 = "gethostbyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((18 of ($x_1_*))) or
            ((1 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_2_*))) or
            ((1 of ($x_3_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_4_*) and 14 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_B_2147581559_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!B"
        threat_id = "2147581559"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#32770" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "bcdefghi8921306qrstuvwxyz547jklmnopa" ascii //weight: 1
        $x_1_4 = "WXYZ9213065478FGHIJKLMABCDENOPQRSTUV" ascii //weight: 1
        $x_1_5 = "RavMon.exe" ascii //weight: 1
        $x_1_6 = "\\explorer.exe" ascii //weight: 1
        $x_1_7 = "PendingFileRenameOperations" ascii //weight: 1
        $x_1_8 = "SYSTEM\\CurrentControlSet\\Control\\Session Manager" ascii //weight: 1
        $x_1_9 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_10 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_11 = "WinExec" ascii //weight: 1
        $x_3_12 = {ff 15 40 10 40 00 3b c3 74 08 53 50 ff 15 74 10 40 00 8b 3d 44 10 40 00 8d 45 f8 50 53 53 68 ?? 15 40 00 53 53 ff d7 8b f0 68 e8 03 00 00 56 ff 15 34 10 40 00 56 8b 35 b4 10 40 00 ff d6 8d 45 f8 50 53 53 68 ?? 1a 40 00 53 53 ff d7 50 ff d6}  //weight: 3, accuracy: Low
        $x_3_13 = {ff 15 a4 10 40 00 53 68 80 00 00 00 6a 02 53 53 8d 85 80 fe ff ff 68 00 00 00 40 50 ff 15 98 10 40 00 83 f8 ff 89 45 fc 75 68 8d 85 80 fe ff ff 56 50 ff 15 50 10 40 00 8d 85 80 fe ff ff 68 ?? 12 40 00 50 e8 ?? 01 00 00 8d 85 80 fe ff ff 68 54 12 40 00 50 e8 ?? 01 00 00 83 c4 10 8d 85 80 fe ff ff 50 ff 15 a4 10 40 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_CC_2147582221_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.CC"
        threat_id = "2147582221"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {be d0 42 00 10 56 57 57 ff 15 ?? 20 00 10 3b c7 89 45 f8}  //weight: 5, accuracy: Low
        $x_5_2 = "VIRUS_ASMAPING_XZASDWRTTYEEWD82473M" ascii //weight: 5
        $x_1_3 = "CreateMutexA" ascii //weight: 1
        $x_1_4 = "OpenMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lineage_C_2147583266_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!C"
        threat_id = "2147583266"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Content-Disposition:" ascii //weight: 5
        $x_5_2 = "Accept: image" ascii //weight: 5
        $x_5_3 = "game.txt" ascii //weight: 5
        $x_5_4 = "Accept-Language: zh-cn" ascii //weight: 5
        $x_5_5 = "Explorer_Server" ascii //weight: 5
        $x_5_6 = "HookOff" ascii //weight: 5
        $x_5_7 = "HookOn" ascii //weight: 5
        $x_5_8 = "server.ini" ascii //weight: 5
        $x_5_9 = "SeDebugPrivilege" ascii //weight: 5
        $x_2_10 = "TianShi" ascii //weight: 2
        $x_1_11 = "GetSystemInfo server" ascii //weight: 1
        $x_1_12 = "getmem user:" ascii //weight: 1
        $x_2_13 = "Lineage Windows Client" ascii //weight: 2
        $x_1_14 = "MapleStoryC" ascii //weight: 1
        $x_2_15 = "serverListWnd" ascii //weight: 2
        $x_1_16 = "tbMainAccount" ascii //weight: 1
        $x_1_17 = "login_p.asp" ascii //weight: 1
        $x_1_18 = "GASHLogin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((9 of ($x_5_*) and 5 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((9 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_I_2147593205_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!I"
        threat_id = "2147593205"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {68 0d 19 00 00 6a 00 6a 04 6a 00 6a ff e8 [0-4] 8b 15 [0-4] 89 02 6a 00 6a 00 6a 00 68 1f 00 0f 00 a1 [0-4] 8b 00 50 e8 [0-4] 8b 15 [0-4] 89 02 a1 [0-4] 8b 00 8b 40 04}  //weight: 30, accuracy: Low
        $x_30_2 = {85 c0 74 39 8d 45 f8 50 68 80 00 00 00 6a 04 53 e8 [0-8] 50 6a 04 8d 45 14 50 53 e8 [0-4] 50 e8 [0-8] 8d 45 f4 50 8b 45 f8 50 6a 04 53 e8}  //weight: 30, accuracy: Low
        $x_30_3 = {8b da 3b 3b 0f 94 c0 f6 d8 1b c0 83 f8 01 1b c9 41 84 c9 75 24 8b 0b 3b 0d b4 13 41 00 76 1a 8b 0b 8a 09 3a 0d ac 13 41 00 75 0e 8b 03 40 8b d8 3b 3b 0f 94 c0 f6 d8 1b c0}  //weight: 30, accuracy: High
        $x_20_4 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 [0-4] 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c [0-4] 46 69 6e 64 4e 65 78 74 46 69 6c 65 57 [0-4] 4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e [0-4] 6e 74 64 6c 6c 2e 64 6c 6c}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((3 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_K_2147593309_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!K"
        threat_id = "2147593309"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 40
        $x_20_2 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 [0-16] 55 8b ec 33 c0 55 68 [0-4] 64 ff 30 64 89 20 ff 05 [0-4] 33 c0 5a 59 59 64 89 10 68 48}  //weight: 20, accuracy: Low
        $x_20_3 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword" ascii //weight: 20
        $x_10_4 = "Accept-Language: zh-cn" ascii //weight: 10
        $x_10_5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" ascii //weight: 10
        $x_10_6 = "Content-Disposition: form-data; name=\"file1\"; filename=" ascii //weight: 10
        $x_10_7 = "Content-Type: application/ochd" ascii //weight: 10
        $x_10_8 = "modifygs mapfile" ascii //weight: 10
        $x_10_9 = {43 74 32 44 6c 6c 2e 64 6c 6c 00 48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e}  //weight: 10, accuracy: High
        $x_10_10 = "http://df.hangame.com/?GO=home" ascii //weight: 10
        $x_10_11 = {69 64 5f 68 69 64 64 65 6e 00 00 00 ff ff ff ff 09 00 00 00 70 61 73 73 77 6f 72 64 32}  //weight: 10, accuracy: High
        $x_10_12 = {4b 65 79 48 6f 6f 6b 2e 64 6c 6c 00 4d 73 67 48 6f 6f 6b 4f 66 66 00 4d 73 67 48 6f 6f 6b 4f 6e}  //weight: 10, accuracy: High
        $x_10_13 = {63 3a 5c 31 2e 74 78 74 [0-16] 68 74 74 70 3a 2f 2f 64 66 2e 68 61 6e 67 61 6d 65 2e 63 6f 6d [0-16] 69 64 5f 68 69 64 64 65 6e}  //weight: 10, accuracy: Low
        $x_10_14 = "DNF.exe" ascii //weight: 10
        $x_10_15 = "http://www.yamsgame.com/itembay/sendmail.asp?tomail=wdo" ascii //weight: 10
        $x_10_16 = "-----------------------------7cf1d6c47c" ascii //weight: 10
        $x_10_17 = "file one content. Contant-Type can be application/octet-stream or ifyou want you can ask your OS fot the exact type" ascii //weight: 10
        $x_10_18 = "http://218.36.124.41/demogs/demo.asp" ascii //weight: 10
        $x_10_19 = "Tencent_Traveler_Main_Window" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*))) or
            ((1 of ($x_20_*) and 7 of ($x_10_*))) or
            ((2 of ($x_20_*) and 5 of ($x_10_*))) or
            ((1 of ($x_40_*) and 5 of ($x_10_*))) or
            ((1 of ($x_40_*) and 1 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_40_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_L_2147597891_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!L"
        threat_id = "2147597891"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Accept-Language: zh-cn" ascii //weight: 5
        $x_5_2 = {c6 44 24 18 26 c6 44 24 19 6d c6 44 24 1a 6f c6 44 24 1b 64}  //weight: 5, accuracy: High
        $x_1_3 = "ineage.exe" ascii //weight: 1
        $x_1_4 = "Lineage Windows Client" ascii //weight: 1
        $x_1_5 = "?mailbody=" ascii //weight: 1
        $x_1_6 = "Sendmail.exe" ascii //weight: 1
        $x_1_7 = {4d 75 6d 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {2e 64 61 74 00 61 73 64 66}  //weight: 1, accuracy: High
        $x_10_9 = "GetWindowTextA" ascii //weight: 10
        $x_10_10 = "SetWindowsHookExA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_WI_2147602373_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.WI"
        threat_id = "2147602373"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6c 32 55 6e 72 65 61 6c 57 57 69 6e 64 6f 77 73 56 69 65 77 70 6f 72 74 57 69 6e 64 6f 77 [0-4] 4c 69 6e 65 61 67 65 20 49 49}  //weight: 10, accuracy: Low
        $x_10_2 = "Lineage launcher" ascii //weight: 10
        $x_10_3 = {53 68 65 6c 6c 48 6f 6f 6b 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: High
        $x_10_4 = "Fws2_32.dll" ascii //weight: 10
        $x_5_5 = "InternetReadFile" ascii //weight: 5
        $x_5_6 = "CallNextHookEx" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_SJ_2147603225_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.SJ"
        threat_id = "2147603225"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 55 56 57 ff 15 ?? ?? ?? ?? 3d c0 d4 01 00 73 07 68 60 ea 00 00 eb 05 68 88 13 00 00 ff 15 ?? ?? ?? ?? 33 (ff 57 57 ff 15 ?? ?? ?? ?? 89|db 53 53 ff 15 ?? ?? ?? ?? 89)}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d5 85 c0 75 63 b9 14 00 00 00 bf ?? ?? ?? ?? f3 ab 8b fe 83 c9 ff f2 ae f7 d1 2b f9 6a 14 8b d1 8b f7 bf ?? ?? ?? ?? c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 48 6f 6f 6b 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 4b 4f 53 00 00 00 00 32 30 30 33 00 00 00 00 58 70 00 00 32 4b 00 00 4e 54 00 00 3b 00 00 00 25 64 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 53 41 46 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lineage_WL_2147608158_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.WL"
        threat_id = "2147608158"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 18 2b fe 8b 4c 24 24 8a 14 37 51 52 8b cb e8 ?? ?? ff ff 88 06 46 4d 75 ea 5f 5e 5d 5b c2 14 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 8b 4d 0c 25 ff 00 00 00 89 4d 0c 89 45 08 50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lineage_WM_2147609248_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.WM"
        threat_id = "2147609248"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 14 45 40 00 b8 6c 66 40 00 e8 93 e5 ff ff b8 6c 66 40 00 e8 25 e3 ff ff e8 0c e1 ff ff 68 28 45 40 00 8d 55 e8 33 c0 e8 59 e2 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "del %0" ascii //weight: 1
        $x_1_3 = "c:\\aa.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lineage_CH_2147610864_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.CH"
        threat_id = "2147610864"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 4, accuracy: Low
        $x_3_2 = {7f 11 8b 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7e 3c 8d 45 ?? e8 ?? ?? ?? ?? 50 8b 45 ?? 50 8b 00 ff 50 48}  //weight: 3, accuracy: Low
        $n_1_3 = {0f 84 2d 01 00 00 6a 00 53 e8 ?? ?? ff ff 8b f0 81 fe 00 00 00 01 0f 83 11 01 00 00 3b 35 ?? ?? ?? ?? 7c 34}  //weight: -1, accuracy: Low
        $n_1_4 = {8b 55 fc e8 ?? ?? ff ff 8b 85 ?? ?? ff ff e8 ?? ?? ff ff 56 57 e8 ?? ?? ff ff 85 c0 75 84 57 e8 ?? ?? ff ff c7 06 16 00 00 00}  //weight: -1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_E_2147616661_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.gen!E"
        threat_id = "2147616661"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 62 61 74 00 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_4 = "3FDEB171-8F86-9558-0001-69B8DB553683" ascii //weight: 1
        $x_1_5 = {73 79 73 74 65 6d 33 32 5c 73 79 73 6a 70 69 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lineage_CK_2147618486_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.CK"
        threat_id = "2147618486"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 11 b0 d8 88 41 04 8b 54 24 04 8d 4c 24 04 51 52 6a 05 68 ?? ?? ?? 10 ff d6}  //weight: 2, accuracy: Low
        $x_1_2 = {ff d6 ff d0 5e 61 e9}  //weight: 1, accuracy: High
        $x_2_3 = {51 6a 05 8d 55 d4 52 56 8b 7d 2c 8b 07 50 ff 15 ?? ?? 00 10 85 c0 0f 84 ?? ?? 00 00 83 bd ?? ?? ?? ff 05 0f 85}  //weight: 2, accuracy: Low
        $x_1_4 = {48 6f 6f 6b 47 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "LineAge2Bee.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lineage_CL_2147622140_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.CL"
        threat_id = "2147622140"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 4a 75 6d 70 48 6f 6f 6b 4f 66 66 00 4a 75 6d 70 48 6f 6f 6b 4f 6e}  //weight: 1, accuracy: High
        $x_1_2 = "e1xp2lore3r" ascii //weight: 1
        $x_1_3 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/4.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lineage_EA_2147806851_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lineage.EA"
        threat_id = "2147806851"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lineage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ",abcLaunchEv" ascii //weight: 10
        $x_10_2 = {47 45 54 20 2f [0-16] 3f 6d 61 69 6c 62 6f 64 79 3d}  //weight: 10, accuracy: Low
        $x_10_3 = "SvcHostDLL.exe" ascii //weight: 10
        $x_10_4 = "C:\\Sendmail.exesdfasdfasdfdda001" ascii //weight: 10
        $x_5_5 = "My Muma" ascii //weight: 5
        $x_5_6 = "winabc" ascii //weight: 5
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

