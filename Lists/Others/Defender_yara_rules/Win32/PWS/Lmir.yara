rule PWS_Win32_Lmir_2147574193_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir"
        threat_id = "2147574193"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 18 88 9c 3d f3 fe ff ff ff 75 fc 53 68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 8b f8 3b fb 74 11 53 57 ff 15 ?? ?? ?? ?? 6a ff 57 ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_5 = "AVP.AlertDialog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_ZX_2147583442_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.ZX"
        threat_id = "2147583442"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "1A404685-7563-4d02-B0F6-58B308A406A9" ascii //weight: 50
        $x_20_2 = "CreateRemoteThread" ascii //weight: 20
        $x_4_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 4
        $x_4_4 = "client.exe" ascii //weight: 4
        $x_4_5 = "SrvHost.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_ZX_2147583442_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.ZX"
        threat_id = "2147583442"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "YB_OnlineClient" ascii //weight: 4
        $x_3_2 = "Accept-Language: zh-cn" ascii //weight: 3
        $x_3_3 = "SeDebugPrivilege" ascii //weight: 3
        $x_1_4 = "Host: %s" ascii //weight: 1
        $x_2_5 = "QElementClient" ascii //weight: 2
        $x_1_6 = "Pass=" ascii //weight: 1
        $x_1_7 = "User=" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\" ascii //weight: 1
        $x_1_9 = "subject" ascii //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_ZY_2147583725_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.ZY"
        threat_id = "2147583725"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mhmain.dll" ascii //weight: 1
        $x_1_2 = "ZtGame_IN" ascii //weight: 1
        $x_1_3 = "ZtGame_OUT" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_6 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_7 = "InternetCloseHandle" ascii //weight: 1
        $x_1_8 = "InternetOpenA" ascii //weight: 1
        $x_1_9 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule PWS_Win32_Lmir_ZZ_2147583726_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.ZZ"
        threat_id = "2147583726"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZtGame_IN" ascii //weight: 5
        $x_5_2 = "ZtGame_OUT" ascii //weight: 5
        $x_1_3 = "other=" ascii //weight: 1
        $x_1_4 = "equ=" ascii //weight: 1
        $x_1_5 = "role=" ascii //weight: 1
        $x_1_6 = "wupin=" ascii //weight: 1
        $x_1_7 = "pin=" ascii //weight: 1
        $x_1_8 = "pass=" ascii //weight: 1
        $x_1_9 = "gameid=" ascii //weight: 1
        $x_1_10 = "server=" ascii //weight: 1
        $x_1_11 = "CallNextHookEx" ascii //weight: 1
        $x_1_12 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_13 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_AAA_2147583727_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AAA"
        threat_id = "2147583727"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "elementclient.exe" ascii //weight: 10
        $x_1_2 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_1_7 = "InternetConnectA" ascii //weight: 1
        $x_1_8 = "User=" ascii //weight: 1
        $x_1_9 = "Pass=" ascii //weight: 1
        $x_1_10 = "Serv=" ascii //weight: 1
        $x_1_11 = "People=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_AAB_2147583728_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AAB"
        threat_id = "2147583728"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ghook" ascii //weight: 1
        $x_1_2 = "del \"" ascii //weight: 1
        $x_1_3 = "if exist \"" ascii //weight: 1
        $x_1_4 = "goto try" ascii //weight: 1
        $x_1_5 = "del %0" ascii //weight: 1
        $x_1_6 = "DATEINFOexe" ascii //weight: 1
        $x_1_7 = "urlsend" ascii //weight: 1
        $x_1_8 = "~hook" ascii //weight: 1
        $x_1_9 = "StarHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule PWS_Win32_Lmir_AAV_2147583827_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AAV"
        threat_id = "2147583827"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "other=" ascii //weight: 1
        $x_1_2 = "role=" ascii //weight: 1
        $x_1_3 = "wupin=" ascii //weight: 1
        $x_1_4 = "pass=" ascii //weight: 1
        $x_1_5 = "gameid=" ascii //weight: 1
        $x_1_6 = "server=" ascii //weight: 1
        $x_1_7 = "CallNextHookEx" ascii //weight: 1
        $x_1_8 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_9 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_10 = "Accept-Encoding: gzip, deflate" ascii //weight: 1
        $x_1_11 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_12 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword, */*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule PWS_Win32_Lmir_I_2147593206_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.gen!I"
        threat_id = "2147593206"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_25_1 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword, */*" ascii //weight: 25
        $x_15_2 = "http://maplestory.nexon.com" ascii //weight: 15
        $x_15_3 = "WebModules/SignUp/MainLogin:tbEmail" ascii //weight: 15
        $x_15_4 = "WebModules/SignUp/MainLogin:tbPassword" ascii //weight: 15
        $x_5_5 = "c:\\1.txt" ascii //weight: 5
        $x_15_6 = "/Pages/MyMaple/ModifyPWD:tbPassword1" ascii //weight: 15
        $x_15_7 = "/Pages/MyMaple/ModifyPWD:tbPassword2" ascii //weight: 15
        $x_15_8 = "Tencent_Traveler_Main_Window" ascii //weight: 15
        $x_15_9 = "maoxiandao mapfile" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_15_*) and 1 of ($x_5_*))) or
            ((6 of ($x_15_*))) or
            ((1 of ($x_25_*) and 4 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_K_2147593311_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.gen!K"
        threat_id = "2147593311"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3200"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "HookProc" ascii //weight: 1000
        $x_1000_2 = "InstallALLHook" ascii //weight: 1000
        $x_1000_3 = "TroyDLL.dll" ascii //weight: 1000
        $x_50_4 = "WSAStartup" ascii //weight: 50
        $x_50_5 = "ReadProcessMemory" ascii //weight: 50
        $x_50_6 = "WriteProcessMemory" ascii //weight: 50
        $x_50_7 = "Toolhelp32ReadProcessMemory" ascii //weight: 50
        $x_5_8 = "mir.dat" ascii //weight: 5
        $x_1_9 = "www.microsoft.com" ascii //weight: 1
        $x_1_10 = "explorer.exe" ascii //weight: 1
        $x_1_11 = "ActiveNetworkMonitor.exe" ascii //weight: 1
        $x_1_12 = "adns_dll.dll" ascii //weight: 1
        $x_1_13 = "bvtversion.dll" ascii //weight: 1
        $x_1_14 = "cain.exe" ascii //weight: 1
        $x_1_15 = "Cap2k.dll" ascii //weight: 1
        $x_1_16 = "Capnt.dll" ascii //weight: 1
        $x_1_17 = "CaptureNet.exe" ascii //weight: 1
        $x_1_18 = "cmmonzc.dll" ascii //weight: 1
        $x_1_19 = "cports.exe" ascii //weight: 1
        $x_1_20 = "cutesniffer.exe" ascii //weight: 1
        $x_1_21 = "cv.exe" ascii //weight: 1
        $x_1_22 = "egui.exe" ascii //weight: 1
        $x_1_23 = "ehsniffer.exe" ascii //weight: 1
        $x_1_24 = "ent.exe" ascii //weight: 1
        $x_1_25 = "entutil.dll" ascii //weight: 1
        $x_1_26 = "eqnetx.dll" ascii //weight: 1
        $x_1_27 = "Ethereal.exe" ascii //weight: 1
        $x_1_28 = "eye.exe" ascii //weight: 1
        $x_1_29 = "fsav.exe" ascii //weight: 1
        $x_1_30 = "fwcom.exe" ascii //weight: 1
        $x_1_31 = "fwmain.exe" ascii //weight: 1
        $x_1_32 = "gagent.dll" ascii //weight: 1
        $x_1_33 = "gcenter.exe" ascii //weight: 1
        $x_1_34 = "icesword.exe" ascii //weight: 1
        $x_1_35 = "iconv.dll" ascii //weight: 1
        $x_1_36 = "iris.exe" ascii //weight: 1
        $x_1_37 = "jahpacket.dll" ascii //weight: 1
        $x_1_38 = "kvfw.exe" ascii //weight: 1
        $x_1_39 = "kvsock_1.dll" ascii //weight: 1
        $x_1_40 = "LGUISdkRes.dll" ascii //weight: 1
        $x_1_41 = "mtna.exe" ascii //weight: 1
        $x_1_42 = "netacrypto.dll" ascii //weight: 1
        $x_1_43 = "NetAnalyzer.exe" ascii //weight: 1
        $x_1_44 = "netcheck.exe" ascii //weight: 1
        $x_1_45 = "NetConnectManager.exe" ascii //weight: 1
        $x_1_46 = "NetPryer.exe" ascii //weight: 1
        $x_1_47 = "NetSnifferV3.exe" ascii //weight: 1
        $x_1_48 = "NetworkView.exe" ascii //weight: 1
        $x_1_49 = "NETXRAY.EXE" ascii //weight: 1
        $x_1_50 = "PacScope.exe" ascii //weight: 1
        $x_1_51 = "PeepNet.exe" ascii //weight: 1
        $x_1_52 = "pfw.exe" ascii //weight: 1
        $x_1_53 = "ppihapi.dll" ascii //weight: 1
        $x_1_54 = "rfwdrv.dll" ascii //weight: 1
        $x_1_55 = "rfwmain.exe" ascii //weight: 1
        $x_1_56 = "rfwsrv.exe" ascii //weight: 1
        $x_1_57 = "SeePort.exe" ascii //weight: 1
        $x_1_58 = "sfmsrv.dll" ascii //weight: 1
        $x_1_59 = "sifrwlsnapin.dll" ascii //weight: 1
        $x_1_60 = "skymisc.dll" ascii //weight: 1
        $x_1_61 = "smbfilesniffer.exe" ascii //weight: 1
        $x_1_62 = "smcomm.dll" ascii //weight: 1
        $x_1_63 = "sniffem.exe" ascii //weight: 1
        $x_1_64 = "sniffer.exe" ascii //weight: 1
        $x_1_65 = "sns.exe" ascii //weight: 1
        $x_1_66 = "SockMon5.exe" ascii //weight: 1
        $x_1_67 = "srmon.dll" ascii //weight: 1
        $x_1_68 = "tcpview.exe" ascii //weight: 1
        $x_1_69 = "tpfw.exe" ascii //weight: 1
        $x_1_70 = "tpw.dll" ascii //weight: 1
        $x_1_71 = "trmail.dll" ascii //weight: 1
        $x_1_72 = "usft_ext.dll" ascii //weight: 1
        $x_1_73 = "vsniffer.exe" ascii //weight: 1
        $x_1_74 = "wit.exe" ascii //weight: 1
        $x_1_75 = "wpe pro.exe" ascii //weight: 1
        $x_1_76 = "wpespy.dll" ascii //weight: 1
        $x_1_77 = "WSockExpert.exe" ascii //weight: 1
        $x_1_78 = "WSockHook.dll" ascii //weight: 1
        $x_1_79 = "XGuard.exe" ascii //weight: 1
        $x_1_80 = "csrss.ex" ascii //weight: 1
        $x_1_81 = "services.exe" ascii //weight: 1
        $x_1_82 = "lsass.ex" ascii //weight: 1
        $x_1_83 = "avpcc.ex" ascii //weight: 1
        $x_1_84 = "avp32.ex" ascii //weight: 1
        $x_1_85 = "antivirus.ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1000_*) and 3 of ($x_50_*) and 50 of ($x_1_*))) or
            ((3 of ($x_1000_*) and 3 of ($x_50_*) and 1 of ($x_5_*) and 45 of ($x_1_*))) or
            ((3 of ($x_1000_*) and 4 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_L_2147593512_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.gen!L"
        threat_id = "2147593512"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_25_1 = "RavMon.exe" ascii //weight: 25
        $x_25_2 = "ZoneAlarm" ascii //weight: 25
        $x_25_3 = "ZAFrameWnd" ascii //weight: 25
        $x_25_4 = "EGHOST.EXE" ascii //weight: 25
        $x_25_5 = "MAILMON.EXE" ascii //weight: 25
        $x_25_6 = "netbargp.exe" ascii //weight: 25
        $x_25_7 = "vrvmon.EXE" ascii //weight: 25
        $x_5_8 = "PFW.EXE" ascii //weight: 5
        $x_5_9 = "KAVPFW.EXE" ascii //weight: 5
        $x_5_10 = "SendMail" ascii //weight: 5
        $x_5_11 = "MirRecord" ascii //weight: 5
        $x_5_12 = "AUTH LOGIN" ascii //weight: 5
        $x_1_13 = "MAIL FROM:" ascii //weight: 1
        $x_1_14 = "127.0.0.1" ascii //weight: 1
        $x_2_15 = "@yahoo.com.cn" ascii //weight: 2
        $x_2_16 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii //weight: 2
        $x_2_17 = "ReadProcessMemory" ascii //weight: 2
        $x_2_18 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_19 = "CallNextHookEx" ascii //weight: 2
        $x_1_20 = "WSAStartup" ascii //weight: 1
        $x_1_21 = "WinExec" ascii //weight: 1
        $x_2_22 = "RegisterServiceProcess" ascii //weight: 2
        $x_2_23 = "CreateToolhelp32Snapshot" ascii //weight: 2
        $x_2_24 = "Toolhelp32ReadProcessMemory" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_25_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_25_*) and 4 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_25_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_25_*) and 4 of ($x_5_*) and 8 of ($x_2_*))) or
            ((5 of ($x_25_*) and 5 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_25_*) and 5 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_25_*) and 5 of ($x_5_*) and 5 of ($x_2_*))) or
            ((6 of ($x_25_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_25_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_25_*) and 5 of ($x_2_*))) or
            ((6 of ($x_25_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_25_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_25_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((6 of ($x_25_*) and 2 of ($x_5_*))) or
            ((7 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_M_2147593513_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.gen!M"
        threat_id = "2147593513"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "155"
        strings_accuracy = "High"
    strings:
        $x_25_1 = "StartHook" ascii //weight: 25
        $x_25_2 = "StopHook" ascii //weight: 25
        $x_25_3 = "Host:" ascii //weight: 25
        $x_25_4 = "Proxy-Connection: Keep-Alive" ascii //weight: 25
        $x_25_5 = "mir.dat" ascii //weight: 25
        $x_25_6 = "mir.exe" ascii //weight: 25
        $x_5_7 = "WinExec" ascii //weight: 5
        $x_5_8 = "ReadProcessMemory" ascii //weight: 5
        $x_5_9 = "UnhookWindowsHookEx" ascii //weight: 5
        $x_5_10 = "SetWindowsHookExA" ascii //weight: 5
        $x_5_11 = "CallNextHookEx" ascii //weight: 5
        $x_5_12 = "WSAStartup" ascii //weight: 5
        $x_5_13 = "gethostbyname" ascii //weight: 5
        $x_5_14 = "socket" ascii //weight: 5
        $x_5_15 = "URLDownloadToFileA" ascii //weight: 5
        $x_5_16 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_17 = "Toolhelp32ReadProcessMemory" ascii //weight: 5
        $n_150_18 = "Only registered version of Iparmor can clean" ascii //weight: -150
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_25_*) and 11 of ($x_5_*))) or
            ((5 of ($x_25_*) and 6 of ($x_5_*))) or
            ((6 of ($x_25_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_BMM_2147596718_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.BMM"
        threat_id = "2147596718"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "mir1.dat" ascii //weight: 1
        $x_1_3 = "MirAZBConstAddr:" ascii //weight: 1
        $x_1_4 = "m_ServerAddr:" ascii //weight: 1
        $x_1_5 = "/CQServer/recvMail.asp?UserPWD=" ascii //weight: 1
        $x_1_6 = "avp32.ex" ascii //weight: 1
        $x_1_7 = "fsav.exe" ascii //weight: 1
        $x_1_8 = "msmpsvc." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_BMM_2147596929_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.BMM!dll"
        threat_id = "2147596929"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "mir1.dat" ascii //weight: 1
        $x_1_3 = "m_LoginAddr:" ascii //weight: 1
        $x_1_4 = "m_ServerAddr:" ascii //weight: 1
        $x_1_5 = "m_MBPYConstAddr:" ascii //weight: 1
        $x_1_6 = "/CQServer/recvMail.asp?UserPWD=" ascii //weight: 1
        $x_1_7 = "svchost.H" ascii //weight: 1
        $x_1_8 = "antivirus.ex|" ascii //weight: 1
        $x_1_9 = "msmpsvc." ascii //weight: 1
        $x_1_10 = "fsav.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_ZD_2147598427_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.ZD"
        threat_id = "2147598427"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mir1.dat" ascii //weight: 1
        $x_1_2 = {45 6e 64 48 6f 6f 6b 00 47 65 74 49 6e 73 74 53 6f 75 46 69 6c 65 00 47 65 74 54 72 56 65 72 73 69 6f 6e 00 53 65 74 49 6e 69 74 53 74 61 74 65 00 53 65 74 49 6e 73 74 53 6f 75 46 69 6c 65 00 53 74 61 72 74 48 6f 6f 6b 00 53 74 61 72 74 4c 69 73 74 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 ec 04 01 00 00 80 a5 fc fe ff ff 00 53 56 57 6a 40 33 c0 59 8d bd fd fe ff ff f3 ab 66 ab 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? aa ff 15 ?? ?? ?? ?? 8b d8 8d 85 fc fe ff ff 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8d 85 fc fe ff ff 6a 5c 50 ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b f0 46 68 ?? ?? ?? ?? 56 ff d7 83 c4 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_BMQ_2147598477_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.BMQ"
        threat_id = "2147598477"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 6f 75 6c c7 45 ?? 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_2 = {41 75 74 6f c7 45 ?? 50 61 74 63 c7 45 ?? 68 2e 65 78 c7 45 ?? 65 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {2e 5c 73 6f c7 45 ?? 75 6c 2e 65 c7 45 ?? 78 65 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = "InternetOpenA" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "soul.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_AGZ_2147598568_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AGZ"
        threat_id = "2147598568"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_3_2 = {53 6e 61 70 73 68 6f 74 00 00 00 00 48 65 61 70}  //weight: 3, accuracy: High
        $x_3_3 = {6d 69 72 32 00 00 54 46 72 6d 4d 61 69 6e 00}  //weight: 3, accuracy: High
        $x_1_4 = "TTroyMir" ascii //weight: 1
        $x_1_5 = ".asp?UserPWD=" ascii //weight: 1
        $x_1_6 = "explorer.exe" ascii //weight: 1
        $x_1_7 = "Woool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_BMO_2147598602_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.BMO"
        threat_id = "2147598602"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "Toolhelp32ReadProcessMemory" ascii //weight: 10
        $x_10_3 = "Woool" ascii //weight: 10
        $x_10_4 = "http://ekey.sdo.com" ascii //weight: 10
        $x_1_5 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_6 = "kav." ascii //weight: 1
        $x_1_7 = "mir1.dat" ascii //weight: 1
        $x_1_8 = "wow." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_BMS_2147598622_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.BMS"
        threat_id = "2147598622"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MTJvXcJeYczkXtRpEBRMXb=]QtRmYCzoZ?>PVTFsWSJbYm" ascii //weight: 1
        $x_1_2 = "ohdPmyPwjYM]RR>kQ?@FwHCupgfMIb@G|XxZjGlGvIp^kWdSfxLSeWLEvxdxjIkt|ixniXlSrZWvewoqoxpCo{Kx{aFfZBNlYdFbXdOroHOhokOzgyhYjXtPiI|ieWI" ascii //weight: 1
        $x_1_3 = "RR>kQBJsUovaXCm" ascii //weight: 1
        $x_1_4 = "ChangeServiceConfig2W" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = {c6 45 e6 fc c6 45 e8 f0 c6 45 ea c0 33 c0 89 45 f0 33 db bf 02 00 00 00 33 c0 89 45 ec 33 f6 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_8 = {8a 45 e3 24 3f 25 ff 00 00 00 89 45 dc b9 06 00 00 00 2b cf d3 6d dc 33 c0 8a c3 0b 45 dc 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_AHB_2147602287_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AHB"
        threat_id = "2147602287"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".WOOOL." wide //weight: 1
        $x_1_2 = "zhengtu.dat" wide //weight: 1
        $x_1_3 = "\\data\\woool.dat" wide //weight: 1
        $x_1_4 = "ifyoudothatagainiwillkickyourass" wide //weight: 1
        $x_1_5 = "#32770" wide //weight: 1
        $x_1_6 = "RAVMON" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_AHC_2147602409_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AHC"
        threat_id = "2147602409"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {74 69 6f 6e 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 53 4f 46 54 57 41 52 45 5c 54 45 4e 43 45 4e 54 5c}  //weight: 3, accuracy: High
        $x_1_2 = {55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 55 8b ec 83 c4 ec 83 65 f8 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00 47 65 74 50 72 6f 63}  //weight: 1, accuracy: High
        $x_4_4 = {83 65 fa 00 66 c7 45 fe e3 03 ff 5d fa 8b c4 8b 64 24 04 50 fa 0f 20 c0}  //weight: 4, accuracy: High
        $x_2_5 = {66 c7 00 72 6f 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80}  //weight: 2, accuracy: High
        $x_2_6 = {3b 45 0c 75 26 8b 45 e8 03 45 08 83 e8 02 8b 00 66 3d c7 05 75 15}  //weight: 2, accuracy: High
        $x_2_7 = {c7 45 f8 02 00 00 00 6a 00 6a 00 6a 10 8d 45 ec 50 6a 00 ff 75 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_AZ_2147604939_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AZ"
        threat_id = "2147604939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "ChangeNumRead" ascii //weight: 1
        $x_1_3 = "DoFunction" ascii //weight: 1
        $x_1_4 = "HookProc" ascii //weight: 1
        $x_1_5 = "InstallHook" ascii //weight: 1
        $x_1_6 = "OpenForm" ascii //weight: 1
        $x_1_7 = "RecPack" ascii //weight: 1
        $x_1_8 = "SwSend" ascii //weight: 1
        $x_1_9 = "UnHook" ascii //weight: 1
        $x_1_10 = {77 73 32 5f 33 32 2e 64 6c 6c 00 00 73 65 6e 64 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 68 65 79 64}  //weight: 1, accuracy: Low
        $x_1_11 = "MYDLLDATA" ascii //weight: 1
        $x_1_12 = {25 2e 32 58 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 42 65 65 70 20 4f 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? 42 65 65 70 20 4f 66 66}  //weight: 1, accuracy: Low
        $x_1_13 = {6a 00 6a 00 6a 00 68 1f 00 0f 00 53 e8 ?? ?? fb ff 89 06 8b 06 c6 40 1b 58 8b 06 c6 40 1c 00 8b 06 c6 40 22 00 8b 06 c6 40 25 00 8b 06 c6 40 1d 00 8b 06 c6 40 1e 00 8b 06 80 78 1f 39 74 06 8b 06 c6 40 1f 58 8b 06 c6 40 05 58 8b 06 c6 40 21 00 8b 06 c6 40 23 01 8b 06 c6 40 32 01 8b 06 66 c7 40 34 01 09 8b 06 c6 40 37 fd 8b 06 c6 40 45 00 8b 06 c6 40 36 ff 83 3e 00 75 19 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_F_2147604995_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.F"
        threat_id = "2147604995"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "/lin.asp|http://" ascii //weight: 3
        $x_3_2 = "fzz~4!!yyy" ascii //weight: 3
        $x_5_3 = {83 c4 1c b8 01 00 00 00 8a 94 24 ?? ?? 00 00 8a 8c 04 ?? ?? 00 00 32 ca 88 8c 04 ?? ?? 00 00 40 3d 80 00 00 00 7c e1}  //weight: 5, accuracy: Low
        $x_2_4 = {68 ff 0f 1f 00 ff 15}  //weight: 2, accuracy: High
        $x_1_5 = {20 2f 25 78 40 00}  //weight: 1, accuracy: High
        $x_2_6 = ".exe /100" ascii //weight: 2
        $x_2_7 = "/1003@C:\\" ascii //weight: 2
        $x_1_8 = "mhs2.exe" ascii //weight: 1
        $x_1_9 = "mhs.exe" ascii //weight: 1
        $x_1_10 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_11 = "#32770" ascii //weight: 1
        $x_1_12 = {80 40 00 6a 65}  //weight: 1, accuracy: High
        $x_1_13 = "msend" ascii //weight: 1
        $x_1_14 = "RavMon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_E_2147604998_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.E!dll"
        threat_id = "2147604998"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?sn=%s&un=%s&pw=%s&sp=%s&pn=%s&gd1=%d&gd2=%d" ascii //weight: 1
        $x_1_2 = "\\system32\\mywininet100.dll" ascii //weight: 1
        $x_1_3 = "\\system32\\wininet.dll" ascii //weight: 1
        $x_1_4 = "\\system32\\ws2_32.dll" ascii //weight: 1
        $x_1_5 = "soul.exe" ascii //weight: 1
        $x_1_6 = "WinInet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_E_2147604999_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.E"
        threat_id = "2147604999"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntsd -c q -p " ascii //weight: 1
        $x_1_2 = "KRegEx.exe" ascii //weight: 1
        $x_1_3 = "KVXP.kxp" ascii //weight: 1
        $x_1_4 = "360tray.exe" ascii //weight: 1
        $x_1_5 = "RUNIEP.EXE" ascii //weight: 1
        $x_1_6 = "iexploer.exe" ascii //weight: 1
        $x_1_7 = "mywinsys.ini" ascii //weight: 1
        $x_1_8 = "dll_hitpop" ascii //weight: 1
        $x_1_9 = "Install.asp?ver=" ascii //weight: 1
        $x_1_10 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_11 = "AVP.TrafficMonConnectionTerm" ascii //weight: 1
        $x_1_12 = "AVP.Button" ascii //weight: 1
        $x_1_13 = "FindWindowA" ascii //weight: 1
        $x_1_14 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_15 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule PWS_Win32_Lmir_AHD_2147605406_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AHD"
        threat_id = "2147605406"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 1c 53 55 56 57 68 3f 00 0f 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 68 ff 01 0f 00 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 4c 24 10 51 6a 01 50 ff 15 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 83 c4 0c 85 c0 74 19 50 6a 00 68 01 04 10 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = "360Tray.exe" ascii //weight: 1
        $x_1_3 = "360Safe.exe" ascii //weight: 1
        $x_1_4 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_5 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "SetServiceStatus" ascii //weight: 1
        $x_1_9 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_10 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_J_2147606748_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.J"
        threat_id = "2147606748"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "KRegEx.exe" ascii //weight: 1
        $x_1_3 = "KVXP.kxp" ascii //weight: 1
        $x_1_4 = "360tray.exe" ascii //weight: 1
        $x_1_5 = "win.ini" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_7 = ".lnk" ascii //weight: 1
        $x_1_8 = "C:\\Windows\\iexplore.$" ascii //weight: 1
        $x_1_9 = "IEframe" ascii //weight: 1
        $x_1_10 = "<a href=" ascii //weight: 1
        $x_1_11 = {6a 00 6a 00 68 ?? ?? ?? 00 6a 00 6a 00 e8 ?? ?? fd ff 33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 33 c0 5a 59 59 64 89 10 eb 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lmir_O_2147609673_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.O"
        threat_id = "2147609673"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 c6 45 f8 e9 50 56 57 88 5d f9 88 5d fa 88 5d fb 88 5d fc}  //weight: 1, accuracy: High
        $x_1_2 = {32 c0 c6 45 f8 e9 88 45 f9 88 45 fa 88 45 fb 88 45 fc 89 35 ?? ?? ?? 10 83 05 ?? ?? ?? 10 05 8d 45 f8 50 56}  //weight: 1, accuracy: Low
        $x_1_3 = {53 55 56 8b 74 24 10 57 66 8b 46 06 66 3d 21 00 74 0a 66 3d 35 00 0f 85 ?? ?? 00 00 66 81 7e 10 aa 0f}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 74 24 08 57 8d 3c 30 3b f7 73 ?? 81 3e 44 ff 44 ff 75}  //weight: 1, accuracy: Low
        $x_1_5 = {81 3e 6a 00 6a 00 75 ?? 81 7e 04 6a 00 52 83}  //weight: 1, accuracy: Low
        $x_1_6 = {81 3e 0f b7 42 08 75 ?? 81 7e 04 0f b7 4a 0a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Lmir_S_2147609927_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.S"
        threat_id = "2147609927"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 51 4c 6f c7 45 ?? 67 69 6e 2e c7 45 ?? 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 3f 61 c7 45 ?? 3d 34 26 75 c7 45 ?? 3d 25 73 26}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 65 63 c7 45 ?? 75 74 65 48 c7 45 ?? 6f 6f 6b 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Lmir_X_2147611290_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.X"
        threat_id = "2147611290"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 64 76 61 c7 44 24 ?? 70 69 33 32 c7 44 24 ?? 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_4_2 = {2b 7d 08 8b cf 8b 75 08 eb 05 80 36 6e 46 49 0b c9 75 f7 6a 00 8d 45 f8 50 57 ff 75 08 ff 75 fc}  //weight: 4, accuracy: High
        $x_1_3 = {c7 07 0d 0a 0d 0a 83 c7 04 c6 07 00}  //weight: 1, accuracy: High
        $x_1_4 = "filtres%d.sav" ascii //weight: 1
        $x_1_5 = "foeman%d.sav" ascii //weight: 1
        $x_2_6 = {2e 64 6c 6c 00 49 6e 73 74 48 6f 6f 6b 50 72 6f 63 00 55 6e 49 6e 73 74 48 6f 6f 6b 50 72 6f 63}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_AQ_2147622318_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.AQ"
        threat_id = "2147622318"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "gethostname" ascii //weight: 10
        $x_10_2 = "closesocket" ascii //weight: 10
        $x_10_3 = "Woool.dat" ascii //weight: 10
        $x_10_4 = "TTroyWoool" ascii //weight: 10
        $x_10_5 = "WARE\\Borland\\Delphi" ascii //weight: 10
        $x_1_6 = {50 6a 20 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 85 c0 74 ?? c7 44 ?? ?? 01 00 00 00 8d 44 ?? ?? 50 68 ?? ?? 40 00 6a 00 e8 ?? ?? ?? ?? 80 ?? ?? 00 74 ?? c7 44 ?? ?? 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = "g_UserPwdAddr:" ascii //weight: 1
        $x_1_8 = "www.microsoft.com" ascii //weight: 1
        $x_1_9 = "\\\\mrgtask2" ascii //weight: 1
        $x_1_10 = "map\\88X600.nmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lmir_EO_2147691773_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lmir.EO"
        threat_id = "2147691773"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 79 63 71 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {2d 3e 25 73 2c 25 73 2c 25 73 00 00 00 00 4c 61 73 74 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "call sendto, send data to %s port:%d,len:%d" ascii //weight: 1
        $x_1_4 = "gameid=%s&PassWord=%s&key=%s&quyu=%s&mirserver=%s&count=%i&zt=%s&action=submit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

