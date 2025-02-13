rule TrojanSpy_Win32_Delf_BE_2147506748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BE"
        threat_id = "2147506748"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftpTransfer" ascii //weight: 1
        $x_1_2 = "taskkill.exe -f -im  cmd.exe" ascii //weight: 1
        $x_1_3 = "cmd /k  start C:\\windows\\system\\svchost.exe" ascii //weight: 1
        $x_1_4 = "Todos Arquivos" ascii //weight: 1
        $x_1_5 = "system\\assun.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_CM_2147512061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CM"
        threat_id = "2147512061"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2a 2e 77 61 62 00 00 00 ff ff ff ff 03 00 00 00 77 61 62 00 ff ff ff ff 05 00 00 00 2a 2e 6d 62}  //weight: 4, accuracy: High
        $x_4_2 = {74 62 62 00 ff ff ff ff 06 00 00 00 2a 2e 6d 62 6f 78 00 00 ff ff ff ff 04 00 00 00 6d 62 6f 78}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_2147567388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf"
        threat_id = "2147567388"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "\\R_O_O_T\\" ascii //weight: 1
        $x_1_3 = "/gate1.php" ascii //weight: 1
        $x_1_4 = {50 4f 53 54 00 00 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 51 49 50 5c 00 00 00 ff ff ff ff 0b 00 00 00 5f 73 72 76 6c 6f 67 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_2147582340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf"
        threat_id = "2147582340"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ShellExecuteHooks" ascii //weight: 1
        $x_1_2 = "LOGIN_BTN_PASSWORD.BMP" ascii //weight: 1
        $x_1_3 = "YB_OnlineClient" ascii //weight: 1
        $x_1_4 = "EHSniffer.exe" ascii //weight: 1
        $x_1_5 = "wind88ws20o8" ascii //weight: 1
        $x_1_6 = "wqrndrws40da" ascii //weight: 1
        $x_1_7 = "wqqnd2ws30o8" ascii //weight: 1
        $x_1_8 = "mywindowsdll" ascii //weight: 1
        $x_1_9 = "wlnd0ws30o7" ascii //weight: 1
        $x_1_10 = "dllfile" ascii //weight: 1
        $x_1_11 = "RXJH423NOTEXECUTE" ascii //weight: 1
        $x_1_12 = "Minrosoft 2001" ascii //weight: 1
        $x_1_13 = "FUCKRUIXINGNIMA" ascii //weight: 1
        $x_1_14 = "WOHENHAO_GOOD_Lu4k" ascii //weight: 1
        $x_1_15 = "Verclsid.eXE" ascii //weight: 1
        $x_1_16 = "FuckRINGKAODKFDSK44" ascii //weight: 1
        $x_1_17 = "fuckkv159" ascii //weight: 1
        $x_1_18 = "fucknod32ni" ascii //weight: 1
        $x_1_19 = "sdfc34kkaozt.baT" ascii //weight: 1
        $x_1_20 = "zhengtu_client" ascii //weight: 1
        $x_1_21 = "zhengtu.dat" ascii //weight: 1
        $x_5_22 = {ff ff 8d 45 fc ba ?? ?? 40 00 e8 ?? ?? ff ff [0-22] 8d 45 fc e8 ?? ?? ff ff 8b d0 b9 ?? ?? 40 00 b8 00 00 00 80 e8 ?? ?? ff ff 68 ?? ?? 40 00 8d 45 fc e8 ?? ?? ff ff 8b d0 b9 ?? ?? 40 00 b8 00 00 00 80 e8 ?? ?? ff ff 68 ?? ?? 40 00 ?? ?? ?? 40 00 [0-5] b8 02 00 00 80 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89}  //weight: 5, accuracy: Low
        $x_8_23 = {e8 7f ff ff ff 8d 55 f4 52 50 e8 ?? ?? ff ff 8b 45 f4 50 6a 00 68 18 04 00 00 e8 ?? ?? ff ff 8b d8 85 db 74 42 be ?? 00 00 00 8d 45 f0 8b d6 e8 ?? ?? ff ff 8d 45 f8 50 56 8b 45 f0 e8 ?? ?? ff ff 50 8b 45 fc 50 53 e8 ?? ?? ff ff 85 c0 74 11 8b 45 f0}  //weight: 8, accuracy: Low
        $x_8_24 = {e8 da f8 ff ff 8b f0 8d 44 24 0c 50 53 e8 b1 f5 ff ff 8b 44 24 0c 50 6a 00 6a 10 e8 3b f5 ff ff 8b d8 85 db 74 69 8d 44 24 08 50 6a 04 56 55 53 e8 2e f5 ff ff 85 c0 74 56 8d 44 24 08 50 6a 04 56}  //weight: 8, accuracy: High
        $x_8_25 = {ff ff 8d 45 d8 50 68 80 00 00 00 6a 04 53 e8 ?? ?? ff ff 8d 45 e4 50 6a 04 8d 45 08 50 53 e8 ?? fa ff ff 50 e8 ?? fa ff ff 8d 45 e0 50 8b 45 d8 50 6a 04 53 e8 ?? fa ff ff}  //weight: 8, accuracy: Low
        $x_8_26 = {e8 fb f5 ff ff 66 85 c0 75 64 8d 55 ec 33 c0 e8 08 dc ff ff 8b 45 ec ba 68 66 40 00 e8 27 f7 ff ff 84 c0 74 49 b8 44 6a 40 00 ba 74 4b 40 00 e8 5c fe ff ff a1 44 6a 40 00 e8 f2 fd ff ff 84 c0 74 22 a1 44 6a 40 00 e8 e4 fd ff ff 84 c0 74 1e a1 44 6a 40 00 e8 1a f0 ff ff 50 e8 60 f5 ff ff}  //weight: 8, accuracy: High
        $x_8_27 = {ff ff 8b f0 57 a1 50 ?? 40 00 50 e8 ?? ?? ff ff ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 56 e8 ?? ed ff ff 56 e8 ?? ?? ff ff ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 56 e8 ?? ?? ff ff 8b c3 e8 ?? ?? ff ff 53 e8 ?? ?? ff ff}  //weight: 8, accuracy: Low
        $x_8_28 = {e8 e4 fc ff ff 8b f0 83 fe ff 75 0f 8b c3 e8 56 fd ff ff 53 e8 10 fd ff ff eb 4a 57 a1 50 66 40 00 50 e8 32 fd ff ff 8b f8 6a 00 8d 44 24 04 50 57 55 56 e8 29 fd ff ff 3b 3c 24 74 0f 8b c3 e8 25 fd ff ff 53 e8 df fc ff ff}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_IG_2147583516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.IG"
        threat_id = "2147583516"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2000"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {89 45 f0 89 45 ec 33 c0 55 68 ?? ?? 40 00 64 ff 30 64 89 20 c6 45 ff 00 e8 ?? ?? ff ff 83 c4 f4 db 3c 24 9b 8d 85 e8 fe ff ff e8 ?? ?? ff ff 8d 95 e8 fe ff ff 8d 45 ec e8 ?? ?? ff ff 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 ff 75 ec 8d 85 e4 fe ff ff ba 06 00 00 00 e8}  //weight: 1000, accuracy: Low
        $x_1000_2 = {83 3d 88 96 40 00 00 0f 84 92 00 00 00 68 8c 96 40 00 e8 ?? ?? ff ff 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 8d 55 f4 b8 01 00 00 00 e8 ?? ?? ff ff ff 75 f4 8d 45 f8 ba 0a 00 00 00 e8}  //weight: 1000, accuracy: Low
        $x_100_3 = {ff ff ff ff 08 00 00 00 26 6c 61 73 74 69 64 3d}  //weight: 100, accuracy: High
        $x_100_4 = {ff ff ff ff 06 00 00 00 26 72 61 6e 64 3d}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_A_2147584365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.gen!A"
        threat_id = "2147584365"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2}  //weight: 50, accuracy: High
        $x_1_2 = "WSAStartup" ascii //weight: 1
        $x_1_3 = "gethostname" ascii //weight: 1
        $x_1_4 = "sendto" ascii //weight: 1
        $x_1_5 = "recvfrom" ascii //weight: 1
        $x_1_6 = "@hotmail.com" ascii //weight: 1
        $x_1_7 = "@gmail.com" ascii //weight: 1
        $n_100_8 = "CTX Budgets" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_50_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_C_2147584412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.gen!C"
        threat_id = "2147584412"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {f7 d9 f7 db 83 d9 00 83 f7 01 89 cd b9 40 00 00 00 57 31 ff 31 f6 d1 e0 d1 d2 d1 d6 d1 d7 39 ef}  //weight: 50, accuracy: High
        $x_5_2 = "@nettaxi.com" ascii //weight: 5
        $x_5_3 = "billgates@mocosoft.com" ascii //weight: 5
        $x_1_4 = "MAIL FROM: <" ascii //weight: 1
        $x_1_5 = "RCPT TO: <" ascii //weight: 1
        $x_1_6 = "From:" ascii //weight: 1
        $x_1_7 = "Subject:" ascii //weight: 1
        $x_1_8 = "WinExec" ascii //weight: 1
        $x_1_9 = "WSAStartup" ascii //weight: 1
        $x_1_10 = "gethostbyname" ascii //weight: 1
        $x_1_11 = "socket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_D_2147593019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.gen!D"
        threat_id = "2147593019"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "280"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "HOOK_DLL.dll" ascii //weight: 100
        $x_100_2 = "HookOn" ascii //weight: 100
        $x_10_3 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 10
        $x_10_4 = "C:\\RF_FILE\\" ascii //weight: 10
        $x_10_5 = "RFlogin.exe" ascii //weight: 10
        $x_10_6 = "RF.exe" ascii //weight: 10
        $x_10_7 = "RF_Online.bin" ascii //weight: 10
        $x_10_8 = "ToMail=" ascii //weight: 10
        $x_10_9 = "&User=" ascii //weight: 10
        $x_10_10 = "&Pass=" ascii //weight: 10
        $x_10_11 = "&Server=" ascii //weight: 10
        $x_10_12 = "&WinBanBen=" ascii //weight: 10
        $x_10_13 = "CallNextHookEx" ascii //weight: 10
        $x_10_14 = "ReadProcessMemory" ascii //weight: 10
        $x_10_15 = "InternetReadFile" ascii //weight: 10
        $x_10_16 = "InternetOpenA" ascii //weight: 10
        $x_10_17 = "InternetConnectA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 8 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_DT_2147596595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.DT"
        threat_id = "2147596595"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\HookLib.dll" ascii //weight: 1
        $x_1_2 = "http://www.manyakpc.com" ascii //weight: 1
        $x_5_3 = {0a 00 00 00 4d 50 46 53 45 52 56 49 43 45 00 00 ff ff ff ff 07 00 00 00 41 56 50 2e 45 58 45 00 ff ff ff ff 03 00 00 00 41 56 50 00 ff ff ff ff 0d 00 00 00 5c 77 69 6e 6c 6f 67 6f 6e 2e 64 6c}  //weight: 5, accuracy: High
        $x_5_4 = {8d 55 d0 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? fe ff 8b 55 d0 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 6a 00 8d 85 fc fe ff ff e8 ?? ?? ff ff 8d 85 fc fe ff ff ba ?? ?? ?? ?? e8 ?? ?? f9 ff 8b 85 fc fe ff ff e8 ?? ?? f9 ff 50 8d 85 f8 fe ff ff b9 ?? ?? ?? ?? 8b 55 d4 e8 ?? ?? f9 ff 8b 85 f8 fe ff ff e8 ?? ?? f9 ff 50 e8 ?? ?? f9 ff 8d 85 f4 fe ff ff b9 ?? ?? ?? ?? 8b 55 d4 e8 ?? ?? f9 ff 8b 85 f4 fe ff ff e8 ?? ?? f9 ff 6a 01 8d 85 f0 fe ff ff e8 ?? ?? ff ff 8d 85 f0 fe ff ff ba ?? ?? ?? ?? e8 ?? ?? f9 ff 8b 85 f0 fe ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HE_2147596612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HE"
        threat_id = "2147596612"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DeleteFileDos.bat" ascii //weight: 1
        $x_1_2 = "&money=" ascii //weight: 1
        $x_1_3 = "&bank=" ascii //weight: 1
        $x_1_4 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 70 72 69 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 69 6e 69 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 74 6d 70 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HF_2147597059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HF"
        threat_id = "2147597059"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DeleteFileDos.bat" ascii //weight: 1
        $x_1_2 = "&money=" ascii //weight: 1
        $x_1_3 = "&storage=" ascii //weight: 1
        $x_1_4 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 70 72 69 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 69 6e 69 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 74 6d 70 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_ABF_2147599150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.gen!ABF"
        threat_id = "2147599150"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "_IEBrowserHelper" ascii //weight: 1
        $x_1_3 = "/~user1/errors/db6.php?" ascii //weight: 1
        $x_1_4 = "&POSTDATA=NOW" ascii //weight: 1
        $x_1_5 = "&COOKIEDATA=NOW" ascii //weight: 1
        $x_1_6 = "&WINDATA=NOW" ascii //weight: 1
        $x_1_7 = {62 72 6f 77 73 65 72 68 65 6c 70 65 72 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_8 = "C:\\TEMP\\\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HI_2147600206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HI"
        threat_id = "2147600206"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "(Yukar" ascii //weight: 1
        $x_1_3 = "(Insert) " ascii //weight: 1
        $x_1_4 = "(Numlock) " ascii //weight: 1
        $x_1_5 = "(Ctrl)" ascii //weight: 1
        $x_1_6 = "(Pause) " ascii //weight: 1
        $x_1_7 = "{ESC} " ascii //weight: 1
        $x_1_8 = "\\windrivers.log" ascii //weight: 1
        $x_1_9 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_10 = "mailsend" ascii //weight: 1
        $x_1_11 = "acilistacalis" ascii //weight: 1
        $x_1_12 = "FormKeyDown" ascii //weight: 1
        $x_1_13 = "smtp_server=" ascii //weight: 1
        $x_1_14 = "smtp_user=" ascii //weight: 1
        $x_1_15 = "srv_file=winserv.exe" ascii //weight: 1
        $x_1_16 = "BackLogger@yahoo.com" ascii //weight: 1
        $x_1_17 = "BackLogger Victim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HJ_2147600235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HJ"
        threat_id = "2147600235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "Software\\Mz\\OpenIe2" ascii //weight: 1
        $x_1_3 = "OpenIe 2006" ascii //weight: 1
        $x_1_4 = "IEFrame" ascii //weight: 1
        $x_1_5 = "[InternetShortcut]" ascii //weight: 1
        $x_1_6 = "url.dll" ascii //weight: 1
        $x_1_7 = "TDownInfo" ascii //weight: 1
        $x_1_8 = "[Setupahomepage]" ascii //weight: 1
        $x_1_9 = "[Interposecollect]" ascii //weight: 1
        $x_1_10 = "[Downloadprocedure]" ascii //weight: 1
        $x_1_11 = "[Concealdarkball]" ascii //weight: 1
        $x_1_12 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_13 = "http://www.hao123.com/" ascii //weight: 1
        $x_1_14 = "http://vip.zeiwang.cn/images/logo.gif" ascii //weight: 1
        $x_1_15 = "Start Page" ascii //weight: 1
        $x_1_16 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_17 = "TaskMgr.Exe" ascii //weight: 1
        $x_1_18 = "VerCLSID.exe" ascii //weight: 1
        $x_1_19 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_ZK_2147601043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.ZK"
        threat_id = "2147601043"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Paleex|-Lca`mdlu(QQ8" ascii //weight: 1
        $x_1_2 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_3 = "Kayitlar'i Geldi." ascii //weight: 1
        $x_1_4 = "\\ras\\syskrnl.sys" ascii //weight: 1
        $x_1_5 = "eiajUc`jocuEnygb|,beb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_AVG_2147601161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.AVG"
        threat_id = "2147601161"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_3 = "Process32Next" ascii //weight: 5
        $x_5_4 = "WinExec" ascii //weight: 5
        $x_5_5 = "mixerOpen" ascii //weight: 5
        $x_5_6 = "KAVPFW.EXE" ascii //weight: 5
        $x_5_7 = "RogueCleaner.exe" ascii //weight: 5
        $x_5_8 = "\\commonds.pif" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_EC_2147602194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.EC"
        threat_id = "2147602194"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "explorerbar" wide //weight: 10
        $x_10_2 = "\\System\\screen.jpg" ascii //weight: 10
        $x_10_3 = "\\System\\svchosts.exe" ascii //weight: 10
        $x_10_4 = "\\System32\\svchosts.exe" ascii //weight: 10
        $x_1_5 = "DavizinX ScreenLogger" ascii //weight: 1
        $x_1_6 = "davizinxtools@daviiznx.com" ascii //weight: 1
        $x_1_7 = "DavizinXKeylogger@davizinx.com" ascii //weight: 1
        $x_1_8 = "http://www.davizinx.com/davizin.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_HK_2147602572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HK"
        threat_id = "2147602572"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "ExeMutex_ADSAL" ascii //weight: 1
        $x_1_3 = "DllMutex_ADSAL" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_6 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_8 = ":\\Program Files\\Common Files\\SYSTEM\\" ascii //weight: 1
        $x_1_9 = "\\InprocServer32" ascii //weight: 1
        $x_1_10 = "adsal.dat" ascii //weight: 1
        $x_1_11 = "adsal.dll" ascii //weight: 1
        $x_1_12 = "NetWorkLogon" ascii //weight: 1
        $x_1_13 = "Service4005381" ascii //weight: 1
        $x_1_14 = "{D18E336D-8C58-0615-8133-E6B60112AA06}" ascii //weight: 1
        $x_1_15 = "{B10343BD-1DC6-442f-9BA2-D44C708CEE83}" ascii //weight: 1
        $x_1_16 = "{1A404685-7563-4d02-B0F6-58B308A406A9}" ascii //weight: 1
        $x_1_17 = "{9A0CFC58-5A6F-41ba-9FFE-4320F4F621BA}" ascii //weight: 1
        $x_1_18 = "{6E44887F-5214-41F2-AB46-4728735C4CC6}" ascii //weight: 1
        $x_1_19 = "Probable reason is that another daemon is already running on the same port" ascii //weight: 1
        $x_1_20 = "Proxy Authentication Required" ascii //weight: 1
        $x_1_21 = "access_log" ascii //weight: 1
        $x_1_22 = "FindExecutableA" ascii //weight: 1
        $x_1_23 = "gethostbyaddr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_BD_2147623602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BD"
        threat_id = "2147623602"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftpTransfer" ascii //weight: 1
        $x_1_2 = "C:\\windows\\winhelp23.ini" ascii //weight: 1
        $x_1_3 = "system\\svchost.exe" ascii //weight: 1
        $x_1_4 = "system\\sysconf.cpl" ascii //weight: 1
        $x_1_5 = "cmd /k  start C:\\windows\\system\\sysconf.cpl" ascii //weight: 1
        $x_2_6 = "Dominada ftp! ** reenvio!!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_BG_2147624745_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BG"
        threat_id = "2147624745"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "http://m2stealer.hostil.pl/c.php?logi=" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\wdmgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_BH_2147626588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BH"
        threat_id = "2147626588"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "input_mail_pwd2" ascii //weight: 1
        $x_1_2 = "LOCA-WEB WEBMAIL" ascii //weight: 1
        $x_1_3 = "pc_login" ascii //weight: 1
        $x_1_4 = "pc_password" ascii //weight: 1
        $x_1_5 = "hp-username-inp" ascii //weight: 1
        $x_1_6 = "hp-password-inp" ascii //weight: 1
        $x_1_7 = "mail.terra.com.br" ascii //weight: 1
        $x_1_8 = "igempresas.com.br" ascii //weight: 1
        $x_1_9 = "https://www.no-ip.com/login/?logout=1" ascii //weight: 1
        $x_1_10 = "ProgressChange: " ascii //weight: 1
        $x_1_11 = "CommandStateChange: COMMAND:" ascii //weight: 1
        $x_1_12 = "Download Begin" ascii //weight: 1
        $x_1_13 = "Download Complete" ascii //weight: 1
        $x_1_14 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HM_2147628350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HM"
        threat_id = "2147628350"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 69 70 6f 3d 00 00 00 ff ff ff ff 07 00 00 00 6e 6f 6d 65 70 63 3d 00 ff ff ff ff 04 00 00 00 69 6e 66 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 74 78 74 00 00 00 00 6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HN_2147628355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HN"
        threat_id = "2147628355"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 20 4d 73 6e 28 00 ff ff ff ff 01 00 00 00 29 00 00 00 ff ff ff ff 08 00 00 00 20 2d 20 57 41 42 20 28 00}  //weight: 1, accuracy: High
        $x_1_2 = {7d 03 47 eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_HO_2147628933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.HO"
        threat_id = "2147628933"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 72 6f 6d 3a 20 00 00 ff ff ff ff 04 00 00 00 63 63 3a 20}  //weight: 1, accuracy: High
        $x_2_2 = "net stop SharedAccess" ascii //weight: 2
        $x_2_3 = "netsh firewall opmode disable" ascii //weight: 2
        $x_2_4 = {4d 41 49 4c 00 00 00 00 45 58 45 46 49 4c 45 00}  //weight: 2, accuracy: High
        $x_1_5 = ".txt" ascii //weight: 1
        $x_1_6 = "*.mbox" ascii //weight: 1
        $x_1_7 = "*.wab" ascii //weight: 1
        $x_1_8 = "*.mbx" ascii //weight: 1
        $x_1_9 = "*.eml" ascii //weight: 1
        $x_1_10 = "*.tbb" ascii //weight: 1
        $x_1_11 = {4f 50 45 4e 20 00 00 00 ff ff ff ff 0d 00 00 00 55 53 45 52 20 25 73 40 25 73 40 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_BT_2147632097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BT"
        threat_id = "2147632097"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 8b d0 03 d3 c6 02 e9 2b f0 2b f3 83 ee 05 42 89 32 8b c3 5d 5f 5e}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 89 3e 8b d6 83 c2 05 8b c3 e8 7a 00 00 00 8b d6 83 c2 04 88 02 c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05}  //weight: 1, accuracy: High
        $x_1_3 = "---/$$/POST_URL=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_BW_2147632201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BW"
        threat_id = "2147632201"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e2KeyPress" ascii //weight: 1
        $x_1_2 = "email=l1n5x@ig.com.br" ascii //weight: 1
        $x_1_3 = "from=bye@oi.com" ascii //weight: 1
        $x_1_4 = "from=ola@oi.com" ascii //weight: 1
        $x_1_5 = "subject=" ascii //weight: 1
        $x_1_6 = "http://www.clubhifi.nl/envia.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Delf_BY_2147638325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BY"
        threat_id = "2147638325"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Capturou Senha_HotMail ->" ascii //weight: 3
        $x_3_2 = "Capturou Usuario_Gmail ->" ascii //weight: 3
        $x_1_3 = "mail.terra.com.br" ascii //weight: 1
        $x_1_4 = "Control Panel\\Desktop\\WindowMetrics\\MinAnimate" ascii //weight: 1
        $x_2_5 = "[[[[[FIM SE MATAR]]]]]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_BZ_2147638388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.BZ"
        threat_id = "2147638388"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "IESniffer1URLChange" ascii //weight: 3
        $x_2_2 = "[Print Screen]" ascii //weight: 2
        $x_3_3 = "c:\\windows\\system\\chache\\CurrentVersiyon\\WinXP\\svchost.exe" ascii //weight: 3
        $x_1_4 = "Software\\Microsoft\\windows\\currentversion\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_CE_2147638402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CE"
        threat_id = "2147638402"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\svsc.dll" ascii //weight: 1
        $x_1_2 = "http://sveta.in/1/upload.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_CG_2147639555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CG"
        threat_id = "2147639555"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Image2Click" ascii //weight: 1
        $x_2_2 = "o do php google gmail qe ta la na pasta de hospedagem" ascii //weight: 2
        $x_2_3 = "emailKeyDown" ascii //weight: 2
        $x_2_4 = "Gmail: Email do Google - Windows Internet Explorer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_CH_2147641245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CH"
        threat_id = "2147641245"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\csrss.exe" ascii //weight: 3
        $x_2_2 = "Fly For Fun" ascii //weight: 2
        $x_1_3 = "Timer1Timer" ascii //weight: 1
        $x_2_4 = ":\\WINDOWS\\system32\\drivers\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_CJ_2147641439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CJ"
        threat_id = "2147641439"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Microsoft\\smss.exe" ascii //weight: 3
        $x_2_2 = "SS Security Services" ascii //weight: 2
        $x_4_3 = "http://freezdec.ru/serviceupdate.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_CL_2147642011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CL"
        threat_id = "2147642011"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Content-Disposition: form-data; name=\"pwdata\"; filename=\"pwdata\"" ascii //weight: 4
        $x_3_2 = "?type=0&email=" ascii //weight: 3
        $x_3_3 = "inetcomm server passwords" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_CO_2147642559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CO"
        threat_id = "2147642559"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KeySpyXP" ascii //weight: 2
        $x_2_2 = "KeyWord.Scroll_Lock" ascii //weight: 2
        $x_2_3 = "{NUMPAD DIVIDE}" ascii //weight: 2
        $x_2_4 = "DJ Mentos" ascii //weight: 2
        $n_6_5 = {4d 6f 74 79 6c 2e 65 78 65 00}  //weight: -6, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_CZ_2147648122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.CZ"
        threat_id = "2147648122"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 73 6d 6d 74 74 70 70 [0-48] 74 65 78 74 6f [0-16] 68 74 74 70 3a 2f 2f 77 77 77 2e 77 61 72 64 72 61 6b 65 2e 6e 65 74 2f 69 64 65 61 [0-32] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 6d 73 73 6e 6e [0-48] 74 65 78 74 6f [0-16] 68 74 74 70 3a 2f 2f 77 77 77 2e 77 61 72 64 72 61 6b 65 2e 6e 65 74 2f 69 64 65 61 [0-32] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_DC_2147649030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.DC"
        threat_id = "2147649030"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ftp.narod.ru" ascii //weight: 1
        $x_1_2 = "Hackloggs" ascii //weight: 1
        $x_1_3 = {53 79 73 74 65 6d 33 32 5c 54 65 73 74 5c 44 69 72 ?? 5c 44 69 72 [0-64] 5c 73 63 72 65 65 6e 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_DH_2147654782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.DH"
        threat_id = "2147654782"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ba e2 04 8b 45 ?? e8 [0-48] 8b 08 ff 51 38 [0-160] 66 ba e2 04 8b 45 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {45 4d 61 69 6c 3a [0-24] 53 65 72 76}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 6f 6d 65 [0-24] 74 65 78 74 6f [0-24] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Delf_DL_2147656892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.DL"
        threat_id = "2147656892"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "WindowsLive:name=*" ascii //weight: 5
        $x_5_2 = "ImRemoteKeylogger$$Finish" ascii //weight: 5
        $x_1_3 = "[BACKSPACE]" ascii //weight: 1
        $x_1_4 = "[Tab]" ascii //weight: 1
        $x_1_5 = "[Del]" ascii //weight: 1
        $x_1_6 = "*Username*: " ascii //weight: 1
        $x_1_7 = "*Password*: " ascii //weight: 1
        $x_1_8 = "Versione di Windows: @@" ascii //weight: 1
        $x_1_9 = "Versione del server: @@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Delf_DN_2147657426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Delf.DN"
        threat_id = "2147657426"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Documento em anexo" ascii //weight: 1
        $x_1_2 = "tipo=" ascii //weight: 1
        $x_1_3 = "hotmail" ascii //weight: 1
        $x_1_4 = "post.srf" ascii //weight: 1
        $x_1_5 = "login?logout=1&.intl=br&.src=ym&.pd=ym_ver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

