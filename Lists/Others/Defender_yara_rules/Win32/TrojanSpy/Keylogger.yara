rule TrojanSpy_Win32_Keylogger_2147494913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger"
        threat_id = "2147494913"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 6d 75 73 74 20 62 65 20 72 75 6e 20 75 6e 64 65 72 20 57 69 6e 33 32 5b 55 70 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 4e 75 6d 20 4c 6f 63 6b 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = "[%s %d-%d-%d %d:%d:%d]" ascii //weight: 1
        $x_1_4 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 6e 6b 6f 77 6e 20 55 73 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Keylogger_2147494913_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger"
        threat_id = "2147494913"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 52 45 43 59 43 4c 45 52 5c 74 65 6d 70 30 31 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "[ENTER]" wide //weight: 1
        $x_1_3 = "[BKSP]" wide //weight: 1
        $x_1_4 = "[INSERT]" wide //weight: 1
        $x_1_5 = {e9 52 02 00 00 83 ff 40 76 1b 83 ff 5b 73 16 6a 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_EJ_2147594710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.EJ"
        threat_id = "2147594710"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "91"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bpk.dat" wide //weight: 10
        $x_10_2 = "web.dat" wide //weight: 10
        $x_10_3 = "bpkch.dat" wide //weight: 10
        $x_10_4 = "keystrokes.html" wide //weight: 10
        $x_10_5 = "websites.html" wide //weight: 10
        $x_10_6 = "chats.html" wide //weight: 10
        $x_10_7 = "report.txt" wide //weight: 10
        $x_5_8 = "WriteProcessMemory" ascii //weight: 5
        $x_5_9 = "WindowsHookEx" ascii //weight: 5
        $x_5_10 = "FtpPutFile" ascii //weight: 5
        $x_5_11 = "FtpSetCurrentDirectory" ascii //weight: 5
        $x_5_12 = "GetKeyboardLayout" ascii //weight: 5
        $x_5_13 = "CORRECT.dll" ascii //weight: 5
        $x_6_14 = "EXECryptor V2.3.9.0.Demo.CracKed.By : fly" ascii //weight: 6
        $x_1_15 = "DLL_GetProjectVersion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 5 of ($x_5_*))) or
            ((7 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 5 of ($x_5_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_EK_2147594711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.EK"
        threat_id = "2147594711"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "126"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "taskmgr.exe" ascii //weight: 10
        $x_10_2 = "pk.bin" ascii //weight: 10
        $x_10_3 = "apps.dat" ascii //weight: 10
        $x_10_4 = "titles.dat" ascii //weight: 10
        $x_10_5 = "inst.dat" ascii //weight: 10
        $x_10_6 = "r.exe" ascii //weight: 10
        $x_10_7 = "hk.dll" ascii //weight: 10
        $x_10_8 = "vw.exe" ascii //weight: 10
        $x_10_9 = "un.exe" ascii //weight: 10
        $x_10_10 = "Log upload date: %s" ascii //weight: 10
        $x_5_11 = "WriteProcessMemory" ascii //weight: 5
        $x_5_12 = "WindowsHookEx" ascii //weight: 5
        $x_5_13 = "FtpPutFile" ascii //weight: 5
        $x_5_14 = "ZwQuerySystemInformation" ascii //weight: 5
        $x_5_15 = "CORRECT.dll" ascii //weight: 5
        $x_1_16 = "DLL_GetProjectVersion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_AQ_2147597966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.AQ"
        threat_id = "2147597966"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "hidefromprocesslist" ascii //weight: 1
        $x_1_3 = "smtp.someserver.something" ascii //weight: 1
        $x_1_4 = "keylogreport" ascii //weight: 1
        $x_1_5 = "email@someserver" ascii //weight: 1
        $x_1_6 = "key logger project\\logger\\Project1.vbp" wide //weight: 1
        $x_1_7 = "78E1BDD1-9941-11cf-9756-00AA00C0090" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_EO_2147599846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.EO"
        threat_id = "2147599846"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 79 5f 6e 61 6d 65 3d 6d 61 69 6c 20 61 64 72 65 73 69 6e 69 7a 69 20 79 61 7a fd 6e fd 7a 2e}  //weight: 1, accuracy: High
        $x_1_2 = "host_name=ftp.bilgihawuzu.com" ascii //weight: 1
        $x_1_3 = {70 61 73 73 5f 6e 61 6d 65 3d 68 61 77 75 7a 33 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 ff ff ff ff 24 00 00 00 70 6f 72 74 5f 6e 61 6d 65 3d 32 31 20}  //weight: 1, accuracy: High
        $x_1_4 = "Tvirkeylog" ascii //weight: 1
        $x_2_5 = {77 69 6e 73 79 73 62 67 2e 64 6c 6c 00 00 00 00 4d 6f 75 73 65 48 6f 6f 6b 5f 53 74 61 72 74 00 4d 6f 75 73 65 48 6f 6f 6b 5f 53 74 6f 70 00 00 4d 6f 75 73 65 48 6f 6f 6b 5f 47 65 74 44 61 74 61 00 00 00 4d 6f 75 73 65 48 6f 6f 6b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_EQ_2147599890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.EQ"
        threat_id = "2147599890"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "index.php?msg=%s&email=%s&from=%s" ascii //weight: 1
        $x_1_2 = "evilcoderz" ascii //weight: 1
        $x_1_3 = "klhook" ascii //weight: 1
        $x_1_4 = ":*:Enabled:" ascii //weight: 1
        $x_1_5 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_6 = "enter" ascii //weight: 1
        $x_1_7 = "backspace" ascii //weight: 1
        $x_1_8 = "insert" ascii //weight: 1
        $x_1_9 = "scroll_lock" ascii //weight: 1
        $x_1_10 = "pause" ascii //weight: 1
        $x_1_11 = "prnt_scrn" ascii //weight: 1
        $x_1_12 = "caps_lock" ascii //weight: 1
        $x_1_13 = "shift" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_ER_2147599898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.ER"
        threat_id = "2147599898"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows\\lsass.exe" ascii //weight: 1
        $x_1_2 = "\\windows\\services.ini" ascii //weight: 1
        $x_1_3 = "Kopath" ascii //weight: 1
        $x_1_4 = "KnightOnline" ascii //weight: 1
        $x_10_5 = {6a 00 68 34 e3 45 00 68 34 e3 45 00 8d 45 d8 ba dc 6c 46 00 b9 91 00 00 00 e8 98 69 fa ff 8d 45 d8 ba 40 e3 45 00 e8 e7 69 fa ff 8b 45 d8 e8 a3 6b fa ff 50 68 54 e3 45 00 6a 00 e8 32 9a fc ff}  //weight: 10, accuracy: High
        $x_10_6 = {b9 6c df 45 00 ba 7c df 45 00 8b c3 8b 30 ff 56 04 8b c3 e8 7d 5c fa ff 6a ff 8d 45 e8 ba dc 6c 46 00 b9 91 00 00 00 e8 ed 6c fa ff 8d 45 e8 ba 94 df 45 00 e8 3c 6d fa ff 8b 45 e8 e8 f8 6e fa ff 50 68 ac df 45 00 e8 c1 89 fa ff b8 54 df 45 00 e8 e3 6e fa ff 50 e8 d9 89 fa ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_ES_2147599923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.ES"
        threat_id = "2147599923"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kavpfw.exe" ascii //weight: 1
        $x_1_2 = "Eghost.exe" ascii //weight: 1
        $x_1_3 = "Ravmon.exe" ascii //weight: 1
        $x_1_4 = "Pfw.exe" ascii //weight: 1
        $x_1_5 = "Explorer.EXE" ascii //weight: 1
        $x_1_6 = "Netbargp.exe" ascii //weight: 1
        $x_1_7 = "KMailMon.exe" ascii //weight: 1
        $x_1_8 = "Iparmor.exe" ascii //weight: 1
        $x_1_9 = "Kvmonxp.exe" ascii //weight: 1
        $x_1_10 = "\\qijian.exe" ascii //weight: 1
        $x_1_11 = "\\qijian.dll" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_ET_2147599927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.ET"
        threat_id = "2147599927"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SevenMutex" ascii //weight: 1
        $x_1_2 = "BUGGetKey" ascii //weight: 1
        $x_1_3 = ":[%s]IP:[%s]-%s" ascii //weight: 1
        $x_1_4 = "<Enter>" ascii //weight: 1
        $x_1_5 = "<CTRL>" ascii //weight: 1
        $x_1_6 = "Sevenlink" ascii //weight: 1
        $x_1_7 = "psmtpinfo->Msg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_EV_2147601438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.EV"
        threat_id = "2147601438"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TClientSocket" ascii //weight: 1
        $x_5_2 = {ff ff ff ff 0a 00 00 00 5b 43 41 50 53 4c 4f 43 4b 5d 00 00 ff ff ff ff 05 00 00 00 5b 45 53 43 5d}  //weight: 5, accuracy: High
        $x_5_3 = {43 3a 5c 64 6c 6c 73 65 72 77 2e 64 6c 6c 00 00 26 00 00 00 01 00 00 00 14 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 66 64 6c 6c 2e 64 6c 6c}  //weight: 5, accuracy: High
        $x_5_4 = {48 45 4c 4f [0-56] 41 55 54 48 20 4c 4f 47 49 4e 0d 0a 00 00 00 00 ff ff ff ff 0c 00 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 00 00 00 00 ff ff ff ff 01 00 00 00 3e 00 00 00 ff ff ff ff 0a 00 00 00 52 43 50 54 20 54 4f 3a 20 3c}  //weight: 5, accuracy: Low
        $x_10_5 = {53 e8 23 a6 ff ff 66 3d 01 80 0f 85 72 08 00 00 8b c3 83 c0 f8 3d d6 00 00 00 0f 87 62 08 00 00 8a 80 68 a8 40 00 ff 24 85 3f a9 40 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_EW_2147602136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.EW"
        threat_id = "2147602136"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 89 45 d0 8d 4d a0 ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 68 ?? ?? ?? ?? 66 8b ?? d0 ?? 6a ff 6a 02 ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 68 ?? ?? ?? ?? 8b ?? 08 8b ?? 40 ?? ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8}  //weight: 10, accuracy: Low
        $x_2_2 = ".::Keylogger by Five-Three-Nine::." wide //weight: 2
        $x_2_3 = "C:\\kill.bat" wide //weight: 2
        $x_2_4 = "C:\\daten.dat" wide //weight: 2
        $x_2_5 = "scvhost.exe" wide //weight: 2
        $x_2_6 = "HNetCfg.FwMgr" wide //weight: 2
        $x_1_7 = "taskkill /f /im" wide //weight: 1
        $x_1_8 = "BACKSPACE" wide //weight: 1
        $x_1_9 = "PAGE DOWN" wide //weight: 1
        $x_1_10 = "DRUCK" wide //weight: 1
        $x_1_11 = "ROLLEN" wide //weight: 1
        $x_1_12 = "ENDE" wide //weight: 1
        $x_1_13 = "LocalPolicy" wide //weight: 1
        $x_1_14 = "CurrentProfile" wide //weight: 1
        $x_1_15 = "FirewallEnabled" wide //weight: 1
        $x_1_16 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_FB_2147605801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FB"
        threat_id = "2147605801"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C*\\AC:\\Documents and Settings\\45rt\\Desktop\\1\\Project1.vbp" wide //weight: 1
        $x_1_2 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" wide //weight: 1
        $x_1_3 = "L$_RasDefaultCredentials#0" wide //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "CIEPasswords" ascii //weight: 1
        $x_1_6 = "RASEntriesNT" ascii //weight: 1
        $x_1_7 = "IsNTAdmin" ascii //weight: 1
        $x_1_8 = "RunPro" wide //weight: 1
        $x_1_9 = "vb wininet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FD_2147610350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FD"
        threat_id = "2147610350"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c 00 50 6c 61 79 57 6f 72 6b 00}  //weight: 5, accuracy: High
        $x_5_2 = "pskey.dat" ascii //weight: 5
        $x_5_3 = {43 61 70 74 75 72 65 00}  //weight: 5, accuracy: High
        $x_5_4 = "http://%s:%d/%d%s" ascii //weight: 5
        $x_5_5 = "ProcessTrans" ascii //weight: 5
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_8 = "GetKeyboardState" ascii //weight: 1
        $x_1_9 = "capCreateCaptureWindowA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FD_2147610350_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FD"
        threat_id = "2147610350"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PlayWork" ascii //weight: 1
        $x_1_2 = "Self Delete Successfully!" ascii //weight: 1
        $x_1_3 = "\"%s\" /c del \"%s\"" ascii //weight: 1
        $x_1_4 = "\\wuauclt.exe" ascii //weight: 1
        $x_1_5 = {50 6f 6c 69 63 69 65 73 5c 43 6f 6d 64 6c 67 33 32 00 4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b 00 00 4e 6f 43 6c 6f 73 65 00 4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 00 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 00 00 52 65 73 74 72 69 63 74 52 75 6e 00 4e 6f 44 72 69 76 65 73 00 00 00 00 4e 6f 52 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_B_2147620341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.B"
        threat_id = "2147620341"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32//sysmnger.exe" ascii //weight: 1
        $x_1_2 = {78 73 65 74 75 70 73 30 31 2e 62 63 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "[Enter]" ascii //weight: 1
        $x_1_5 = "%.2d/%.2d/%4d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_AR_2147628595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.AR"
        threat_id = "2147628595"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{F1}" ascii //weight: 1
        $x_1_2 = "{DOWN}" ascii //weight: 1
        $x_1_3 = "{RIGHT}" ascii //weight: 1
        $x_1_4 = "{LEFT}" ascii //weight: 1
        $x_1_5 = "{UP}" ascii //weight: 1
        $x_1_6 = "{CAPS}" ascii //weight: 1
        $x_1_7 = "{ESC}" ascii //weight: 1
        $x_1_8 = "{TAB}" ascii //weight: 1
        $x_5_9 = {c6 45 e4 47 c6 45 e5 65 88 5d e6 c6 45 e7 4b c6 45 e8 65 c6 45 e9 79 c6 45 ea 53 88 5d eb c6 45 ec 61 88 5d ed c6 45 ee 65 c6 45 ef 00}  //weight: 5, accuracy: High
        $x_5_10 = {c6 45 c0 47 c6 45 c1 65 88 5d c2 c6 45 c3 41 c6 45 c4 73 c6 45 c5 79 c6 45 c6 6e c6 45 c7 63 c6 45 c8 4b c6 45 c9 65 c6 45 ca 79 c6 45 cb 53 88 5d cc c6 45 cd 61 88 5d ce c6 45 cf 65 c6 45 d0 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_O_2147631242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.O"
        threat_id = "2147631242"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 66 66 66 66 a1 ?? ?? ?? ?? 50 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 5c 6a 08 0f b7 c6 50 6a 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "route delete 0.0.0.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_AD_2147632898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.AD"
        threat_id = "2147632898"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 85 e0 fe ff ff 50 e8 ?? ?? ?? ?? 8d 8d dc fe ff ff b2 02 b0 15 e8 ?? ?? ?? ?? 0f b6 46 08 88 45 eb 0f b7 46 0c c1 e8 08 88 45 ea 8d 8d d8 fe ff ff b2 01 b0 20 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 eb}  //weight: 10, accuracy: High
        $x_1_3 = {6e 74 2e 64 6c 6c 00 74 65 74 74}  //weight: 1, accuracy: High
        $x_1_4 = "[Baslat]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_AW_2147647344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.AW"
        threat_id = "2147647344"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://oppitronic.net/hidden/poc/logch.php" ascii //weight: 3
        $x_1_2 = "Haha, I'm still there" ascii //weight: 1
        $x_1_3 = "keystroke spy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_AZ_2147648310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.AZ"
        threat_id = "2147648310"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-9] 2e 65 78 65 [0-9] 25 32 30 00 47 45 54 20 2f 6c 6f 61 64 64 64 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = "keylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_AZ_2147648310_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.AZ"
        threat_id = "2147648310"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".uaneskeylogger.pl" ascii //weight: 10
        $x_2_2 = {2f 75 70 64 2e 70 68 70 3f 64 61 74 61 3d 00 26 73 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_3 = {2f 6c 6f 61 64 64 64 2e 70 68 70 3f 64 61 74 61 3d 00 26 73 69 64 3d 00}  //weight: 2, accuracy: High
        $x_1_4 = {26 70 61 67 65 00 26 6c 6f 67 69 6e 70 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 52 75 6e 00 63 73 72 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 52 75 6e 00 63 72 73 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 52 75 6e 00 63 73 72 72 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_BA_2147648323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BA"
        threat_id = "2147648323"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 64 61 74 61 5c 61 70 70 64 61 74 61 2e 64 6c 6c [0-9] 5c 64 61 74 61 5c 61 70 70 64 61 74 61 2e 64 61 74 [0-9] 5c 6b 65 79 6c 6f 67 67 65 72 2e 64 6c 6c [0-9] 5c 53 45 52 56 49 43 45 53 2e 45 58 45 [0-9] 6f 70 74 69 6f 6e [0-9] 50 72 6f 74 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FP_2147652578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FP"
        threat_id = "2147652578"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Date:%u/%u/%u %u:%u" ascii //weight: 1
        $x_1_2 = "-Clipboard->" ascii //weight: 1
        $x_1_3 = {5d 00 00 6d 73 69 6e 69 74 00 00 53 4f 46 54 57 41 52 45 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FQ_2147653464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FQ"
        threat_id = "2147653464"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {18 00 00 00 8a ?? ?? 0c 8a 1c ?? 32 ?? 88 1c ?? ?? 3b ?? 7c e7 03 00 79 05}  //weight: 2, accuracy: Low
        $x_1_2 = {33 c9 3b fa c6 44 24 04 57 c6 44 24 06 6f}  //weight: 1, accuracy: High
        $x_1_3 = {83 fd 01 75 06 c6 ?? ?? 69 eb 2a 83 fd 02 75 06 c6 ?? ?? 64 eb 1f 83 fd 03 75 06 c6 ?? ?? 72 eb 14}  //weight: 1, accuracy: Low
        $x_1_4 = {03 c6 33 d2 f7 f1 33 c0 8a 82 d8 4d 41 00 33 d2 03 c3 03 d9 f7 74 24 ?? 8b 44 24 ?? 80 c2 ?? 88 54 2e ff 46 3b f7 7e d8 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_BQ_2147653684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BQ"
        threat_id = "2147653684"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 32 32 41 46 43 31 32 45 36 34 34 31 35 32 33 45 34 33 31 46 38 30 31 31 45 31 31 31 30 30 45 30 36 30 36 34 37 44 44 33 46 44 38 33 38 31 43 30 39 31 30 34 36 38 42 43 46 30 32 34 34 39 32 43 35 30 46 42 43 32 37 36 36 41 41 34 31 43 35 34 44 41 37 37 41 42 43 37 34 38 30 39 41 36 42 42 37 37 37 42 34 39 32 37 32 41 38 36 41 00}  //weight: 2, accuracy: High
        $x_2_2 = {37 35 41 39 37 42 38 32 39 32 36 46 42 36 34 45 44 42 35 31 46 34 33 32 46 38 30 35 31 42 46 45 31 46 46 37 31 46 30 46 31 33 30 41 30 30 31 45 46 41 31 39 46 35 36 33 39 34 33 39 39 46 32 37 42 41 31 45 41 41 33 38 41 44 34 31 44 36 32 33 46 36 30 30 33 41 45 42 30 39 31 45 00}  //weight: 2, accuracy: High
        $x_2_3 = {46 41 37 41 41 42 41 38 37 41 38 38 39 42 39 42 36 36 41 36 37 43 46 30 33 46 43 46 32 44 45 36 32 44 33 46 44 33 38 37 38 34 39 33 37 41 41 35 36 35 41 44 39 45 38 46 00}  //weight: 2, accuracy: High
        $x_1_4 = "{PRINT SCREEN}" ascii //weight: 1
        $x_1_5 = "{CTRL+C}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_BS_2147653834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BS"
        threat_id = "2147653834"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 72 6f 6a 61 6e 73 6e 74 6c 64 72 2e 64 6c 6c 00 6b 61 6b 61 6a}  //weight: 1, accuracy: High
        $x_1_2 = "[Delete]" ascii //weight: 1
        $x_1_3 = "[Yapistir]" ascii //weight: 1
        $x_1_4 = "run.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_BT_2147653836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BT"
        threat_id = "2147653836"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KeyLog Service Start..." ascii //weight: 1
        $x_1_2 = {4b 65 79 4c 6f 67 [0-5] 25 73 5c 25 73 [0-7] 6d 72 78 79 6b 65 79 2e 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_3 = "[TAB]" ascii //weight: 1
        $x_1_4 = "%2.2d:%2.2d:%2.2d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FR_2147656214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FR"
        threat_id = "2147656214"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 57 c6 85 ?? (fe|ff) ff ff 54 c6 85 ?? (fe|ff) ff ff 53 c6 85 ?? (fe|ff) ff ff 47}  //weight: 1, accuracy: Low
        $x_1_2 = {4a 79 05 ba 18 00 00 00 8a 44 ?? ?? 8a 1c 31 32 d8 88 1c 31 41 3b cf 7c e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FR_2147656214_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FR"
        threat_id = "2147656214"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe e8 03 00 00 7d 17 e8 ?? ?? ?? ?? 99 b9 e8 03 00 00 f7 f9 46 89 14 b5 ?? ?? ?? ?? eb e1}  //weight: 1, accuracy: Low
        $x_1_2 = {89 06 83 c6 04 81 fe ?? ?? ?? ?? 7c ee be}  //weight: 1, accuracy: Low
        $x_1_3 = {4a 79 05 ba 18 00 00 00 8a 44 ?? ?? 8a 1c 31 32 d8 88 1c 31 41 3b cf 7c e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_BW_2147658721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BW"
        threat_id = "2147658721"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4b 65 79 62 6f 61 72 64 43 61 6c 6c 62 61 63 6b 00}  //weight: 5, accuracy: High
        $x_5_2 = {55 6e 68 4b 65 79 62 6f 61 72 64 00}  //weight: 5, accuracy: High
        $x_5_3 = "[/CTRL]" wide //weight: 5
        $x_5_4 = "[/ALT]" wide //weight: 5
        $x_5_5 = "[/SHFT]" wide //weight: 5
        $x_1_6 = "mainfrm" wide //weight: 1
        $x_1_7 = "\\newtmp\\" wide //weight: 1
        $x_1_8 = "&%#@?,:*" wide //weight: 1
        $x_1_9 = "_uninsep.bat" wide //weight: 1
        $x_1_10 = "if exist \"{executable}\" goto Repeat" wide //weight: 1
        $x_1_11 = "\\Start Menu\\Programs\\Startup\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_FW_2147658724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FW"
        threat_id = "2147658724"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRINT-SCREEN}" ascii //weight: 1
        $x_1_2 = {c6 45 d7 67 c6 45 d8 50 c6 45 d9 72 c6 45 da 69 c6 45 db 76 c6 45 dc 2e 88 5d dd c6 45 de 78}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 a6 63 c6 45 a7 75 c6 45 a8 72 c6 45 a9 69 c6 45 aa 74 c6 45 ab 79 c6 45 ad 54}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 c4 44 c6 45 c5 69 c6 45 c6 73 88 5d c7 c6 45 c8 62 88 55 ca c6 45 cb 54 c6 45 cc 68}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 0c 75 c6 44 24 0f 72 c6 44 24 10 33 c6 44 24 11 32 c6 44 24 12 2e c6 44 24 13 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Keylogger_BX_2147659326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BX"
        threat_id = "2147659326"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.html" ascii //weight: 1
        $x_1_2 = "svvhost.exe" wide //weight: 1
        $x_1_3 = "Log Of KeyLogger" wide //weight: 1
        $x_1_4 = "[ Anti Virus Target Shoma" wide //weight: 1
        $x_1_5 = "Select * from FirewallProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Keylogger_BY_2147661334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.BY"
        threat_id = "2147661334"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Enter]" wide //weight: 1
        $x_1_2 = "[BackSpace]" wide //weight: 1
        $x_1_3 = "[Home]" wide //weight: 1
        $x_10_4 = "GetAsyncKeyState" ascii //weight: 10
        $x_10_5 = "===============" wide //weight: 10
        $x_10_6 = "---------------" wide //weight: 10
        $x_100_7 = {ff d3 50 68 ?? ?? 40 00 ff 15 ?? 10 40 00 8b d0 8d 4d ?? ff d3 50 68 ?? ?? 40 00 ff 15 ?? 10 40 00 8b d0 8d 4d ?? ff d3}  //weight: 100, accuracy: Low
        $x_100_8 = "Amin Hadihi" ascii //weight: 100
        $x_100_9 = "Tcheckwintxt" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_CB_2147664496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CB"
        threat_id = "2147664496"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SaLiLoG keylogger server" ascii //weight: 1
        $x_1_2 = "\\Cradex Server\\" wide //weight: 1
        $x_1_3 = {2f 00 76 00 65 00 72 00 69 00 2f 00 73 00 65 00 6e 00 64 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "| All The Stored Passwords & Comradex.co" wide //weight: 1
        $x_1_5 = "Cradex Stealer ! - [" wide //weight: 1
        $x_1_6 = "Bilgisayar Adi : [" wide //weight: 1
        $x_1_7 = "Keylogging Kaydedilme Zaman" wide //weight: 1
        $x_1_8 = {5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00 22 00 00 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FX_2147678743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FX"
        threat_id = "2147678743"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "netsh advfirewall set currentprofile state off" ascii //weight: 1
        $x_1_3 = {3c 63 74 72 6c 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 4e 44 4d 20 4e 4f 54 20 43 52 45 41 54 45 44 00}  //weight: 1, accuracy: High
        $x_1_5 = {83 ec 04 66 3d 01 80 0f 85 df 03 00 00 66 83 bd b2 fd ff ff 26 7e 48 66 83 bd b2 fd ff ff 40 7f 3e 0f bf 85 b2 fd ff ff 89 44 24 08 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 b8 fe ff ff 89 04 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_FY_2147678772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FY"
        threat_id = "2147678772"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/islem/loqer.php" wide //weight: 10
        $x_5_2 = "mavi> [PageDown] </span>" wide //weight: 5
        $x_1_3 = "\\SysService.exe" wide //weight: 1
        $x_1_4 = "\\winlogon.exe" wide //weight: 1
        $x_1_5 = "\\svchosts.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_FZ_2147678917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.FZ"
        threat_id = "2147678917"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 44 00 4f 00 2e 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Keylogger" ascii //weight: 1
        $x_1_3 = "\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_4 = "Coder By Rikku" wide //weight: 1
        $x_1_5 = {00 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_CC_2147679353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CC"
        threat_id = "2147679353"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 69 6e 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 65 6c 6f 20 6d 65 2e 73 6f 6d 65 70 61 6c 61 63 65 2e 63 6f 6d 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 fc 00 00 00 00 8b 45 08 89 04 24 e8 ?? ?? 00 00 3b 45 fc 76 1e 8b 45 08 8b 4d fc 01 c1 8b 45 08 8b 55 fc 01 c2 8b 45 0c 02 02 88 01 8d 45 fc ff 00 eb d2}  //weight: 1, accuracy: Low
        $x_1_4 = {ff ff 08 00 66 81 bd ?? ?? ff ff de 00 0f 8f 11 04 00 00 0f bf 85 ?? ?? ff ff 89 04 24 a1 10 50 40 00 ff d0 83 ec 04 66 3d 01 80 0f 85 df 03 00 00 66 83 bd ?? ?? ff ff 26 7e 48 66 83 bd ?? ?? ff ff 40 7f 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_CH_2147687557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CH"
        threat_id = "2147687557"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Firewall 4" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "keylogger" ascii //weight: 1
        $x_1_4 = "logs=update=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_CI_2147689649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CI"
        threat_id = "2147689649"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uKeyLogger" ascii //weight: 1
        $x_1_2 = "fuSandBox" ascii //weight: 1
        $x_1_3 = "uPersistence" ascii //weight: 1
        $x_1_4 = "[*CLIPBOARD*]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_CN_2147696773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CN"
        threat_id = "2147696773"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 76 63 2e 63 6e 66 00 2f 25 73 2f 25 73 00 00 54 45 4d 50 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 65 78 65 20 72 75 6e 00}  //weight: 1, accuracy: High
        $x_10_3 = {25 73 5c 4b 45 59 5f 25 64 5f 25 30 2e 32 64 5f 25 30 2e 32 64 2e 4b 6c 67 00}  //weight: 10, accuracy: High
        $x_10_4 = {25 73 5c 53 43 52 5f 25 64 5f 25 30 2e 32 64 5f 25 30 2e 32 64 5f 25 30 2e 32 64 25 30 2e 32 64 25 30 2e 32 64 2e 53 6c 6d 00}  //weight: 10, accuracy: High
        $x_10_5 = {25 73 5c 57 41 56 5f 25 64 25 30 2e 32 64 25 30 2e 32 64 25 30 2e 32 64 25 30 2e 32 64 25 30 2e 32 64 2e 57 6c 6d 00}  //weight: 10, accuracy: High
        $x_10_6 = {25 73 5c 43 41 4d 5f 25 64 5f 25 30 2e 32 64 5f 25 30 2e 32 64 5f 25 30 2e 32 64 25 30 2e 32 64 25 30 2e 32 64 2e 43 6c 6d 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Keylogger_CQ_2147706726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CQ"
        threat_id = "2147706726"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\1B4BAB0F-4544-4c13-90E9-622E2EE1411B" wide //weight: 1
        $x_1_2 = "\\iismgr.dat" wide //weight: 1
        $x_1_3 = {5b 57 69 6e 64 6f 77 73 5d [0-8] 5b 4e 75 6d 62 65 72 20 4c 6f 63 6b 5d [0-8] 5b 53 63 72 65 65 6e 20 4c 6f 63 6b 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {4b 65 79 4c 6f 67 2e 64 6c 6c 00 4f 70 65 72 61 74 65 52 6f 75 74 69 6e 65 57 00 53 74 61 72 74 52 6f 75 74 69 6e 65 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_CR_2147707110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.CR"
        threat_id = "2147707110"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f7 08 0f be 45 f7 89 04 24 e8}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 08 07 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 4f 47 2e 74 78 74 00 61 2b 00 5b 42 41 43 4b 53 50 41 43 45 5d 00 5b 54 41 42 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_HA_2147720187_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.HA!dha"
        threat_id = "2147720187"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[!]Clipboard paste" wide //weight: 1
        $x_1_2 = "[*]Window PID > %d: " wide //weight: 1
        $x_1_3 = "Install hooks ok!" wide //weight: 1
        $x_1_4 = "whatever" ascii //weight: 1
        $x_1_5 = "%ls%d.~tmp" wide //weight: 1
        $x_1_6 = "KeyboardState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_HC_2147733015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.HC!bit"
        threat_id = "2147733015"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 6b 00 6f 00 6e 00 61 00 77 00 61 00 72 00 6b 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 5b 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "GetKeyState" ascii //weight: 1
        $x_1_4 = "GetForegroundWindow" ascii //weight: 1
        $x_1_5 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_HE_2147733020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.HE!bit"
        threat_id = "2147733020"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OurMouseProc" ascii //weight: 1
        $x_1_2 = "OurKeyboardProc" ascii //weight: 1
        $x_1_3 = "[Left Ctrl][V][/Left Ctrl]" ascii //weight: 1
        $x_1_4 = "[Rmouse]  [/Rmouse] [Lmouse]  [/Lmouse]" ascii //weight: 1
        $x_1_5 = {00 73 6d 2e 70 73 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_HZ_2147733150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.HZ!bit"
        threat_id = "2147733150"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EWeqwdqwdd1d12" wide //weight: 1
        $x_1_2 = "/log.php" wide //weight: 1
        $x_1_3 = "><Process:" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_DA_2147739904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.DA!bit"
        threat_id = "2147739904"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send_keylog_stream_data" ascii //weight: 1
        $x_1_2 = "send_shell_exec" ascii //weight: 1
        $x_1_3 = "WebMonitor Client" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_SS_2147772804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.SS!MTB"
        threat_id = "2147772804"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uparkx" wide //weight: 1
        $x_1_2 = "S  u  r  e" wide //weight: 1
        $x_1_3 = "saverbro" wide //weight: 1
        $x_1_4 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_5 = "oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl" wide //weight: 1
        $x_1_6 = "cmd.exe /c timeout.exe /T 11 & Del" wide //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "Logger" ascii //weight: 1
        $x_1_9 = "mufuckr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Keylogger_RT_2147809235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.RT!MTB"
        threat_id = "2147809235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AASEaHR0cDovL25ld2xvc2hyZWUueHl6L3dvcmsva2VubnkzLnBocA==YTYD" ascii //weight: 1
        $x_1_2 = "aHR0cDovL3RlcmViaW5uYWhpY2MuY2x1Yi9zZWMva29vbC50eHQ=" ascii //weight: 1
        $x_1_3 = "PADwqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwe[XXXXXXX]" ascii //weight: 1
        $x_1_4 = "oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Keylogger_ARA_2147899135_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keylogger.ARA!MTB"
        threat_id = "2147899135"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":\\TEMP\\KeyLog.txt" ascii //weight: 2
        $x_2_2 = "\\MmNew.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

