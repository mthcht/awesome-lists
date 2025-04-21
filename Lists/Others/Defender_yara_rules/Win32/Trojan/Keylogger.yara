rule Trojan_Win32_Keylogger_PA_2147741467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PA!MTB"
        threat_id = "2147741467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The Keylogger has been installed" ascii //weight: 1
        $x_1_2 = "%ProgramFiles%\\TMonitor\\" ascii //weight: 1
        $x_1_3 = "www.MyKeyloggerOnline.com" ascii //weight: 1
        $x_1_4 = "Windows Task Monitor.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_PB_2147745185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PB!MTB"
        threat_id = "2147745185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "EmailSendingKeylogger.exe" wide //weight: 20
        $x_20_2 = "Keyloggerka Daste Peykrd La" wide //weight: 20
        $x_20_3 = "KeyLogger Started at" wide //weight: 20
        $x_20_4 = "Keylogger Has Ben Start At" wide //weight: 20
        $x_20_5 = "Keyloggerka Has Ben Start At" wide //weight: 20
        $x_20_6 = "Keylogger/Keylogger.exe" wide //weight: 20
        $x_20_7 = "ArtisteKeylogger by bakhcha" wide //weight: 20
        $x_5_8 = "smtp.gmail.com" wide //weight: 5
        $x_5_9 = "smtp.office365.com" wide //weight: 5
        $x_1_10 = "set_keyTimer" ascii //weight: 1
        $x_1_11 = "set_emailTimer" ascii //weight: 1
        $x_1_12 = "NetworkCredential" ascii //weight: 1
        $x_1_13 = "get_Keyboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Keylogger_PC_2147748588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PC!MTB"
        threat_id = "2147748588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shock_Labs_Keylogger_v1._0" ascii //weight: 1
        $x_1_2 = "\\log.txt" wide //weight: 1
        $x_1_3 = "Keylogger Log for" wide //weight: 1
        $x_1_4 = "smtp.gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AB_2147749273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AB!MTB"
        threat_id = "2147749273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\SysFile\\appdat.ini" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\system32\\cmd.exe /c java.exe -jar C:\\SysFile\\mail.jar" ascii //weight: 1
        $x_1_3 = {5b 4e 55 4d 50 41 44 5f 53 45 50 41 52 41 54 4f 52 5d [0-16] 5b 43 41 50 53 5d [0-16] 5b 45 4e 44 5d [0-16] 5b 48 4f 4d 45 5d [0-16] 5b 49 4e 53 45 52 54 5d [0-16] 5b 44 45 4c 45 54 45 5d}  //weight: 1, accuracy: Low
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_PD_2147749282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PD!MTB"
        threat_id = "2147749282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smtp.gmail.com" wide //weight: 1
        $x_1_2 = "KEYLOG BOIZZ" wide //weight: 1
        $x_1_3 = "C:/ProgramData/mylog.txt" wide //weight: 1
        $x_1_4 = "FinalKeyLogger" ascii //weight: 1
        $x_1_5 = "MailAddressCollection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_PE_2147752192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PE!MTB"
        threat_id = "2147752192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Keylogger" ascii //weight: 10
        $x_5_2 = "donkeyballs" wide //weight: 5
        $x_1_3 = "smtp.gmail.com" wide //weight: 1
        $x_1_4 = "MailAddressCollection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_PF_2147752361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PF!MTB"
        threat_id = "2147752361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\windows\\klogs.txt" wide //weight: 1
        $x_1_2 = "Log Sent by Keylogger" wide //weight: 1
        $x_1_3 = "newKeylogs" wide //weight: 1
        $x_1_4 = "smtp.gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_SA_2147788514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.SA"
        threat_id = "2147788514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C5.Client.KL.pdb" ascii //weight: 5
        $x_5_2 = "get_AdminId" ascii //weight: 5
        $x_5_3 = "set_VictimId" ascii //weight: 5
        $x_5_4 = "set_CommandId" ascii //weight: 5
        $x_5_5 = "[RightArrow]" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Keylogger_RPN_2147796929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.RPN!MTB"
        threat_id = "2147796929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 45 f6 89 04 24 e8 ?? ?? ?? ?? 83 ec 04 66 3d 01 80 0f 94 c0 84 c0 74 3d c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 e8 0f b7 45 f6 89 44 24 08 c7 44 24 04 ?? ?? ?? ?? 8b 45 e8 89 04 24 e8 ?? ?? ?? ?? 8b 45 e8 89 04 24 e8 ?? ?? ?? ?? 66 ff 45 f4 66 ff 45 f6 66 83 7d f4 31 0f 96 c0 84 c0 75 95 c7 04 24 01 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_RPO_2147797356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.RPO!MTB"
        threat_id = "2147797356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 83 c1 01 89 4d fc 8b 55 f8 2b 55 f4 39 55 fc 73 1b 8b 4d f4 8b 7d 0c 8b 75 08 03 75 fc 33 c0 f3 a6 75 07 b8 01 00 00 00 eb 04 eb d1}  //weight: 1, accuracy: High
        $x_1_2 = "svchost.exe" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_RPA_2147809256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.RPA!MTB"
        threat_id = "2147809256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m.pipedream.net" ascii //weight: 1
        $x_1_2 = "Startup" ascii //weight: 1
        $x_1_3 = "keys.txt" ascii //weight: 1
        $x_1_4 = "keylogger" ascii //weight: 1
        $x_1_5 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AN_2147818876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AN!MTB"
        threat_id = "2147818876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Log Submitted!" wide //weight: 1
        $x_1_2 = "log.txt" wide //weight: 1
        $x_1_3 = "uparkx" wide //weight: 1
        $x_1_4 = "No print jobs!" wide //weight: 1
        $x_1_5 = "c.exe" wide //weight: 1
        $x_1_6 = "ch.exe" wide //weight: 1
        $x_1_7 = "cunbhai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AO_2147818896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AO!MTB"
        threat_id = "2147818896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Log Submitted!" wide //weight: 1
        $x_1_2 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_3 = "uparkx" wide //weight: 1
        $x_1_4 = "oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl" wide //weight: 1
        $x_1_5 = "c.exe" wide //weight: 1
        $x_1_6 = "ch.exe" wide //weight: 1
        $x_1_7 = "cunbhai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AP_2147826268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AP!MTB"
        threat_id = "2147826268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S  u  r  e" wide //weight: 1
        $x_1_2 = "saverbro" wide //weight: 1
        $x_1_3 = "Are  You   Sure   You   Want To  Re-set Timer???" wide //weight: 1
        $x_1_4 = "achibat321X" wide //weight: 1
        $x_1_5 = "[Passwords]" wide //weight: 1
        $x_1_6 = "killerman" ascii //weight: 1
        $x_1_7 = "cunbhai" ascii //weight: 1
        $x_1_8 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_9 = "Log Submitted!" wide //weight: 1
        $x_1_10 = "WantToCle Log?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AQ_2147828685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AQ!MTB"
        threat_id = "2147828685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S  u  r  e" wide //weight: 1
        $x_1_2 = "saverbro" wide //weight: 1
        $x_1_3 = "Are  You   Sure   You   Want To  Re-set Timer???" wide //weight: 1
        $x_1_4 = "achibat123" wide //weight: 1
        $x_1_5 = "[Passwords]" wide //weight: 1
        $x_1_6 = "werewrwwwwww" wide //weight: 1
        $x_1_7 = "c.exe" wide //weight: 1
        $x_5_8 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 5
        $x_1_9 = "Log Submitted!" wide //weight: 1
        $x_1_10 = "WantToCle Log?" wide //weight: 1
        $x_1_11 = "[ ALTDOWN ]" wide //weight: 1
        $x_1_12 = "namebro" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_BD_2147841157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.BD!MTB"
        threat_id = "2147841157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendUserName: Couldn't get the user name !!" ascii //weight: 1
        $x_1_2 = "C:\\Users\\%s\\AppData\\Local\\WinUpdate.exe" ascii //weight: 1
        $x_1_3 = "C:\\Users\\%s\\%d-%d-%d.bmp" ascii //weight: 1
        $x_1_4 = "C:\\Users\\%s\\AppData\\Local\\payload.ps1" ascii //weight: 1
        $x_1_5 = "keyLoggerMain" ascii //weight: 1
        $x_1_6 = "[BACKSPACE]" ascii //weight: 1
        $x_1_7 = "[ESCAPE]" ascii //weight: 1
        $x_1_8 = "Data written in the file successfully" ascii //weight: 1
        $x_1_9 = "writeLogs: Could not create the file for keylog ouput !!" ascii //weight: 1
        $x_1_10 = "C:\\Users\\%s\\AppData\\Local\\.windows_defender.conf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_MA_2147842170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.MA!MTB"
        threat_id = "2147842170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 8b 41 00 34 8b 41 00 3c 8b 41 00 44 8b 41 00 50 8b 41 00 58 8b 41 00 64 8b 41 00 30 8b 41}  //weight: 5, accuracy: High
        $x_2_2 = "keylogger\\source\\Debug\\keylogger.pdb" ascii //weight: 2
        $x_2_3 = "[NPDEL]" ascii //weight: 2
        $x_2_4 = "[CRSEL]" ascii //weight: 2
        $x_2_5 = "[PROCESSKEY]" ascii //weight: 2
        $x_2_6 = "[BROWSER_FAVORITES]" ascii //weight: 2
        $x_2_7 = "[KANJI]" ascii //weight: 2
        $x_1_8 = "SetWindowsHookExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_MA_2147842170_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.MA!MTB"
        threat_id = "2147842170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "FUNC _ISPRESSED ( $HEXKEY )" ascii //weight: 2
        $x_2_2 = "GetAsyncKeyState" ascii //weight: 2
        $x_2_3 = "$DATE = @YEAR & @MON & @MDAY" ascii //weight: 2
        $x_2_4 = "$LOG = @WINDOWSDIR" ascii //weight: 2
        $x_2_5 = "Administrator\\Desktop\\svchost.exe" ascii //weight: 2
        $x_2_6 = "\\system\\svchost.exe" ascii //weight: 2
        $x_2_7 = "FUNC _LOGKEYPRESS" ascii //weight: 2
        $x_2_8 = "SLEEP" ascii //weight: 2
        $x_2_9 = "REGDELETE" ascii //weight: 2
        $x_2_10 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_11 = {49 00 46 00 20 00 5f 00 49 00 53 00 50 00 52 00 45 00 53 00 53 00 45 00 44 00 20 00 28 00 20 00 [0-5] 20 00 29 00 20 00 3d 00 20 00 31 00 20 00 54 00 48 00 45 00 4e 00 20 00 5f 00 4c 00 4f 00 47 00 4b 00 45 00 59 00 50 00 52 00 45 00 53 00 53 00}  //weight: 2, accuracy: Low
        $x_2_12 = {49 46 20 5f 49 53 50 52 45 53 53 45 44 20 28 20 [0-5] 20 29 20 3d 20 31 20 54 48 45 4e 20 5f 4c 4f 47 4b 45 59 50 52 45 53 53}  //weight: 2, accuracy: Low
        $x_2_13 = "{CAPSLOCK}" ascii //weight: 2
        $x_2_14 = "{RIGHT ARROW}" ascii //weight: 2
        $x_2_15 = "{DOWN ARROW}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule Trojan_Win32_Keylogger_DAL_2147849897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.DAL!MTB"
        threat_id = "2147849897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 02 84 dc 87 43 44 d1 11 89 06 00 a0 c9 11 00 49 67 0d 26 db 8c b9 05 4e 83 9c 6e df 77 1d 5b 0e 21 3d [0-4] 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73}  //weight: 2, accuracy: Low
        $x_2_2 = {35 3c ff 1c 6a 05 f4 00 1c 16 05 fc c8 f4 00 1c 1d 05 fc c8 f4 00 1c 24 05 fc c8 f4 00 1c 2b 05 fc c8 f5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_DL_2147851789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.DL!MTB"
        threat_id = "2147851789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 60 fe 69 00 fb ef 38 ff 60 31 b0 fe 36 06 00 68 ff 48 ff 38 ff 00 77}  //weight: 1, accuracy: High
        $x_1_2 = {28 ff 04 08 ff 0a 25 00 14 00 04 08 ff ff 36 08 20 59 04 ff 04 34 ff ff 02 32 06 00 2c ff 28 ff 00 ff 29 04 00 78}  //weight: 1, accuracy: High
        $x_1_3 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_4 = "[Passwords]" wide //weight: 1
        $x_1_5 = "Log Submitted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_DO_2147853246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.DO!MTB"
        threat_id = "2147853246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c6 03 d9 50 8d 14 33 52 53 e8 b1 57 f5 ff 8b 5d 08 83 c4 0c 2b de 8b cd 57 53 e8 16 e2 f2 ff 84 c0 74 08 53 8b cd e8 e4 43 f4 ff 8b cd e8 88 e2 f2 ff 5f 8b c5 5e 5d 5b 59 c2 04 00 3b df 76 4c 3b d8 75}  //weight: 2, accuracy: High
        $x_2_2 = {73 36 6a 01 8b cd e8 8b e2 f2 ff 8b 46 04 3b c7 75 05 b8 30 19 50 00 89 45 04 8b 4e 08 89 4d 08 8b 56 0c 89 55 0c 8a 48 ff fe c1 5f 88 48 ff 8b c5 5e 5d 5b 59 c2 04 00 6a 01 53 8b cd e8 9f e1 f2 ff 84 c0 74 29}  //weight: 2, accuracy: High
        $x_1_3 = "?dispatchMap@CHtmlSkinDlg@@1UAFX_DISPMAP@@B" ascii //weight: 1
        $x_1_4 = "?dispatchMap@CSmallDownloadManagerDlg@@1UAFX_DISPMAP@@B" ascii //weight: 1
        $x_1_5 = "?messageMap@CSmallDownloadManagerApp@@1UAFX_MSGMAP@@B" ascii //weight: 1
        $x_1_6 = "_uninsdm.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AMBE_2147899964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AMBE!MTB"
        threat_id = "2147899964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 5
        $x_5_2 = "Keylogger is up and running." ascii //weight: 5
        $x_1_3 = "SetClipboardData" ascii //weight: 1
        $x_1_4 = "OpenClipboard" ascii //weight: 1
        $x_1_5 = "GetKeyNameTextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_AMBE_2147899964_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AMBE!MTB"
        threat_id = "2147899964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL3RlcmViaW5uYWhpY2MuY2x1Yi9zZWMva29vbC50eHQ" ascii //weight: 1
        $x_1_2 = "oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsv" wide //weight: 1
        $x_1_3 = "(1|3)[1-9A-HJ-NP-Za-km-z]{26,34}$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_ARA_2147906067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.ARA!MTB"
        threat_id = "2147906067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 c2 41 88 54 ?? ?? ?? 3b ?? 7c e8}  //weight: 2, accuracy: Low
        $x_3_2 = {8a 44 14 14 30 ?? ?? ?? ?? ?? ?? 3b ?? 7c e9}  //weight: 3, accuracy: Low
        $x_3_3 = {8a 44 14 10 30 ?? ?? ?? ?? ?? ?? 3b ?? 7c e9}  //weight: 3, accuracy: Low
        $x_2_4 = "/c2/data" ascii //weight: 2
        $x_2_5 = "GetAsyncKeyState" ascii //weight: 2
        $x_2_6 = "vmware.exe" ascii //weight: 2
        $x_2_7 = "HttpSendRequestA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Keylogger_AMAK_2147920547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.AMAK!MTB"
        threat_id = "2147920547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {46 6c 61 73 68 42 75 66 00 47 65 74 44 75 6d 70 65 72 44 4c 4c 4e 61 6d 65 00 47 65 74 44 75 6d 70 65 72 44 4c 4c 56 65 72 73 69 6f 6e 00 49 6e 73 74 61 6c 6c 44 75 6d 70 65 72 44 4c 4c 00 4c 61 73 74 4b 65 79 53 74 72 00 50 61 75 73 65 4c 6f 67 00 55 6e 69 6e 73 74 61 6c 6c 44 75 6d 70 65 72 44 4c 4c}  //weight: 3, accuracy: High
        $x_1_2 = "DumperDLLMutex" ascii //weight: 1
        $x_1_3 = "GetComputerName Failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Keylogger_PGL_2147939520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keylogger.PGL!MTB"
        threat_id = "2147939520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sysproc.exe" wide //weight: 1
        $x_2_2 = "8088595201:AAGqn7XzBsY0t9vBDe9hKuSdcv2DVFotiCg" ascii //weight: 2
        $x_2_3 = "/sendMessage?chat_id=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

