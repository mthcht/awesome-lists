rule TrojanClicker_Win32_Delf_AT_2147598655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.AT"
        threat_id = "2147598655"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Internet Explorer_TridentDlgFrame" ascii //weight: 10
        $x_10_3 = "WebBrowser1StatusTextChange" ascii //weight: 10
        $x_10_4 = "TWebBrowserOnMenuBar" ascii //weight: 10
        $x_10_5 = "TProcessUrlActionEvent" ascii //weight: 10
        $x_10_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_7 = "User Agent\\Post Platform" ascii //weight: 10
        $x_10_8 = "htmlfile\\shell\\open\\ddeexec\\application" ascii //weight: 10
        $x_10_9 = "Honbeforeunload" ascii //weight: 10
        $x_30_10 = "http://2005-search.com/go/go.php" wide //weight: 30
        $x_10_11 = "WebBrowser1.LocationURL" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Delf_BA_2147600380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.BA"
        threat_id = "2147600380"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {84 c0 75 1d 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ff 50 8b 45 ?? e8 ?? ?? ?? ff 50 6a 00 e8 ?? ?? ?? ff 8d 45 ?? ba ?? ?? ?? 00 e8 ?? ?? ?? ff [0-13] 8d 85 ?? ff ff ff 8d 95 ?? ff ff ff b9 81 00 00 00 e8 ?? ?? ?? ff 8b 95 ?? ff ff ff 8d 45 ?? b9 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 ?? e8 ?? ?? ?? ff 84 c0}  //weight: 10, accuracy: Low
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_3 = "\\taskmor.exe" ascii //weight: 1
        $x_1_4 = "http://www.wzdq.cn/sf" ascii //weight: 1
        $x_1_5 = "\\winlogin.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Delf_BC_2147600631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.BC"
        threat_id = "2147600631"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 8d 45 f8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8 58 e8 ?? ?? ?? ff 0f 84 91 00 00 00 8d 45 f4 e8 ?? ?? ?? ff 8d 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 84 c0 75 70 e8 ?? ?? ?? ff 6a 00 8d 45 f0 e8 ?? ?? ?? ff 8d 45 f0 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f0 e8 ?? ?? ?? ff 50 8d 55 ec 33 c0 e8 ?? ?? ?? ff 8b 45 ec e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff 6a 00 6a 00 68 ?? ?? ?? 00 8d 45 e8 e8 ?? ?? ?? ff 8d 45 e8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 e8 e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "ServiceAfterInstall" ascii //weight: 1
        $x_1_4 = "popup.php?" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Delf_K_2147609709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.K"
        threat_id = "2147609709"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 3a 5c 6d 69 63 72 6f 73 6f 66 74 5c 00 00 00 [0-5] 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_3_3 = "2005-search.com/go.php" ascii //weight: 3
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Honbeforeunload" ascii //weight: 1
        $x_1_6 = "Timer: Starting to click...." ascii //weight: 1
        $x_1_7 = "Folder\\shell\\explore\\ddeexec" ascii //weight: 1
        $x_1_8 = {00 00 57 69 6e 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_9 = "explorerbar" wide //weight: 1
        $x_1_10 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Delf_P_2147613103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.P"
        threat_id = "2147613103"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 07 00 00 00 73 76 77 2e 65 78 65 00 ff ff ff ff 2e 00 00 00 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 ff ff ff ff 04 00 00 00 6e 65 74 77 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "WebBrowser1DocumentComplete" ascii //weight: 1
        $x_1_3 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_4 = "Sxema1 Klikat ne budem! Uze est " ascii //weight: 1
        $x_1_5 = "klikaem na treidera" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Delf_R_2147618122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.gen!R"
        threat_id = "2147618122"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "search.com/new.php" ascii //weight: 10
        $x_10_3 = "http://blacktraff.com/track.php?" ascii //weight: 10
        $x_10_4 = {68 00 61 00 72 00 64 00 70 00 6f 00 72 00 6e 00 6d 00 70 00 67 00 00 00}  //weight: 10, accuracy: High
        $x_1_5 = {70 6c 61 79 65 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = "WebBrowser1BeforeNavigate2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Delf_AV_2147630057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.AV"
        threat_id = "2147630057"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.whatismyip.com/automation/n09230945.asp" ascii //weight: 1
        $x_1_2 = "http://l2top.ru/vote/%d/" ascii //weight: 1
        $x_1_3 = {b8 31 00 00 00 e8 ?? ?? ?? ?? ff 34 85 ?? ?? ?? ?? b8 0b 00 00 00 e8 ?? ?? ?? ?? ff 34 85 ?? ?? ?? ?? b8 38 00 00 00 e8 ?? ?? ?? ?? ff 34 85 ?? ?? ?? ?? 8b c3 ba 03 00 00 00 e8 ?? ?? ?? ?? 5b c3}  //weight: 1, accuracy: Low
        $x_1_4 = {73 65 63 5f 72 65 66 65 72 65 72 3d [0-4] ff ff ff ff 09 00 00 00 76 6f 74 65 4f 6b 3d 6f 6b [0-32] 6e 61 6d 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Delf_S_2147635790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.S"
        threat_id = "2147635790"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@=\"Internet Exploer\"" ascii //weight: 1
        $x_2_2 = "ButtonMyCmputerToSYS32" ascii //weight: 2
        $x_2_3 = "@=\"[SYS32DIR]odexl.exe\"" ascii //weight: 2
        $x_2_4 = "@@@Thunder IE Update@@@" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Delf_MB_2147637358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.MB"
        threat_id = "2147637358"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://ginsdirect.net/1/tds6.php" wide //weight: 3
        $x_2_2 = "0 clicks, be lucky next time" ascii //weight: 2
        $x_2_3 = "begin %d clicks" ascii //weight: 2
        $x_1_4 = "window.confirm=function(){};window." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Delf_U_2147654168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.U"
        threat_id = "2147654168"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.ilikeclick." ascii //weight: 1
        $x_1_2 = "http://click.clickstory." ascii //weight: 1
        $x_1_3 = {64 ff 30 64 89 20 8b 55 08 b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 85 c0 0f 84 2d 01 00 00 8b 55 08 b8 4c 03 4a 00 e8 ?? ?? ?? ?? 85 c0 0f 84 8e 00 00 00 8b 55 08 b8 4c 03 4a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanClicker_Win32_Delf_W_2147656323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.W"
        threat_id = "2147656323"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://1.234.27.146/popup.do" ascii //weight: 1
        $x_1_2 = "cmd=redirect_list" ascii //weight: 1
        $x_1_3 = "cmd=redirect_log&url=" ascii //weight: 1
        $x_1_4 = "cmd=keywordLog&keyword=" ascii //weight: 1
        $x_1_5 = "cmd=popupLog&keyword=" ascii //weight: 1
        $x_1_6 = "cmd=getSite&keyword=" ascii //weight: 1
        $x_1_7 = "WINDOWS/system32/pog.log" ascii //weight: 1
        $x_1_8 = "WINDOWS/system32/cffmom.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Delf_AR_2147711783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Delf.AR!bit"
        threat_id = "2147711783"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 68 65 6c 6c 5c 41 73 73 6f 63 69 61 74 69 6f 6e 73 5c 55 72 6c 41 73 73 6f 63 69 61 74 69 6f 6e 73 5c 68 74 74 70 5c 55 73 65 72 43 68 6f 69 63 65 00 50 72 6f 67 69 64 00}  //weight: 10, accuracy: High
        $x_1_2 = {74 00 61 00 73 00 6b 00 62 00 61 00 72 00 75 00 6e 00 70 00 69 00 6e 00 00 00 00 00 73 00 74 00 61 00 72 00 74 00 75 00 6e 00 70 00 69 00 6e 00 00 00 00 00 74 00 61 00 73 00 6b 00 62 00 61 00 72 00 70 00 69 00 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 00 45 00 54 00 00 00 50 00 4f 00 53 00 54 00 00 00 00 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00 72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 68 00 61 00 6f 00 31 00 32 00 33 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 00 70 00 65 00 6e 00 6c 00 6e 00 6b 00 00 00 00 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 6f 00 6e 00 67 00 6a 00 69 00 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

