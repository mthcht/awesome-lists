rule MonitoringTool_Win32_RefogKeylogger_205589_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "KGB Keylogger" wide //weight: 1
        $x_1_3 = "Advanced key logger" wide //weight: 1
        $x_1_4 = "MAIL FROM: " ascii //weight: 1
        $x_1_5 = "RCPT TO:" ascii //weight: 1
        $x_1_6 = "GetKeyboardType" ascii //weight: 1
        $x_1_7 = "OpenClipboard" ascii //weight: 1
        $x_1_8 = "CloseClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_RefogKeylogger_205589_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 70 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 4d 5f 4b 45 59 48 4f 4f 4b 5f 4b 47 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 04 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 83 c4 18 b8 01 00 00 00 c2 04 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 56 50 6a 04 ff d7 8b 4c 24 14 6a 00 56 99}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_RefogKeylogger_205589_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "www.refog.com/files/ie5.zip" wide //weight: 4
        $x_2_2 = "All Chats with this Contact" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_RefogKeylogger_205589_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4d 70 6b 2e 64 6c 6c 00 46 [0-2] 46 [0-2] 46}  //weight: 2, accuracy: Low
        $x_2_2 = {4d 70 6b 69 2e 64 6c 6c 00 46 [0-2] 46 [0-2] 46}  //weight: 2, accuracy: Low
        $x_2_3 = "MPK64" ascii //weight: 2
        $x_2_4 = "S:(ML;;NW;;;LW)" wide //weight: 2
        $x_1_5 = "WM_KEYHOOK" ascii //weight: 1
        $x_1_6 = "WM_MOUSEHOOK" ascii //weight: 1
        $x_1_7 = "WM_CREATEHOOK" ascii //weight: 1
        $x_1_8 = "WM_SHOWHOOK" ascii //weight: 1
        $x_1_9 = "WM_MOUSEMOVEHOOK" ascii //weight: 1
        $x_1_10 = "WM_PROGRUNHOOK" ascii //weight: 1
        $x_1_11 = "WM_PROGSTOPHOOK" ascii //weight: 1
        $x_1_12 = "WM_GETWNDDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_RefogKeylogger_205589_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.refog.com/unins" ascii //weight: 1
        $x_1_2 = {6d 70 6b 76 69 65 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "REFOG Monitor is a multifunctional keyboard" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Refog Software" ascii //weight: 1
        $x_1_5 = "{commonappdata}\\MPK" ascii //weight: 1
        $x_1_6 = "Please use Employee Monitor or Terminal Monitor version." ascii //weight: 1
        $x_1_7 = "KGB Spy Home.lnk" ascii //weight: 1
        $x_1_8 = "REFOG Keylogger.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_Win32_RefogKeylogger_205589_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://www.refog.com" ascii //weight: 5
        $x_1_2 = {4d 50 4b 41 44 4d 49 4e 50 53 57 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 50 4b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 50 4b 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 50 4b 56 69 65 77 2e 65 78 65 5f 4d 41 49 4e 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 75 6e 72 65 66 6f 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 6b 65 79 6c 6f 67 67 65 72 2f 75 70 67 72 61 64 65 5f 74 6f 5f 73 70 79 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {2f 66 69 6c 65 73 2f 6b 65 79 73 70 65 63 74 70 72 6f 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = "/updates/integrity/" ascii //weight: 1
        $x_1_10 = {52 45 46 4f 47 20 46 72 65 65 20 4b 65 79 6c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_11 = "MpkNetInstall.exe - application installer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_RefogKeylogger_205589_6
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "REFOG Keylogger Setup" wide //weight: 1
        $x_1_2 = "This installation was built with Inno Setup." wide //weight: 1
        $x_1_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 52 00 45 00 46 00 4f 00 47 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 ?? ?? ?? ?? 52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_RefogKeylogger_205589_7
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z:\\Projects\\ReleaseRepository\\MonitorProject\\Delphi" wide //weight: 1
        $x_1_2 = "MPK.dll" wide //weight: 1
        $x_1_3 = "MPK64.dll" wide //weight: 1
        $x_1_4 = "MPKView.exe" wide //weight: 1
        $x_1_5 = "runrefog" wide //weight: 1
        $x_1_6 = "www.refog.com" wide //weight: 1
        $x_1_7 = {52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "keylogger_update_from_program" wide //weight: 1
        $x_1_9 = "logs@vista-keylogger.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule MonitoringTool_Win32_RefogKeylogger_205589_8
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RefogKeylogger"
        threat_id = "205589"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefogKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 4d 00 20 00 43 00 68 00 61 00 74 00 20 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 4d 00 65 00 73 00 73 00 61 00 6e 00 67 00 65 00 72 00 53 00 70 00 79 00 2e 00 70 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 50 00 4b 00 41 00 44 00 4d 00 49 00 4e 00 50 00 53 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "refog.com/?utm_source=" wide //weight: 1
        $x_1_6 = "personal-monitor/upgrade.html?utm_source=" wide //weight: 1
        $x_1_7 = "keylogger/faq.html?utm_source=" wide //weight: 1
        $x_1_8 = {44 00 6f 00 6e 00 27 00 74 00 20 00 67 00 6f 00 21 00 20 00 47 00 65 00 74 00 20 00 52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 46 00 52 00 45 00 45 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {72 00 75 00 6e 00 72 00 65 00 66 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 00 53 00 70 00 79 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 46 00 6f 00 72 00 6d 00 2e 00 70 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {4d 00 55 00 54 00 45 00 58 00 5f 00 50 00 52 00 4f 00 47 00 52 00 41 00 4d 00 5f 00 52 00 55 00 4e 00 4e 00 49 00 4e 00 47 00 3a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

