rule MonitoringTool_Win32_PerfectKeylogger_9644_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SetWindowsHookExA" ascii //weight: 3
        $x_3_2 = "EnableSpecialKeysLogging" ascii //weight: 3
        $x_3_3 = "EnableNTInvisible" ascii //weight: 3
        $x_1_4 = {77 62 2e 64 6c 6c 00 00 68 6b 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {74 69 74 6c 65 73 2e 64 61 74 00 61 70 70 73 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_6 = {00 70 6b 2e 62 69 6e 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Setup=rinst.exe" ascii //weight: 10
        $x_10_2 = {61 70 70 73 2e 64 61 74 00 00 00 00 70 6b 2e 62 69 6e}  //weight: 10, accuracy: High
        $x_10_3 = "Perfect Keylogger" ascii //weight: 10
        $x_10_4 = "%APPDATA%\\BPK\\" ascii //weight: 10
        $x_10_5 = {77 65 62 2e 64 61 74 00 62 70 6b 63 68 2e 64 61 74}  //weight: 10, accuracy: High
        $x_1_6 = "vw.exe" ascii //weight: 1
        $x_1_7 = "wb.dll" ascii //weight: 1
        $x_1_8 = "hk.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "bpk.chm" ascii //weight: 3
        $x_3_2 = "bpk.dat" ascii //weight: 3
        $x_3_3 = "rinst.exe" ascii //weight: 3
        $x_3_4 = "BPK Main Window" ascii //weight: 3
        $x_2_5 = "PKL Window" ascii //weight: 2
        $x_2_6 = "pk.bin" ascii //weight: 2
        $x_2_7 = "http://www.blazingtools.com" ascii //weight: 2
        $x_3_8 = "bsdhooks.dll" ascii //weight: 3
        $x_3_9 = "Perfect Keylogger" ascii //weight: 3
        $x_3_10 = "Program Files\\BPK" ascii //weight: 3
        $x_1_11 = "PC and Internet surveillance" ascii //weight: 1
        $x_1_12 = "Software\\Blazing Tools" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {77 62 2e 64 6c 6c 00 00 68 6b 2e 64 6c 6c 00 00 72 2e 65 78 65 00 00 00 2e 65 78 65 00 00 00 00 6b 77 2e 64 61 74 00 00 69 6e 73 74 2e 64 61 74 00 00 00 00 6d 63 2e 64 61 74 00 00 74 69 74 6c 65 73 2e 64 61 74 00 00 61 70 70 73 2e 64 61 74 00 00 00 00 70 6b 2e 62 69 6e 00 00}  //weight: 4, accuracy: High
        $x_4_2 = {00 62 70 6b 2e 64 61 74 00 77 65 62 2e 64 61 74 00 62 70 6b 63 68 2e 64 61 74 00 00}  //weight: 4, accuracy: High
        $x_2_3 = {4c 6f 67 20 75 70 6c 6f 61 64 20 64 61 74 65 3a 20 25 73 0d 0a 54 69 6d 65 3a 20 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 20 25 73 0d 0a 49 50 20 61 64 64 72 65 73 73 3a 20 25 73 0d 0a 55 73 65 72 3a 20 25 73 0d}  //weight: 2, accuracy: High
        $x_2_4 = "BPK IE File Uploader Class" ascii //weight: 2
        $x_2_5 = "PKL Window" ascii //weight: 2
        $x_1_6 = "Show entire log" ascii //weight: 1
        $x_1_7 = "keystrokes.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "IsDebuggerPresent" ascii //weight: 10
        $x_10_2 = "FIXCLOCK" ascii //weight: 10
        $x_2_3 = "Perfect Keylogger " wide //weight: 2
        $x_2_4 = {62 00 6c 00 61 00 7a 00 69 00 6e 00 67 00 74 00 6f 00 6f 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = "Perfect Keylogger!" wide //weight: 2
        $x_1_6 = "screen capture (screenshot)" wide //weight: 1
        $x_1_7 = "clear log" wide //weight: 1
        $x_1_8 = "&Stealth" wide //weight: 1
        $x_1_9 = "keylogger's startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/i_bpk_trial.exe" ascii //weight: 1
        $x_1_2 = "connected to Internet" ascii //weight: 1
        $x_1_3 = "Downloading Perfect Keylogger." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_6
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 72 69 6e 73 74 2e 65 78 65 00}  //weight: 3, accuracy: High
        $x_3_2 = {00 62 70 6b 2e 64 61 74 00}  //weight: 3, accuracy: High
        $x_2_3 = {00 70 6b 2e 62 69 6e 00}  //weight: 2, accuracy: High
        $x_2_4 = "PKL Window" ascii //weight: 2
        $x_2_5 = "blazingtools" ascii //weight: 2
        $x_1_6 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_7 = {00 68 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 77 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PerfectKeylogger_9644_7
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PerfectKeylogger"
        threat_id = "9644"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PerfectKeylogger"
        severity = "48"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 70 00 6b 00 2e 00 64 00 61 00 74 00 00 00 77 00 65 00 62 00 2e 00 64 00 61 00 74 00 00 00 62 00 70 00 6b 00 63 00 68 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {6b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 00 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 00 00 63 00 68 00 61 00 74 00 73 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "4) Click \"Show entire log\"" wide //weight: 1
        $x_1_4 = "Log upload date: %s" wide //weight: 1
        $x_1_5 = "BPK_32_64" wide //weight: 1
        $x_1_6 = {25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 00 00 2f 00 00 00 5c 00 00 00 2f 00 00 00 2f 00 00 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

