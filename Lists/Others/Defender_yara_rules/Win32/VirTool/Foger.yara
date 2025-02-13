rule VirTool_Win32_Foger_A_2147602261_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Foger.gen!A"
        threat_id = "2147602261"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Foger"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 4b 4c 4e 4d 45 4d 4c 2c 47 5a 47 [0-21] 45 58 50 4c 4f 52 45 52 2e 45 58 45 [0-21] 49 45 58 50 4c 4f 52 45 2e 45 58 45 [0-32] 6b 6a 32 33 61 77 61 72 78 79 64 6e 33 34 73 2e 74 6d 70 [0-16] 54 4f 54 41 4c 43 4d 44 2e 45 58 45}  //weight: 3, accuracy: Low
        $x_3_2 = "kj23awarxydn34s.tmp" ascii //weight: 3
        $x_3_3 = "fuwarxyus.dll" ascii //weight: 3
        $x_3_4 = "DLLName\"=\"\\\\\\\\fuwarxyus.dll" ascii //weight: 3
        $x_1_5 = "Logon\"=\"WinlogonLogonEvent" ascii //weight: 1
        $x_1_6 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\crypt32set]" ascii //weight: 1
        $x_1_7 = "Logoff\"=\"WinlogonLogoffEvent" ascii //weight: 1
        $x_1_8 = "ScreenSaver\"=\"WinlogonScreenSaverEvent" ascii //weight: 1
        $x_1_9 = "Startup\"=\"WinlogonStartupEvent" ascii //weight: 1
        $x_1_10 = "Shutdown\"=\"WinlogonShutdownEvent" ascii //weight: 1
        $x_1_11 = "StartShell\"=\"WinlogonStartShellEvent" ascii //weight: 1
        $x_1_12 = "Impersonate\"=dword:00000000" ascii //weight: 1
        $x_1_13 = "Asynchronous\"=dword:00000001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

