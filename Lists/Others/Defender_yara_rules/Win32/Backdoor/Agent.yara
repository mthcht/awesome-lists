rule Backdoor_Win32_Agent_2147789785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent"
        threat_id = "2147789785"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "check.223344556677.com" ascii //weight: 1
        $x_1_2 = "o5nwy1giptdm-log.sdajk46546.com" ascii //weight: 1
        $x_1_3 = "wireshark.exe" ascii //weight: 1
        $x_1_4 = "www.systweak.com" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_8 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_2147789785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent"
        threat_id = "2147789785"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BotMainDll.dll" ascii //weight: 1
        $x_1_2 = "fxsst.dll" ascii //weight: 1
        $x_1_3 = "System\\CurrentControlSet\\Services\\%s\\Security" ascii //weight: 1
        $x_1_4 = "Registry\\Machine\\System\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "GetSystemWindowsDirectoryA" ascii //weight: 1
        $x_1_7 = "FindNextFileA" ascii //weight: 1
        $x_1_8 = "OpenSCManagerA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_2147789785_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent"
        threat_id = "2147789785"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Shell0]" ascii //weight: 1
        $x_1_2 = "[Shell2]11111!!!" ascii //weight: 1
        $x_1_3 = "iEw48Ew38Ew" ascii //weight: 1
        $x_1_4 = "[Shell2]22222!!!" ascii //weight: 1
        $x_1_5 = "[Shell0]33333!!!" ascii //weight: 1
        $x_1_6 = "[Shell2]33333!!!" ascii //weight: 1
        $x_1_7 = "BF380" wide //weight: 1
        $x_1_8 = "[Shell0]PE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_2147789785_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent"
        threat_id = "2147789785"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://votnews.com/ecode/exit.php" ascii //weight: 5
        $x_5_2 = "http://votnews.com/listnew3.txt" ascii //weight: 5
        $x_5_3 = "A security error of unknown cause has been detected which has" ascii //weight: 5
        $x_5_4 = "kavsvc" ascii //weight: 5
        $x_5_5 = "Symantec Core LC" ascii //weight: 5
        $x_5_6 = "update_UpdateLocalSharedFiles some error" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_RL_2147790241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.RL"
        threat_id = "2147790241"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_2 = "systemup.exe" ascii //weight: 1
        $x_1_3 = "system16.exe" ascii //weight: 1
        $x_1_4 = "vbfile.exe u" ascii //weight: 1
        $x_1_5 = "iojik.ru/botzupd.html" ascii //weight: 1
        $x_1_6 = "iojik.ru/in.php?ver=3.0a0005" ascii //weight: 1
        $x_1_7 = "iojik.ru/botzcfg.php?ver=3.0a0005" ascii //weight: 1
        $x_1_8 = "SetHook_" ascii //weight: 1
        $x_1_9 = "WriteFile" ascii //weight: 1
        $x_1_10 = "RegSetValueExA" ascii //weight: 1
        $x_1_11 = "LIBHIDE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CAA_2147790280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAA"
        threat_id = "2147790280"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "/alexa_count.asp?url=" ascii //weight: 10
        $x_10_2 = "http://alexa.verynx.cn" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Alexa Internet" ascii //weight: 10
        $x_10_4 = "\\Msf3sf.sys" ascii //weight: 10
        $x_10_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 45 58 45}  //weight: 10, accuracy: Low
        $x_10_6 = "(C) Microsoft Corporation. All rights reserved." wide //weight: 10
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GI_2147790289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GI"
        threat_id = "2147790289"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\\\Group.wab" ascii //weight: 1
        $x_1_2 = {8a 07 fe c8 88 04 32 42 4f 3b d1 7c f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CAA_2147792069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAA"
        threat_id = "2147792069"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 69 6e 67 20 2d 6e 20 [0-4] 20 31 32 37 2e 30 2e 30 2e 31 20 3e 20 6e 75 6c}  //weight: 10, accuracy: Low
        $x_10_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 45 58 45}  //weight: 10, accuracy: Low
        $x_10_3 = "C:\\WINDOWS\\SYSTEM32\\delme.bat" ascii //weight: 10
        $x_10_4 = "C:\\WINDOWS\\SYSTEM32\\ggkb.bat" ascii //weight: 10
        $x_10_5 = "(C) Microsoft Corporation. All rights reserved." wide //weight: 10
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_FD_2147792117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.FD"
        threat_id = "2147792117"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{D17A40D7-AF4E-034A-C131-4C12C86133E2}" ascii //weight: 10
        $x_10_2 = "software\\microsoft\\direct3d" ascii //weight: 10
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_4 = "%s\\drivers" ascii //weight: 10
        $x_10_5 = "%s\\svchost.exe" ascii //weight: 10
        $x_1_6 = "OutpostFirewall" ascii //weight: 1
        $x_1_7 = "Anti-Hacker" ascii //weight: 1
        $x_1_8 = "Antivirus Service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_FH_2147792120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.FH"
        threat_id = "2147792120"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Outpost Firewall" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "netsh firewall set allowedprogram" ascii //weight: 10
        $x_1_4 = "botnet" ascii //weight: 1
        $x_1_5 = "p2p_worm" ascii //weight: 1
        $x_1_6 = "spoolcool" ascii //weight: 1
        $x_1_7 = "botModules" ascii //weight: 1
        $x_1_8 = "BackDoor.SnowCrash" ascii //weight: 1
        $x_1_9 = "Norton Av crack.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_ACA_2147792152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ACA"
        threat_id = "2147792152"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "DllFunctionCall" ascii //weight: 10
        $x_10_3 = "\\Documents and Settings\\Koshi\\Desktop\\backdoor\\gangsta.vbp" wide //weight: 10
        $x_10_4 = "I will love you forever Rima. Everything forever." wide //weight: 10
        $x_1_5 = "gangsta" ascii //weight: 1
        $x_1_6 = "modRandomz" ascii //weight: 1
        $x_1_7 = "clsInfect" ascii //weight: 1
        $x_1_8 = "clsNetInfo" ascii //weight: 1
        $x_1_9 = "Connected" ascii //weight: 1
        $x_1_10 = "WSAStartup" ascii //weight: 1
        $x_1_11 = "RemoteHostIP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_HA_2147792332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.HA"
        threat_id = "2147792332"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {33 c0 85 f6 7e 08 30 04 38 40 3b c6 7c f8 80 24 37 00 8b c7}  //weight: 30, accuracy: High
        $x_10_2 = "sBot" ascii //weight: 10
        $x_10_3 = "bot killer" ascii //weight: 10
        $x_10_4 = "bot killer thread" ascii //weight: 10
        $x_10_5 = "Uninstalling bot..." ascii //weight: 10
        $x_10_6 = "Error terminating botkiller" ascii //weight: 10
        $x_10_7 = "Spybot" ascii //weight: 10
        $x_10_8 = "LOGIN Logged user %s into bot" ascii //weight: 10
        $x_10_9 = "echo open %s > o&echo user %s %s >> o &echo send" ascii //weight: 10
        $x_2_10 = "Morpheus.exe" ascii //weight: 2
        $x_2_11 = "hidserv.exe" ascii //weight: 2
        $x_1_12 = "msnmsgr.exe" ascii //weight: 1
        $x_1_13 = "msnupdate.exe" ascii //weight: 1
        $x_2_14 = "SERVICES.EXE" ascii //weight: 2
        $x_2_15 = "explorer.exe" ascii //weight: 2
        $x_1_16 = "WinExec" ascii //weight: 1
        $x_1_17 = "ReadProcessMemory" ascii //weight: 1
        $x_1_18 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_19 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_20 = "Wisdom" ascii //weight: 1
        $x_2_21 = "titfuck" ascii //weight: 2
        $x_2_22 = "&echo bye" ascii //weight: 2
        $x_2_23 = "cyber@crime.gov" ascii //weight: 2
        $x_1_24 = "Windows Updater Services" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_2_*))) or
            ((5 of ($x_10_*))) or
            ((1 of ($x_30_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_30_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_30_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_30_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_30_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_ACF_2147792333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ACF"
        threat_id = "2147792333"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "238"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "svchost.exe" ascii //weight: 100
        $x_100_2 = "!ddos" ascii //weight: 100
        $x_10_3 = "explorer.exe" ascii //weight: 10
        $x_10_4 = "Auto HotKey Poller" ascii //weight: 10
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_6 = "ZONEALARM.EXE" ascii //weight: 1
        $x_1_7 = "ZAUINST.EXE" ascii //weight: 1
        $x_1_8 = "ZATUTOR.EXE" ascii //weight: 1
        $x_1_9 = "WRCTRL.EXE" ascii //weight: 1
        $x_1_10 = "SeEnableDelegationPrivilege" ascii //weight: 1
        $x_1_11 = "SeRemoteShutdownPrivilege" ascii //weight: 1
        $x_1_12 = "SeAuditPrivilege" ascii //weight: 1
        $x_1_13 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_14 = "SeSystemtimePrivilege" ascii //weight: 1
        $x_1_15 = "InternetGetConnectedState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_LV_2147792338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.LV"
        threat_id = "2147792338"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[This is PWD]      " ascii //weight: 1
        $x_1_2 = {5b 48 4f 53 54 20 20 20 20 20 20 20 3a 5d 20 25 73 0d 0a 5b 50 4f 52 54 20 20 20 20 20 20 20 3a 5d 20 25 73 0d 0a 5b 50 41 53 53 20 20 20 20 20 20 20 3a 5d 20 25 73}  //weight: 1, accuracy: High
        $x_1_3 = "Move '%s' To '%s' Successfully" ascii //weight: 1
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CAB_2147792340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAB"
        threat_id = "2147792340"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 51 8b 45 08 83 c0 04 50 8b 4d 08 ff 11 89 45 fc 8b 45 fc 8b e5 5d c2 04 00}  //weight: 10, accuracy: High
        $x_5_2 = {00 64 74 72 2e 64 6c 6c}  //weight: 5, accuracy: High
        $x_5_3 = {00 68 6f 6f 6b 2e 64 6c 6c}  //weight: 5, accuracy: High
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $n_100_7 = "\\CSCheat\\Driver" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_RJ_2147792351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.RJ"
        threat_id = "2147792351"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FPUMaskValue" ascii //weight: 10
        $x_5_3 = {eb 5f 5e 5b 59 59 5d c3 ff ff ff ff 14 00 00 00 53 6f 66 74 77 61 72 65 5c 59 61 68 6f 6f 5c 70 61 67 65 72 00 00 00 00 ff ff ff ff 03 00 00 00 45 54 53 00 ff ff ff ff 0e 00 00 00 59 61 68 6f 6f 21 20 55 73 65 72 20 49 44 00 00 ff ff ff ff 0f 00 00 00 59 61 68 6f 6f b1 62 b8 b9 a1 47 0d 0a 0d 0a 00 ff ff ff ff 02 00 00 00 0d 0a 00 00 ff ff ff ff 19 00 00 00 a5 5b b1 4b b9 4c aa ba b1 4b bd 58 28 45 54 53 20 76 61 6c 75 65 29 a1}  //weight: 5, accuracy: High
        $x_5_4 = {ff ff ff ff 0b 00 00 00 59 61 68 6f 6f b1 62 b8 b9 21 21 00 ff ff ff ff 0d 00 00 00}  //weight: 5, accuracy: High
        $x_10_5 = {55 8b ec 6a 00 6a 00 53 56 57 8b d8 33 c0 55 68 ea 78 46 00 64 ff 30 64 89 20 a1 fc 9b 46 00 8b 00 c6 40 5b 00 b2 01 a1 d4 72 42 00 e8 bb fc fb ff a3 dc af 46 00 ba 01 00 00 80 a1 dc af 46 00 e8 47 fd fb ff 33 c9 ba 00 79 46 00 a1 dc af 46 00 e8 9a fd fb ff 84 c0 0f 84 b9 01 00 00 8d 4d fc ba 20 79 46 00 a1 dc af 46 00 e8 1c ff fb ff 8b 55 fc b8 d4 af 46 00 e8 3f c8 f9 ff 8d 4d f8 ba}  //weight: 10, accuracy: High
        $x_10_6 = {f9 ff 8d 4d f8 ba 2c 79 46 00 a1 dc af 46 00 e8 fd fe fb ff 8b 55 f8 b8 d8 af 46 00 e8 20 c8 f9 ff a1 dc af 46 00 e8 b6 fc fb ff 68 44 79 46 00 ff 35 d8 af 46 00 68 5c 79 46 00 68 5c 79 46 00 68 68 79 46 00 68 5c 79 46 00 68 5c 79 46 00 ff 35 d4 af 46 00 b8 e0 af 46 00 ba 08 00 00 00 e8 09 cb f9 ff 8b 83 f8 02 00 00 8b 15 e0 af 46 00 e8 48 8b fc ff 33 c0 55 68 04 78 46 00 64 ff 30 64}  //weight: 10, accuracy: High
        $x_10_7 = {46 00 64 ff 30 64 89 20 8b 83 fc 02 00 00 b2 01 e8 35 fc ff ff 8b 83 fc 02 00 00 ba 8c 79 46 00 8b 08 ff 91 88 00 00 00 8b 83 fc 02 00 00 ba 19 00 00 00 8b 08 ff 91 8c 00 00 00 8b 83 fc 02 00 00 83 ca ff 8b 08 ff 91 94 00 00 00 33 c0 5a 59 59 64 89 10 eb 14}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_ADF_2147792354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ADF"
        threat_id = "2147792354"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "StartProcessAtStartup" ascii //weight: 5
        $x_5_2 = "StartProcessAtWinLogon" ascii //weight: 5
        $x_5_3 = "StopProcessAtWinLogoff" ascii //weight: 5
        $x_5_4 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_5 = "Process32Next" ascii //weight: 5
        $x_5_6 = "CreateRemoteThread" ascii //weight: 5
        $x_5_7 = "WriteProcessMemory" ascii //weight: 5
        $x_5_8 = "VirtualAllocEx" ascii //weight: 5
        $x_1_9 = "xuhuankilllove" ascii //weight: 1
        $x_1_10 = "System\\wab32db.dll" ascii //weight: 1
        $x_1_11 = "BeiZhu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_CF_2147792355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CF"
        threat_id = "2147792355"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\115.16.79.72\\abcd$" ascii //weight: 1
        $x_1_2 = "%s\\termfile.txt" ascii //weight: 1
        $x_1_3 = "%s\\disable.txt" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "1.bat" ascii //weight: 1
        $x_1_6 = "2.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CK_2147792356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CK"
        threat_id = "2147792356"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\NTboot.exe" ascii //weight: 1
        $x_1_2 = "DarkShell\\Release\\DarkShell.pdb" ascii //weight: 1
        $x_1_3 = "program files\\Internet Explorer\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_4 = "DarkShell.dll" ascii //weight: 1
        $x_1_5 = "DownCtrlAltDel" ascii //weight: 1
        $x_1_6 = "DarkShell_Event_StartWait" wide //weight: 1
        $x_1_7 = "DarkShell_Event_StopWait" wide //weight: 1
        $x_1_8 = "Internet Explorer_Server" wide //weight: 1
        $x_1_9 = "cmd.exe /c \"%s\" \"%s\"" wide //weight: 1
        $x_1_10 = "Start_Wait_%s" wide //weight: 1
        $x_1_11 = "StopWait_%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_YZ_2147792364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.YZ"
        threat_id = "2147792364"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avp.exe" wide //weight: 1
        $x_1_2 = "setup.exe" wide //weight: 1
        $x_1_3 = "/p2p/" wide //weight: 1
        $x_1_4 = "OK Closed accepted socket: " wide //weight: 1
        $x_1_5 = "*\\AC:\\Documents and Settings\\Fakundo\\Mis documentos\\Eye Crypter V4\\Stub\\Project1.vbp" wide //weight: 1
        $x_1_6 = "OK Destroyed accept collection" wide //weight: 1
        $x_1_7 = "CSocketMaster.Connect" wide //weight: 1
        $x_1_8 = "open=setup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_FT_2147792365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.FT"
        threat_id = "2147792365"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "276"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {53 65 72 76 69 63 65 44 6c 6c 00 00 5c 00 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 5c 50 61 72 61 6d 65 74 65 72 73 00 73 65 72 76 65 72 2e 64 6c 6c 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 00 00 00 00 69 72 6d 6f 6e 00 00 00 6e 65 74 73 76 63 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72}  //weight: 100, accuracy: High
        $x_100_2 = {72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 00 00 00 00 20 3e 4e 55 4c 00 00 00 20 2f 63 20 64 65 6c 20 00 00 00 00 43 4f 4d 53 50 45 43 00 5c 75 73 65 72 33 32 2e 64 6c 6c 00 66 69 6c 65 00 00 00 00 70 6c 78 70 63 69 00 00 5c 64 72 69 76 65 72 73 5c 70 6c 78 70 63 69 2e 73 79 73 00 5c 53 79 73 74 65 6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 44 52 49 56 45 52 53 5c 70 6c 78 70 63 69 2e 73 79 73 00 73 65 72 76 65 72 00 00 64 72 69 76 65 72 00 00 5c 61 73 63 33 35 35 31 2e 73 79 73 00 00 00 00 5c 77 74 69 6d 65 2e 65 78 65 00 00 5c 73 65 72 76 65 72 2e 64 6c 6c 00 5c 70 6c 78 70 63 69 2e 73 79 73 00 7a 6c 63 6c 69 65 6e 74 2e 65 78 65 00 00 00 00 3c 75 6e 6b 6e 6f 77 6e 3e 00 00 00}  //weight: 100, accuracy: High
        $x_5_3 = "\\wtime.exe" ascii //weight: 5
        $x_5_4 = "\\server.dll" ascii //weight: 5
        $x_10_5 = "\\SystemRoot\\system32\\DRIVERS\\plxpci.sys" ascii //weight: 10
        $x_5_6 = "zlclient.exe" ascii //weight: 5
        $x_10_7 = "\\asc3551.sys" ascii //weight: 10
        $x_10_8 = "\\drivers\\plxpci.sys" ascii //weight: 10
        $x_5_9 = "plxpci" ascii //weight: 5
        $x_10_10 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 10
        $x_1_11 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_12 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" ascii //weight: 1
        $x_1_13 = "\\user32.dll" ascii //weight: 1
        $x_1_14 = " /c del " ascii //weight: 1
        $x_2_15 = "GetActiveWindow" ascii //weight: 2
        $x_2_16 = "server.dll" ascii //weight: 2
        $x_2_17 = "ServiceDll" ascii //weight: 2
        $x_2_18 = "SERVER1" wide //weight: 2
        $x_2_19 = "irmon" ascii //weight: 2
        $x_2_20 = "driver" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_KN_2147792366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.KN"
        threat_id = "2147792366"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "Start Download and run task" ascii //weight: 1
        $x_1_3 = "Complete Download and run task" ascii //weight: 1
        $x_1_4 = "Clones\\VISTA\\vista\\release\\Vista.pdb" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_6 = "5E9755A1-314A-4ae6-99E1-B9F7DC7C7CF0" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_8 = "InternetReadFile" ascii //weight: 1
        $x_1_9 = "HttpSendRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_RM_2147792367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.RM"
        threat_id = "2147792367"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 53 55 56 57 50 6a 00 68 2a 04 00 00 ff 15 ?? ?? ?? ?? 8b d8 85 db 75 07 5f 5e 5d 5b c2 08 00 8b 6c 24 18 83 c9 ff 8b fd 33 c0 f2 ae f7 d1 49 6a 04 8b f1 68 00 10 00 00 46 56 50 53 ff 15 ?? ?? ?? ?? 8b f8 85 ff 75 07 5f 5e 5d 5b c2 08 00 6a 00 56 55 57 53 ff 15 ?? ?? ?? ?? 85 c0 75 07 5f 5e 5d 5b c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 62 00 00 6f 70 65 6e 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 20 3e 20 6e 75 6c 00 00 20 2f 63 20 20 64 65 6c 20 00 00 00 43 4f 4d 53 50 45 43 00 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 5c 53 56 43 48 30 53 54 2e 45 58 45 00 00 00 00 44 4c 4c 00 5c 6d 73 76 63 6c 61 70 69 78 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_ADB_2147792368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ADB"
        threat_id = "2147792368"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "113"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32\\SVCH0ST.EXE" ascii //weight: 1
        $x_1_2 = ".htmGET" ascii //weight: 1
        $x_1_3 = ".aspGET" ascii //weight: 1
        $x_1_4 = ".htmlGET" ascii //weight: 1
        $x_1_5 = "Windows Firewall" ascii //weight: 1
        $x_1_6 = "c:\\pagefile.pif" ascii //weight: 1
        $x_1_7 = "Windows98" ascii //weight: 1
        $x_1_8 = "Windows95" ascii //weight: 1
        $x_1_9 = "WindowsNT" ascii //weight: 1
        $x_1_10 = "Windows2000" ascii //weight: 1
        $x_1_11 = "WindowsXP" ascii //weight: 1
        $x_1_12 = "Windows2003" ascii //weight: 1
        $x_1_13 = "fuckweb" ascii //weight: 1
        $x_1_14 = "Referer: http://www.baidu.com" ascii //weight: 1
        $x_100_15 = {33 c0 53 56 57 8d 7c 24 0c f3 ab 8d 44 24 0c 68 00 01 00 00 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c9 ff 33 c0 8d 54 24 0c f2 ae f7 d1 2b f9 68 3f 00 0f 00 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 54 24 10 83 e1 03 50 f3 a4 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 50 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 13 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_ADC_2147792369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ADC"
        threat_id = "2147792369"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "177"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "\\update.bak" ascii //weight: 50
        $x_2_2 = ".htmGET" ascii //weight: 2
        $x_2_3 = ".aspGET" ascii //weight: 2
        $x_2_4 = ".htmlGET" ascii //weight: 2
        $x_2_5 = "c:\\pagefile.pif" ascii //weight: 2
        $x_2_6 = "Windows98" ascii //weight: 2
        $x_2_7 = "Windows95" ascii //weight: 2
        $x_2_8 = "WindowsNT" ascii //weight: 2
        $x_2_9 = "Windows2000" ascii //weight: 2
        $x_2_10 = "WindowsXP" ascii //weight: 2
        $x_2_11 = "Windows2003" ascii //weight: 2
        $x_2_12 = "fuckweb" ascii //weight: 2
        $x_2_13 = "Referer: http://www.baidu.com" ascii //weight: 2
        $x_2_14 = "\\AutoRun.inf" ascii //weight: 2
        $x_1_15 = "\\Device\\PhysicalMemory" wide //weight: 1
        $x_1_16 = "\\system32\\drivers\\svchost.exe" ascii //weight: 1
        $x_100_17 = {33 c0 53 56 57 8d 7c 24 ?? f3 ab 8d 44 24 ?? 68 00 01 00 00 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c9 ff 33 c0 8d ?? ?? ?? f2 ae f7 d1 2b f9 50 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 6a 02 8b cb 6a 02 50 83 e1 03 6a 02 8d ?? ?? ?? 68 00 00 00 40 f3 a4 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 51 8b f0 68 00 20 00 00 68 ?? ?? ?? ?? 56 ff 15}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_CC_2147792395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CC"
        threat_id = "2147792395"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[Num Lock]" ascii //weight: 10
        $x_10_2 = "[Down]" ascii //weight: 10
        $x_10_3 = "[Right]" ascii //weight: 10
        $x_10_4 = "[UP]" ascii //weight: 10
        $x_1_5 = "Check Clone Account" ascii //weight: 1
        $x_1_6 = "XShell BackDoor" ascii //weight: 1
        $x_1_7 = "arpspoof" ascii //weight: 1
        $x_1_8 = "Online KeyLog" ascii //weight: 1
        $x_1_9 = "Clone User As Administrator" ascii //weight: 1
        $x_1_10 = "-sniffpwd" ascii //weight: 1
        $x_1_11 = "reset_spoof_sock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_FP_2147792397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.FP"
        threat_id = "2147792397"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "firewall set allowedprogram" ascii //weight: 1
        $x_1_2 = "\"securesystd\"" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\IEAgent" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\systink" ascii //weight: 1
        $x_1_5 = "privelegeupdates.info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GJ_2147792398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GJ"
        threat_id = "2147792398"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%02hu-%02hu-%hu_%02hu-%02hu-%02hu_%s" ascii //weight: 1
        $x_1_2 = "USB_File_Rat_" ascii //weight: 1
        $x_1_3 = "Registry-Grabbing.reg" ascii //weight: 1
        $x_1_4 = {52 45 4d 4f 56 41 42 4c 45 00 46 49 58 45 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_PB_2147792419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.PB"
        threat_id = "2147792419"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "243"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 61 6d 65 39 39 38 38 2e 63 6e 2f [0-8] 2e 65 78 65}  //weight: 100, accuracy: Low
        $x_10_3 = "cnt.exe" ascii //weight: 10
        $x_10_4 = "ef26ev.dll" ascii //weight: 10
        $x_10_5 = "\\wininit.ini" ascii //weight: 10
        $x_10_6 = "browsewmzero.dll" ascii //weight: 10
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_9 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_PD_2147792421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.PD"
        threat_id = "2147792421"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "432"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "WINLOGON" ascii //weight: 100
        $x_100_2 = "seven-eleven" ascii //weight: 100
        $x_100_3 = "\\TrojanS_P.exe" ascii //weight: 100
        $x_100_4 = "TROJAN VER 1.0 BUILD" ascii //weight: 100
        $x_10_5 = "SeShutdownPrivilege" ascii //weight: 10
        $x_10_6 = "Set cdAudio door open wait" ascii //weight: 10
        $x_10_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "InternetGetConnectedState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_ADU_2147792422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ADU"
        threat_id = "2147792422"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bensorty.dll" ascii //weight: 10
        $x_10_2 = "http://yuoiop.info/rd/rd.php" ascii //weight: 10
        $x_10_3 = "http://nanoatom.info/rd/rd.php" ascii //weight: 10
        $x_10_4 = "{8D5849A2-93F3-429D-FF34-260A2068897C}" ascii //weight: 10
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_ADV_2147792423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ADV"
        threat_id = "2147792423"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "324"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {00 46 5f 53 65 72 76 65 72 2e 65 78 65 00}  //weight: 100, accuracy: High
        $x_100_2 = {00 74 68 75 61 2e 33 33 32 32 2e 6f 72 67 00}  //weight: 100, accuracy: High
        $x_100_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_4 = "TTunnel" ascii //weight: 10
        $x_10_5 = "CaptureWindow" ascii //weight: 10
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_ADX_2147792424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ADX"
        threat_id = "2147792424"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "254"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "-kill %s %s /install" ascii //weight: 100
        $x_100_2 = "return escape(unescape(a.replace(" ascii //weight: 100
        $x_10_3 = "%s\\system\\%s.exe" ascii //weight: 10
        $x_10_4 = "C:\\Program Files\\Common Files\\System\\%s.exe" ascii //weight: 10
        $x_10_5 = "CreateRemoteThread" ascii //weight: 10
        $x_10_6 = "WriteProcessMemory" ascii //weight: 10
        $x_10_7 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_8 = "MyGeekPartnerResults" ascii //weight: 1
        $x_1_9 = "195.8.15.138" ascii //weight: 1
        $x_1_10 = "217.145.76.13" ascii //weight: 1
        $x_1_11 = "porn1." ascii //weight: 1
        $x_1_12 = "virgins." ascii //weight: 1
        $x_1_13 = "hotxxxtv." ascii //weight: 1
        $x_1_14 = "freelove." ascii //weight: 1
        $x_1_15 = "freepornnow." ascii //weight: 1
        $x_1_16 = "freeporntoday." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 5 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_AFA_2147792425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.AFA"
        threat_id = "2147792425"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "del %s /a" ascii //weight: 10
        $x_10_2 = "\\ctfmon.exe" ascii //weight: 10
        $x_10_3 = "\\SERVICES.EXE" ascii //weight: 10
        $x_10_4 = "%ALLUSERSPROFILE%\\Documents\\microtm.bat" ascii //weight: 10
        $x_1_5 = "cmd.exe /c copy %s %s" ascii //weight: 1
        $x_1_6 = "cmd.exe /c copy \\*.*" ascii //weight: 1
        $x_1_7 = "regedit.exe /s /e  %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_AFB_2147792426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.AFB"
        threat_id = "2147792426"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "svchost.exe" wide //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "WScript.Shell" wide //weight: 10
        $x_10_4 = "http://www.gaiya9.cn/mm/config.t" wide //weight: 10
        $x_1_5 = "\\Program Files\\Internet Explorer\\IEXPLORE.EXE" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" wide //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\IEXPLORE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_AFF_2147792427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.AFF"
        threat_id = "2147792427"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "http://201.11.233.30/" wide //weight: 10
        $x_10_4 = "\\loader\\Instal\\Project1.vbp" wide //weight: 10
        $x_1_5 = "diabo.scr" wide //weight: 1
        $x_1_6 = "\\System\\dllram.exe" wide //weight: 1
        $x_1_7 = "\\System\\AVG.clean.cmd" wide //weight: 1
        $x_1_8 = "Arquivo de Imagem JPEG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_DT_2147792429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.DT"
        threat_id = "2147792429"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "131"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0f be 34 1f 83 fe 20 7c 22 83 fe 7e 7f 1d e8 ?? ?? ?? ?? 8d 0c 40 c1 e1 05 8d 44 31 ?? b9 5f 00 00 00 99 f7 f9 80 c2 20 88 14 1f 47 3b fd 7c}  //weight: 100, accuracy: Low
        $x_10_2 = "shutdown -s -t 0 -f" ascii //weight: 10
        $x_10_3 = "Microsoft Corporation" wide //weight: 10
        $x_10_4 = "PsSetLoadImageNotifyRoutine" ascii //weight: 10
        $x_1_5 = "sin.bat" ascii //weight: 1
        $x_1_6 = "del %0" ascii //weight: 1
        $x_1_7 = "del \"%s\" " ascii //weight: 1
        $x_1_8 = "cd  C:\\" ascii //weight: 1
        $x_1_9 = "if exist \"%s\" goto" ascii //weight: 1
        $x_1_10 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_FQ_2147792433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.FQ"
        threat_id = "2147792433"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e8 ff d3 33 d2 f7 f5 83 ee 01 8a 92 ?? ?? ?? ?? 88 14 37 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 57 56 6a 05 e8 ?? ?? 00 00 3d 04 00 00 c0 74 ?? 85 c0 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 74 4b 65 72 6e 65 6c 4f 62 6a 65 63 74 53 65 63 75 72 69 74 79 00 ?? ?? 4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_FW_2147792440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.FW"
        threat_id = "2147792440"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!ddos" ascii //weight: 2
        $x_1_2 = "?nick=" ascii //weight: 1
        $x_3_3 = "SpL_%s_[%s]" ascii //weight: 3
        $x_2_4 = "SbieDll.dll" ascii //weight: 2
        $x_3_5 = "wpaw55&mfg" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_GS_2147792448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GS"
        threat_id = "2147792448"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 33 33 30 00 00 00 00 6d 79 72 61 74 2e 64 79 6e 64 6e 73 2e 6f 72 67}  //weight: 1, accuracy: High
        $x_1_2 = "Global\\server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GT_2147792449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GT"
        threat_id = "2147792449"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 33 33 30 00 00 6d 79 52 41 54}  //weight: 1, accuracy: High
        $x_1_2 = "Windows Update\\update.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GX_2147792450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GX"
        threat_id = "2147792450"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pipe\\_69" ascii //weight: 1
        $x_1_2 = "\\temp.temp" ascii //weight: 1
        $x_1_3 = {41 8a 94 38 ?? ?? 00 10 8a 99 ?? ?? 00 10 32 d3 88 97 ?? ?? 00 10 75 06 88 9f ?? ?? 00 10 47 3b 7d fc 7c ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GY_2147792451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GY"
        threat_id = "2147792451"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Kill You" ascii //weight: 10
        $x_10_2 = "C:\\Shadow.exe" ascii //weight: 10
        $x_1_3 = "cmd.exe /c" ascii //weight: 1
        $x_1_4 = "CreatePipe" ascii //weight: 1
        $x_1_5 = "%s SP%d (Build %d)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CAC_2147792453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAC"
        threat_id = "2147792453"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d f4 30 15 00 00 73 19 8b 4d f4 33 d2 8a 91 88 11 b8 72 83 f2 19 8b 45 f4 88 90 88 11 b8 72 eb d5}  //weight: 1, accuracy: High
        $x_1_2 = {0f 84 36 01 00 00 c6 85 54 fd ff ff 65 c6 85 55 fd ff ff 78 c6 85 56 fd ff ff 70 c6 85 57 fd ff ff 6c c6 85 58 fd ff ff 6f}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 d4 fe ff ff 77 c6 85 d5 fe ff ff 69 c6 85 d6 fe ff ff 6e c6 85 d7 fe ff ff 73 c6 85 d8 fe ff ff 74 c6 85 d9 fe ff ff 61 c6 85 da fe ff ff 30 c6 85 db fe ff ff 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 ac 41 c6 45 ad 64 c6 45 ae 76 c6 45 af 61 c6 45 b0 70 c6 45 b1 69 c6 45 b2 33 c6 45 b3 32 c6 45 b4 2e c6 45 b5 64 c6 45 b6 6c c6 45 b7 6c c6 45 b8 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CAD_2147792454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAD"
        threat_id = "2147792454"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "run file sucess" ascii //weight: 1
        $x_1_2 = "send file sucess" ascii //weight: 1
        $x_1_3 = "cmd killed" ascii //weight: 1
        $x_1_4 = "cmd coming" ascii //weight: 1
        $x_1_5 = "implementationfilddlldlsefwefwef" wide //weight: 1
        $x_1_6 = "mmtask MFC Application" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Agent_CAE_2147792455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAE"
        threat_id = "2147792455"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESK_Server_Dll" ascii //weight: 1
        $x_1_2 = {5f 44 65 6c 65 74 65 2e 64 6c 6c 00 4c 65 73 73}  //weight: 1, accuracy: High
        $x_1_3 = "Reload User Path Config File" ascii //weight: 1
        $x_1_4 = "Mang.xml" ascii //weight: 1
        $x_1_5 = "Timeout & QUIT!!!" ascii //weight: 1
        $x_1_6 = "Unicode Normalization DLL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Agent_CAF_2147792456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAF"
        threat_id = "2147792456"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sys@User : %s@%s (%s)" ascii //weight: 1
        $x_1_2 = "Ping sec : %4dms %4dms %4dms ->  average%4dms" ascii //weight: 1
        $x_1_3 = "s%4d%02d%02d%02d%02d%02d.jpg" ascii //weight: 1
        $x_1_4 = "ddir c:\\my documents" ascii //weight: 1
        $x_1_5 = "undeldir%d.html" ascii //weight: 1
        $x_1_6 = "xecure ssl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Agent_CAG_2147792457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAG"
        threat_id = "2147792457"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sqlpass.dic" ascii //weight: 1
        $x_1_2 = "sa:p@ssw0rd" ascii //weight: 1
        $x_1_3 = "Computer Numbers: %d" ascii //weight: 1
        $x_1_4 = {28 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 29 [0-16] 28 53 51 4c 53 45 52 56 45 52 29}  //weight: 1, accuracy: Low
        $x_1_5 = "====welcome====" ascii //weight: 1
        $x_1_6 = "usage:%s   IP  port [proxip] [port] [key]" ascii //weight: 1
        $x_1_7 = "new_connection_to_bounce():" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Agent_CAH_2147792458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAH"
        threat_id = "2147792458"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 49 4c 4c 45 44 00 00 42 59 45 20 42 59 45}  //weight: 1, accuracy: High
        $x_1_2 = {4d 41 43 3a [0-8] 48 6f 73 74 4e 61 6d 65 3a [0-16] 55 73 65 72 4e 61 6d 65 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {44 45 46 41 55 4c 54 4d 41 43 [0-16] 44 45 46 53 45 52 00 00 63 3a 5c}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 84 e0 00 00 00 8d ?? ?? ?? ?? ?? 68 ?? d2 40 00 (50|51) e8 ?? ?? 00 00 83 c4 08 85 c0 75 0f 8b ?? e4 0f 41 00 (51|52) e8 ?? ?? ff ff 83 c4 04 8d ?? ?? fc ff ff 68 ?? d2 40 00 (50|52)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_CAI_2147792459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.CAI"
        threat_id = "2147792459"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]" ascii //weight: 1
        $x_1_2 = {45 00 58 00 45 00 43 00 [0-6] 49 00 4e 00 4a 00 45 00 43 00 54 00 [0-6] 53 00 4c 00 45 00 45 00 50 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Windows\\KickStart" wide //weight: 1
        $x_1_4 = "ROOT\\SecurityCenter2" ascii //weight: 1
        $x_1_5 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST \"%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Agent_AXA_2147792461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.AXA"
        threat_id = "2147792461"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Ilovebeibei" ascii //weight: 3
        $x_3_2 = "s%\\pmeT\\SWODNIW\\:C" ascii //weight: 3
        $x_3_3 = "\\Startup\\36OPG.com" ascii //weight: 3
        $x_3_4 = "\\Temp\\hx107.tmp" ascii //weight: 3
        $x_2_5 = "\\Help\\RUNDLL32.exe" ascii //weight: 2
        $x_1_6 = "\\360rp\\" ascii //weight: 1
        $x_1_7 = "\\360SelfProtection\\" ascii //weight: 1
        $x_1_8 = "Rstray.exe" ascii //weight: 1
        $x_1_9 = "Fuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Agent_AXC_2147792462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.AXC"
        threat_id = "2147792462"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 50 e8 ?? ?? ?? ?? 83 c4 08 0a 00 68 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 3c 8b bc 24 28 01 00 00 03 c5 8b 70 78 8b 40 7c}  //weight: 1, accuracy: High
        $x_1_3 = "http://www.531140.com/" ascii //weight: 1
        $x_1_4 = {00 5c 72 65 6c 65 61 73 65 2e 74 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_ABHO_2147792463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ABHO"
        threat_id = "2147792463"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsharingsite.com/gettasks.php" wide //weight: 1
        $x_1_2 = "thenetsharing.com/gettasks.php" wide //weight: 1
        $x_1_3 = "backdoor-v4-ed2k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_ABHP_2147792464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.ABHP"
        threat_id = "2147792464"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 0f a2 85 c0 0f 84 ?? ?? ?? ?? b8 01 00 00 00 0f a2 f6 c6 01 74}  //weight: 1, accuracy: Low
        $x_1_2 = {68 63 d6 00 00 e8 ?? ?? ?? ?? 66 89 45 da 6a 00 e8 ?? ?? ?? ?? 89 45 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {00 62 61 63 6b 64 6f 6f 72 20 73 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 62 69 6e 64 00 63 6d 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GD_2147792465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GD"
        threat_id = "2147792465"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0}  //weight: 1, accuracy: Low
        $x_1_2 = "\\System\\ado\\msador15" ascii //weight: 1
        $x_1_3 = "av0309\\av0310\\new jk2009\\" ascii //weight: 1
        $x_1_4 = "system32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GF_2147792466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GF"
        threat_id = "2147792466"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuck360" ascii //weight: 1
        $x_1_2 = "fuckweb" ascii //weight: 1
        $x_2_3 = {00 64 6c 6c 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_GG_2147792467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.GG"
        threat_id = "2147792467"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 2a 8b fe fe c0 43 88 02 83 c9 ff}  //weight: 1, accuracy: High
        $x_1_2 = "\\System32\\TrkWcs.ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_HB_2147792468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.HB"
        threat_id = "2147792468"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 62 88 14 01 41 81 f9 ?? ?? 00 00 76 ee}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\gh0st" ascii //weight: 1
        $x_1_3 = "Comres.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_HC_2147792469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.HC"
        threat_id = "2147792469"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 30 26 40 3d ?? ?? ?? ?? 72 f5 e9}  //weight: 2, accuracy: Low
        $x_1_2 = {33 d2 f7 75 0c 8b 45 08 85 d2 74 0a}  //weight: 1, accuracy: High
        $x_1_3 = "SetThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_HD_2147792470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.HD"
        threat_id = "2147792470"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 34 11 18 03 ca 42 3b d0 7c f2}  //weight: 2, accuracy: High
        $x_1_2 = {8b 46 24 8b 4d 08 8d 04 48 0f b7 04 ?? 8b ?? 1c}  //weight: 1, accuracy: Low
        $x_1_3 = "\\System32\\svchost.exe -k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_HE_2147792471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.HE"
        threat_id = "2147792471"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "in IcmpPackFlood()" ascii //weight: 1
        $x_1_2 = "rename \"%s\" \"%s.exe\"" ascii //weight: 1
        $x_1_3 = "\\ctfmon.exe" ascii //weight: 1
        $x_1_4 = {00 5f 73 76 72 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {80 33 25 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Agent_OY_2147792473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agent.OY"
        threat_id = "2147792473"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 53 b1 45 88 44 24 ?? 88 44 24 ?? b0 52 88 4c 24 ?? 88 44 24 ?? 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {50 c6 44 24 ?? 55 c6 44 24 ?? 52 c6 44 24 ?? 4c c6 44 24 ?? 44 88 4c 24 ?? c6 44 24 ?? 77}  //weight: 1, accuracy: Low
        $x_1_3 = "GET %s HTTP/1.1" ascii //weight: 1
        $x_1_4 = {6a 06 8d 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

