rule Backdoor_Win32_Remcos_A_2147731013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.A!MTB"
        threat_id = "2147731013"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uploading file to C&C:" ascii //weight: 1
        $x_1_2 = "hCreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide //weight: 1
        $x_1_3 = "REMCOS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_PA_2147742673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.PA!MTB"
        threat_id = "2147742673"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 30 eb ?? [0-32] 80 f3 58 eb ?? [0-32] f6 d3 eb ?? [0-32] 80 f3 13 eb ?? [0-32] 88 1c 30 eb ?? [0-32] 46 eb 0f [0-32] 81 fe ?? ?? 00 00 eb ?? [0-32] 0f 85 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 ?? 00 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_2147744086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos!MTB"
        threat_id = "2147744086"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 41 f7 e3 c1 ea 02 83 e2 fc 8d 04 92 f7 d8 0f b6 04 06 46 30 87 ?? ?? ?? ?? 47 75 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_2147744086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos!MTB"
        threat_id = "2147744086"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ENTER]" wide //weight: 1
        $x_1_2 = "[BKSP]" wide //weight: 1
        $x_1_3 = "[CTRL]" wide //weight: 1
        $x_1_4 = "[CAPS]" wide //weight: 1
        $x_1_5 = "[INSERT]" wide //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "\\User Data\\Local State" wide //weight: 1
        $x_1_8 = "\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_9 = "NSSBase64_DecodeBuffer" ascii //weight: 1
        $x_1_10 = "PK11_CheckUserPassword" ascii //weight: 1
        $x_1_11 = "encryptedUsername" ascii //weight: 1
        $x_1_12 = "encryptedPassword" ascii //weight: 1
        $x_1_13 = "POP3 Password" wide //weight: 1
        $x_1_14 = "SMTP Password" wide //weight: 1
        $x_1_15 = "HTTP Password" wide //weight: 1
        $x_1_16 = "IMAP Password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule Backdoor_Win32_Remcos_WS_2147748024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.WS!MTB"
        threat_id = "2147748024"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 6c 65 ?? ?? ?? 69 6e ?? ?? ?? ?? ?? 00 00 00 66 ?? 63 c1 a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? 66 0f 6a d2 a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? 0f 63 f7 a9 ?? ?? ?? ?? 31 1c 08 a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? 66 0f 68 ef a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? 66 0f 6b f5 a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? 66 0f 69 c5 a9 ?? ?? ?? ?? a9 ?? ?? ?? ?? 66 0f 6b f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_PS_2147754914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.PS!MTB"
        threat_id = "2147754914"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 03 0f 66 a9 fd 0e 66 a4 35 00 66 0f 98 10 66 ?? 0d 0e 66 2f 4e 0e 66 b9 22 0d 66 d7 a3 00 66 f6 6d 10 66 ?? 92 0f 66 30 6c 0e 66 ed ee 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_ARK_2147761620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.ARK!MTB"
        threat_id = "2147761620"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d a4 24 00 00 00 00 [0-31] 8b ?? ?? 40 24 41 00 33 ?? ?? 89 [0-2] 85 c9 74 [0-4] 83 c1 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8d a4 24 00 00 00 00 [0-31] 8b ?? ?? 70 24 41 00 33 ?? ?? 85 c9 89 [0-2] 74 [0-4] 83 c1 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Remcos_ARK_2147761620_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.ARK!MTB"
        threat_id = "2147761620"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f0 8b 45 ec e8 ?? ?? ?? ?? 8b d8 85 db 75 ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 8b c6 8b 55 e8 e8 ?? ?? ?? ?? eb ?? ff 36 ef 00 90 90 90 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_PB_2147772778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.PB!MTB"
        threat_id = "2147772778"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /cstart https://vk.me/kyugg" wide //weight: 1
        $x_1_2 = "C:\\MathGame\\" wide //weight: 1
        $x_1_3 = "FromBase64String" wide //weight: 1
        $x_1_4 = "get_ExplorerLogin" ascii //weight: 1
        $x_1_5 = "CreateTextFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_GA_2147773587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.GA!MTB"
        threat_id = "2147773587"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Remcos" ascii //weight: 10
        $x_1_2 = "Remcos_Mutex_Inj" ascii //weight: 1
        $x_1_3 = "BreakingSecurity.net" ascii //weight: 1
        $x_1_4 = "Remcos restarted by watchdog" ascii //weight: 1
        $x_1_5 = "Mutex_RemWatchdog" ascii //weight: 1
        $x_1_6 = "%02i:%02i:%02i:%03i" ascii //weight: 1
        $x_1_7 = "Remcos v" ascii //weight: 1
        $x_1_8 = "keylogger" ascii //weight: 1
        $x_1_9 = "CloseCamera" ascii //weight: 1
        $x_1_10 = "OpenCamera" ascii //weight: 1
        $x_1_11 = "[Enter]" ascii //weight: 1
        $x_1_12 = "SbieDll.dll" ascii //weight: 1
        $x_1_13 = "PROCMON_WINDOW_CLASS" ascii //weight: 1
        $x_1_14 = "HARDWARE\\ACPI\\DSDT\\VBOX__" ascii //weight: 1
        $x_1_15 = "[KeepAlive]" ascii //weight: 1
        $x_1_16 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Remcos_ZJ_2147776657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.ZJ!MTB"
        threat_id = "2147776657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShutDownDlg.dll" ascii //weight: 1
        $x_1_2 = "\\Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "RunDlg.dll" ascii //weight: 1
        $x_1_4 = "Internet Walker" ascii //weight: 1
        $x_1_5 = "CheckIC.dll" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Remcos_ZK_2147776658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.ZK!MTB"
        threat_id = "2147776658"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Control Panel\\Desktop\\ResourceLocale" wide //weight: 1
        $x_1_2 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide //weight: 1
        $x_1_3 = "%s%S.dll" wide //weight: 1
        $x_1_4 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-15] 2e 00 74 00 6d 00 70 00 2d 00 3e 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-15] 2e 00 74 00 6d 00 70 00 5c 00 63 00 75 00 73 00 74 00 6f 00 6d 00 2e 00 69 00 6e 00 69 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_ZL_2147777167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.ZL!MTB"
        threat_id = "2147777167"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 8a 54 11 ?? 32 c2 5a 88 02 ff 06 4b 75 d1 19 00 8b 16 8d 44 10 ?? 50 8b 45 ?? 8b 16 8a 44 10 ?? 8b 16 2b 15 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Users\\Public\\Libraries\\temp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_ZO_2147778945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.ZO!MTB"
        threat_id = "2147778945"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cdkrixeoskzlr" ascii //weight: 1
        $x_1_2 = "CryptEncryptMessage" ascii //weight: 1
        $x_1_3 = "CryptMsgGetParam" ascii //weight: 1
        $x_1_4 = "WINNLSEnableIME" ascii //weight: 1
        $x_1_5 = "AVIStreamTimeToSample" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_MM_2147787629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.MM!MTB"
        threat_id = "2147787629"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 0f b7 00 f6 c4 f9 74 1e 8b 1d ?? ?? ?? ?? 8b 1b 03 1d ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d8 a1 ?? ?? ?? ?? 01 03 83 01 02 ff 05 ?? ?? ?? ?? 4a 75 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_MM_2147787629_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.MM!MTB"
        threat_id = "2147787629"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {25 f0 07 00 00 66 0f 28 a0 80 09 46 00 66 0f 28 b8 70 05 46 00 66 0f 54 f0 66 0f 5c c6 66 0f 59 f4 66 0f 5c f2 f2 0f 58 fe 66 0f 59 c4 66 0f 28 e0}  //weight: 10, accuracy: High
        $x_2_3 = "Remcos restarted by watchdog!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_MM_2147787629_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.MM!MTB"
        threat_id = "2147787629"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stub\\UopyEx\\achiiMe" ascii //weight: 1
        $x_1_2 = "get_Is64BitOperatingSystem" ascii //weight: 1
        $x_1_3 = "xl@zCn=mt]sk]" ascii //weight: 1
        $x_1_4 = "GetEntryAssembly" ascii //weight: 1
        $x_1_5 = "CreateFromUrl" ascii //weight: 1
        $x_1_6 = "$15UEAEDC-EA00-45H8-8D67?8BD7CCTEAC70" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_DB_2147794750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.DB!!Remcos.gen!DB"
        threat_id = "2147794750"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "Remcos: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "DB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remcos_Mutex" ascii //weight: 1
        $x_1_2 = "Keylogger Started" ascii //weight: 1
        $x_1_3 = "Mutex_RemWatchdog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_QW_2147795463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.QW!MTB"
        threat_id = "2147795463"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "PolTraget.vbp" ascii //weight: 3
        $x_3_2 = "dencie" ascii //weight: 3
        $x_3_3 = "students_and_employees.ToggleState" ascii //weight: 3
        $x_3_4 = "DTPicker" ascii //weight: 3
        $x_3_5 = "KeyAscii" ascii //weight: 3
        $x_3_6 = "KeyCode" ascii //weight: 3
        $x_3_7 = "SysAllocStringByteLen" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_BL_2147837070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.BL!MTB"
        threat_id = "2147837070"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e0 07 0b d0 88 95 [0-4] 0f b6 8d [0-4] f7 d9 88 8d [0-4] 8b 95 [0-4] 8a 85 [0-4] 88 84 15 [0-4] e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_MA_2147896308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.MA!MTB"
        threat_id = "2147896308"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e0 00 02 03 0b 01 03 00 00 ea 09 00 00 3e 01 00 00 00 00 00 f0 e3 05 00 00 10 00 00 00 30 1b 00 00 00 40 00 00 10}  //weight: 2, accuracy: High
        $x_2_2 = {4d 61 63 68 69 6e 65 01 07 4d 61 70 4b 65 79 73 01 07 4e 61 6d 65 6c 65 6e 01 07 4e 65 77 50 72 6f 63 01 07 4f 62 6a 4e 61 6d 65 01 07 50 6b 67 50 61 74 68 01 07 50 6f 69 6e 74 65 72 01 07 50 72 6f}  //weight: 2, accuracy: High
        $x_2_3 = ":/Users/Admin/AppData/Roaming/installer/installer/main.go" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_GXB_2147911990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.GXB!MTB"
        threat_id = "2147911990"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f ef c1 0f 11 80 ?? ?? ?? ?? 0f 10 80 ?? ?? ?? ?? 66 0f ef c1 0f 11 80 ?? ?? ?? ?? 0f 10 80 ?? ?? ?? ?? 66 0f ef c1 0f 11 80 ?? ?? ?? ?? 0f 10 80 ?? ?? ?? ?? 66 0f ef c1 0f 11 80 ?? ?? ?? ?? 83 c0 40 3d 00 a4 08 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Remcos_GZZ_2147942120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remcos.GZZ!MTB"
        threat_id = "2147942120"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d8 33 fa 89 5c 24 ?? 8b cf 8b 74 24 ?? 8b df 8b c6 c1 eb 0f 0f a4 c1 11 33 d2 89 7c 24 ?? c1 e0 ?? 0b d1 0b d8}  //weight: 10, accuracy: Low
        $x_5_2 = {f0 64 a1 30 00 00 00 89 78 ?? 8b 42 ?? 03 c7 ff d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

