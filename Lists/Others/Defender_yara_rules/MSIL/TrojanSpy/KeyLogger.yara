rule TrojanSpy_MSIL_Keylogger_B_2147643444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.B"
        threat_id = "2147643444"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger Log From:" wide //weight: 1
        $x_1_2 = "smtp.gmail.com" wide //weight: 1
        $x_1_3 = {42 00 61 00 73 00 65 00 64 00 20 00 6f 00 66 00 66 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 70 00 6f 00 6c 00 79 00 6d 00 6f 00 72 00 70 00 68 00 69 00 63 00 20 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 74 00 75 00 74 00 6f 00 72 00 69 00 61 00 6c 00 20 00 77 00 72 00 69 00 74 00 74 00 65 00 6e 00 20 00 62 00 79 00 20 00 43 00 6c 00 61 00 73 00 73 00 69 00 63 00 61 00 6c 00 2e 00 0d 00 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 65 74 5f 4b 65 79 62 6f 61 72 64 00 67 65 74 5f 43 74 72 6c 4b 65 79 44 6f 77 6e 00 67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e 00 67 65 74 5f 43 61 70 73 4c 6f 63 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_C_2147643592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.C"
        threat_id = "2147643592"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 4b 65 79 62 6f 61 72 64 00 67 65 74 5f 43 74 72 6c 4b 65 79 44 6f 77 6e 00 67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_2 = "Polymorphic Keylogger has been activated on" wide //weight: 1
        $x_1_3 = "by Classical at HackForums" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_E_2147647968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.gen!E"
        threat_id = "2147647968"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "JFKrvS" wide //weight: 5
        $x_5_2 = "Grieve Logger" wide //weight: 5
        $x_5_3 = "Predator" wide //weight: 5
        $x_5_4 = "SkyNeo" wide //weight: 5
        $x_5_5 = "XYZ Logger" wide //weight: 5
        $x_1_6 = "smtp.gmail.com" wide //weight: 1
        $x_3_7 = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPLKHJJGFDSAZXCVBNM" wide //weight: 3
        $x_3_8 = "[CTRL]" wide //weight: 3
        $x_3_9 = "{CTRL}" wide //weight: 3
        $x_3_10 = "[ALT]" wide //weight: 3
        $x_3_11 = "{ALT}" wide //weight: 3
        $x_3_12 = "[DEL]" wide //weight: 3
        $x_3_13 = "{DEL}" wide //weight: 3
        $x_1_14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_15 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies" wide //weight: 1
        $x_2_16 = "NoFolderOptions" wide //weight: 2
        $x_2_17 = "NoControlPanel" wide //weight: 2
        $x_2_18 = "DisableTaskMgr" wide //weight: 2
        $x_2_19 = "DisableRegistryTools" wide //weight: 2
        $x_2_20 = "drivers\\etc\\hosts" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylogger_F_2147652064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.F"
        threat_id = "2147652064"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1a 13 05 08 28 ?? 00 00 0a 0a 1b 13 05 06 8e b7 17}  //weight: 2, accuracy: Low
        $x_1_2 = "set_K" ascii //weight: 1
        $x_1_3 = "ChromeToolbarsicn" wide //weight: 1
        $x_1_4 = {52 00 65 00 74 00 75 00 72 00 6e 00 [0-4] 5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00}  //weight: 1, accuracy: Low
        $x_1_5 = "srreal_" wide //weight: 1
        $x_1_6 = "smtp.aol.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylogger_H_2147653791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.H"
        threat_id = "2147653791"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U0VMRUNUICogRlJPTSBtb3pfbG9naW5zOw==" ascii //weight: 1
        $x_1_2 = "dHh0aW5mZWN0ZWRQQ0luZm8=" ascii //weight: 1
        $x_1_3 = "UGFzc3dvcmRzIG9mIA==" ascii //weight: 1
        $x_1_4 = "RW1pc3NhcnkgU2NyZWVuc2hvdCBvZjog" ascii //weight: 1
        $x_1_5 = {63 6d 56 6e 5a 57 52 70 64 41 3d 3d 0c 63 48 4a 76 59 32 56 34 63 41 3d 3d 0c 62 58 4e 6a 62 32 35 6d 61 57 63 3d 0c 64 32 6c 79 5a 58 4e 6f 59 58 4a 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_O_2147658712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.O"
        threat_id = "2147658712"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Stealth Keylogger Successfully Ran On:" wide //weight: 10
        $x_1_2 = "Stealth Log From:" wide //weight: 1
        $x_1_3 = "OFRna73m*aze01xY" wide //weight: 1
        $x_1_4 = "\\svcsvr.emp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylogger_T_2147671753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.T"
        threat_id = "2147671753"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{0}{1}{2}{3}{4}{5}{6}.exe" wide //weight: 1
        $x_1_2 = "taken on {4} at {5}:{6}:{7}" wide //weight: 1
        $x_1_3 = "smtp.gmail.com" wide //weight: 1
        $x_1_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 54 00 69 00 74 00 6c 00 65 00 3a 00 20 00 7b 00 32 00 7d 00 0d 00 0a 00 54 00 69 00 6d 00 65 00 3a 00 20 00 7b 00 33 00 7d 00 3a 00 7b 00 34 00 7d 00 3a 00 7b 00 35 00 7d 00}  //weight: 1, accuracy: High
        $x_1_5 = "{0}{1}{2}{3}.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_Z_2147683344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.Z"
        threat_id = "2147683344"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%&Dgolld.com" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "deformacion" wide //weight: 1
        $x_1_4 = "KBDLLHookProc" ascii //weight: 1
        $x_1_5 = "Informacion AnonymousBart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AD_2147684125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AD"
        threat_id = "2147684125"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msoklogs" wide //weight: 1
        $x_1_2 = "\\Microsoft-Security" wide //weight: 1
        $x_1_3 = "\\msologs" wide //weight: 1
        $x_1_4 = "[ENTER]" wide //weight: 1
        $x_1_5 = {57 52 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AE_2147684126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AE"
        threat_id = "2147684126"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scren=capturedScreen" wide //weight: 1
        $x_1_2 = "hascam=hascam" wide //weight: 1
        $x_1_3 = "uklog=send" wide //weight: 1
        $x_1_4 = "sendPassLogs" ascii //weight: 1
        $x_1_5 = "sendScreen" ascii //weight: 1
        $x_1_6 = "sendKeyLogs" ascii //weight: 1
        $x_1_7 = "sendCam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AG_2147684231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AG"
        threat_id = "2147684231"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "Usb Capture" wide //weight: 1
        $x_1_3 = "Screenshots" wide //weight: 1
        $x_1_4 = "WebCam" wide //weight: 1
        $x_1_5 = "FTPPUT" wide //weight: 1
        $x_1_6 = "Burn Keylogger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AH_2147684240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AH"
        threat_id = "2147684240"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "Started..." wide //weight: 1
        $x_1_3 = "Screenshot|{0}|" wide //weight: 1
        $x_1_4 = "Hello|{0}|{1}|{2}|{3}|{4}|" wide //weight: 1
        $x_1_5 = "StressStart" wide //weight: 1
        $x_1_6 = "GetPassFTP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AI_2147685402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AI"
        threat_id = "2147685402"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stoptheselfprotectioninnameofgode" ascii //weight: 1
        $x_1_2 = "[RCTRLAPPS]" ascii //weight: 1
        $x_1_3 = "set keyboard hook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AJ_2147685624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AJ"
        threat_id = "2147685624"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startuptmr" ascii //weight: 1
        $x_1_2 = "RemoteCommands" ascii //weight: 1
        $x_1_3 = "PrintScreentmr" ascii //weight: 1
        $x_1_4 = "AllinOnetmr" ascii //weight: 1
        $x_1_5 = "- ## Process list ## Of  ###" wide //weight: 1
        $x_1_6 = "----- Keyboard logger -----" wide //weight: 1
        $x_1_7 = "----- Victim's Info -----" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AK_2147686395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AK"
        threat_id = "2147686395"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "StartKeyLogger" ascii //weight: 1
        $x_1_2 = "StopDetectMyVirus" ascii //weight: 1
        $x_1_3 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_4 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_5 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AN_2147687543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AN"
        threat_id = "2147687543"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyLogger" ascii //weight: 1
        $x_1_2 = "SaveLogfile" ascii //weight: 1
        $x_1_3 = "_isEmailerOn" ascii //weight: 1
        $x_1_4 = "TimerEmailerTick" ascii //weight: 1
        $x_1_5 = "\\Acitivitylog.xml" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "CS Key logger Log Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AQ_2147687559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AQ"
        threat_id = "2147687559"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Keylogger:" wide //weight: 10
        $x_10_2 = "SendAll" ascii //weight: 10
        $x_10_3 = "btnEmailNow_Click" ascii //weight: 10
        $x_1_4 = "UserActivityHook" ascii //weight: 1
        $x_10_5 = "GetChromeUrl" ascii //weight: 10
        $x_10_6 = "FileLogHTML" ascii //weight: 10
        $x_10_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_1_8 = "HookManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylogger_AR_2147687562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AR"
        threat_id = "2147687562"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyLogger" ascii //weight: 1
        $x_1_2 = "UserActivityHook" ascii //weight: 1
        $x_1_3 = "SendMailImage" ascii //weight: 1
        $x_1_4 = "[PrintScreen]" wide //weight: 1
        $x_1_5 = "imagen.jpg" wide //weight: 1
        $x_1_6 = "@hotmail.com" wide //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AS_2147687573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AS"
        threat_id = "2147687573"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n7aKeylogger" ascii //weight: 1
        $x_1_2 = "KLG_Polling" ascii //weight: 1
        $x_1_3 = "/window.png" wide //weight: 1
        $x_1_4 = "i=MsTro" wide //weight: 1
        $x_1_5 = "smtp.gmail.com" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AT_2147687574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AT"
        threat_id = "2147687574"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":Zone.Identifier" wide //weight: 1
        $x_1_2 = "Screenshots" wide //weight: 1
        $x_1_3 = "Keylogger" wide //weight: 1
        $x_1_4 = "\\'Logs'.log" wide //weight: 1
        $x_1_5 = "Anonimous@Anonimous.com" wide //weight: 1
        $x_1_6 = "FTPPUT" wide //weight: 1
        $x_1_7 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AV_2147687591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AV"
        threat_id = "2147687591"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ultimate Logger" wide //weight: 1
        $x_1_2 = "firewall set opmode disable" wide //weight: 1
        $x_1_3 = "tmrSendLog_Tick" ascii //weight: 1
        $x_1_4 = "SendMailConfirmation" ascii //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AW_2147687592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AW"
        threat_id = "2147687592"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Logger" ascii //weight: 1
        $x_1_2 = "cam_listener" ascii //weight: 1
        $x_1_3 = "TakeScreenShot" ascii //weight: 1
        $x_1_4 = "UAH is ENABLED" wide //weight: 1
        $x_1_5 = "SENDING FILE ERROR" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BC_2147688165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BC"
        threat_id = "2147688165"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "domelt" ascii //weight: 1
        $x_1_2 = "Downaexec" ascii //weight: 1
        $x_1_3 = "GetCoolnovo" ascii //weight: 1
        $x_1_4 = "SendPasswords" ascii //weight: 1
        $x_1_5 = "DisableControlPanel" ascii //weight: 1
        $x_1_6 = "DisableLUA" ascii //weight: 1
        $x_1_7 = "DisableTaskMGR" ascii //weight: 1
        $x_1_8 = "Galaxy Logger" wide //weight: 1
        $x_1_9 = "_Passwords_" wide //weight: 1
        $x_1_10 = "Screenshot" wide //weight: 1
        $x_1_11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BD_2147688171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BD"
        threat_id = "2147688171"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 65 6e 64 70 72 65 76 69 6f 75 73 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 74 70 55 70 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "|sneakyeye|" wide //weight: 1
        $x_1_4 = "smtp.gmail.com" wide //weight: 1
        $x_1_5 = "\\tempkey\\templog.txt" wide //weight: 1
        $x_1_6 = "---------------] Log sent from:" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BH_2147688663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BH"
        threat_id = "2147688663"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Keylogger" ascii //weight: 10
        $x_1_2 = "ScreenShot" ascii //weight: 1
        $x_1_3 = "sendEmail" ascii //weight: 1
        $x_1_4 = "startup" ascii //weight: 1
        $x_1_5 = "klhost" wide //weight: 1
        $x_1_6 = "htmail3@gmail.com" wide //weight: 1
        $x_1_7 = "\\zlg.nat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BI_2147688713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BI"
        threat_id = "2147688713"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 [0-10] 53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "IDM addon" wide //weight: 1
        $x_1_3 = "cyberzzzzzzzzzz@gmail.com" wide //weight: 1
        $x_1_4 = "Block Alt+F4 and Alt+Tab key combinations" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_A_2147688963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.gen!A"
        threat_id = "2147688963"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "blackhat1997@gmail.com" wide //weight: 10
        $x_10_2 = "Add to start up" wide //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_4 = "sillycar21" wide //weight: 10
        $x_10_5 = "f.lux.Resources" ascii //weight: 10
        $x_1_6 = "OemMinus" wide //weight: 1
        $x_1_7 = "Oemplus" wide //weight: 1
        $x_1_8 = "OemOpenBrackets" wide //weight: 1
        $x_1_9 = "Oem6" wide //weight: 1
        $x_1_10 = "Oem5" wide //weight: 1
        $x_1_11 = "Oem1" wide //weight: 1
        $x_1_12 = "Oem7" wide //weight: 1
        $x_1_13 = "Oemcomma" wide //weight: 1
        $x_1_14 = "OemPeriod" wide //weight: 1
        $x_1_15 = "OemQuestion" wide //weight: 1
        $x_1_16 = "Oemtilde" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylogger_BJ_2147689788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BJ"
        threat_id = "2147689788"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ralphyx9876@gmail.com" ascii //weight: 1
        $x_1_2 = "y2uzkcrqztn8xnw" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BK_2147690590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BK"
        threat_id = "2147690590"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taznact002@gmail.com" ascii //weight: 1
        $x_1_2 = "rqbgvnfmpqkwambw" ascii //weight: 1
        $x_1_3 = "bss_chrom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BP_2147696741_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BP"
        threat_id = "2147696741"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetStartup" ascii //weight: 1
        $x_1_2 = "KeyLogger.Properties" wide //weight: 1
        $x_1_3 = "pastebin.com/api/api_post.php" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_BQ_2147696822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.BQ"
        threat_id = "2147696822"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 6e 64 54 6f 53 65 72 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 69 6c 6c 50 72 6f 63 65 73 73 41 6e 64 43 68 69 6c 64 72 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 6f 6f 6b 44 65 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "/getdata/getdata.php?type1=c&site1=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_CI_2147722443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.CI!bit"
        threat_id = "2147722443"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetKeyState" ascii //weight: 1
        $x_1_2 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_3 = "GetKeyboardState" ascii //weight: 1
        $x_1_4 = "System.Net.Mail" ascii //weight: 1
        $x_1_5 = "MailAddress" ascii //weight: 1
        $x_1_6 = "NetworkCredential" ascii //weight: 1
        $x_1_7 = "smtp.gmail.com" wide //weight: 1
        $x_1_8 = "@gmail.com" wide //weight: 1
        $x_1_9 = "log.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_CJ_2147723918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.CJ!bit"
        threat_id = "2147723918"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\data.txt" wide //weight: 1
        $x_1_2 = "\\dllhost.exe" wide //weight: 1
        $x_2_3 = "smtp.gmail.com" wide //weight: 2
        $x_2_4 = "Local Ip: {0} {1} Local ComputerName : {2} {1} Local UserName {3} {1}Data : {4}" wide //weight: 2
        $x_2_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylogger_HB_2147724790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.HB!bit"
        threat_id = "2147724790"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "watchwinsp.org/v2.txt" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 [0-2] 2f 00 73 00 20 00 2f 00 74 00 20 00 30 00}  //weight: 1, accuracy: Low
        $x_1_4 = "sendActiveEmail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_HE_2147728116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.HE!bit"
        threat_id = "2147728116"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".klog" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "globalKeyboardHook" ascii //weight: 1
        $x_1_4 = "\\KeyLogger\\obj\\Debug\\KeyLogger.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_HF_2147728274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.HF!bit"
        threat_id = "2147728274"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\datexsl.system" wide //weight: 1
        $x_1_2 = "smtp.gmail.com" wide //weight: 1
        $x_1_3 = " /CLICK/ " wide //weight: 1
        $x_1_4 = "update - " wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_SV_2147819193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.SV!MTB"
        threat_id = "2147819193"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Defender.pdb" ascii //weight: 1
        $x_1_2 = "SingleFileGenerator" ascii //weight: 1
        $x_1_3 = "GetKeyboardLayout" ascii //weight: 1
        $x_1_4 = "LowLevelKeyboardProc" ascii //weight: 1
        $x_1_5 = "WM_KEYDOWN" ascii //weight: 1
        $x_1_6 = "WH_KEYBOARD_LL" ascii //weight: 1
        $x_1_7 = "testwefwef\\testwefwef" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AK_2147839586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AK!MTB"
        threat_id = "2147839586"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 00 11 05 13 06 16 13 07 2b 4f 11 06 11 07 9a 13 08 00 11 08 06 07 28 31 00 00 0a 28 34 00 00 0a 13 09 11 09 2c 2c 00 73 36 00 00 0a 13 0a 02 7b 05 00 00 04 11 08 02 7b 06 00 00 04 72 c3 00 00 70 11 0a 28 0c 00 00 06 00 11 08 28 37 00 00 0a 00 00 00 11 07 17 58 13 07 11 07 11 06 8e 69 32 a9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_HNA_2147908589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.HNA!MTB"
        threat_id = "2147908589"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROCESS_SUSPEND_RESUME" ascii //weight: 1
        $x_1_2 = "GetConsoleWindow" ascii //weight: 1
        $x_1_3 = "GetActiveWindowTitle" ascii //weight: 1
        $x_1_4 = "GetKeyState" ascii //weight: 1
        $x_1_5 = "AppendAllText" ascii //weight: 1
        $x_1_6 = "CallNextHookEx" ascii //weight: 1
        $x_1_7 = "WH_KEYBOARD" ascii //weight: 1
        $x_1_8 = "PROCESS_CREATE_THREAD" ascii //weight: 1
        $x_1_9 = "WH_KEYBOARD_LL" ascii //weight: 1
        $x_1_10 = "WM_KEYDOWN" ascii //weight: 1
        $x_1_11 = "PROCESS_ALL_ACCESS" ascii //weight: 1
        $x_1_12 = "GetForegroundWindow" ascii //weight: 1
        $x_1_13 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_14 = "GetWindowText" ascii //weight: 1
        $x_1_15 = "GetKeyboardLayout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_SSD_2147924469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.SSD!MTB"
        threat_id = "2147924469"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PinloggerHelpers" ascii //weight: 1
        $x_1_2 = "Galaxy Logger V3 Stolen Passes" wide //weight: 1
        $x_1_3 = "/c ping -n 3 127.0.0.1 > nul & del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_AYA_2147925546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.AYA!MTB"
        threat_id = "2147925546"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "The logger has started, computer information:" wide //weight: 2
        $x_1_2 = "i-Cue Login" wide //weight: 1
        $x_1_3 = "KeyReaderr" ascii //weight: 1
        $x_1_4 = "InstallPRG" ascii //weight: 1
        $x_1_5 = "InfoSender_Tick" ascii //weight: 1
        $x_1_6 = "hideEverything" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylogger_SAY_2147931941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylogger.SAY!MTB"
        threat_id = "2147931941"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 28 0f 00 00 0a 72 ?? ?? ?? 70 28 10 00 00 0a 28 11 00 00 0a 2d 20 28 12 00 00 0a 6f 13 00 00 0a 1d 28 0f 00 00 0a 72 ?? ?? ?? 70 28 10 00 00 0a 17 28 14 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

