rule TrojanSpy_MSIL_KeyLogger_BR_2147706587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.BR"
        threat_id = "2147706587"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadLogsKeylogger" wide //weight: 1
        $x_1_2 = "Botnet Offline" wide //weight: 1
        $x_1_3 = "entradatrasera=hidad&key=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_BS_2147706673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.BS"
        threat_id = "2147706673"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LiveKeyLog" ascii //weight: 1
        $x_1_2 = "GetKeyLog" ascii //weight: 1
        $x_1_3 = "GetPasswords" ascii //weight: 1
        $x_1_4 = "GetScreen" ascii //weight: 1
        $x_1_5 = "StartChat" ascii //weight: 1
        $x_1_6 = "StartCMD" ascii //weight: 1
        $x_1_7 = "StartStress" ascii //weight: 1
        $x_1_8 = "StartWebcam" ascii //weight: 1
        $x_1_9 = "StartDownload" ascii //weight: 1
        $x_1_10 = "StartUpload" ascii //weight: 1
        $x_1_11 = "DisableCMD" ascii //weight: 1
        $x_1_12 = "DisableTaskMGR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_BT_2147706784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.BT"
        threat_id = "2147706784"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "explorer.Resources" wide //weight: 1
        $x_1_2 = "@gmail.com" wide //weight: 1
        $x_1_3 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_4 = "keybd_event" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_BU_2147706798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.BU"
        threat_id = "2147706798"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@KeyStrokeWait" wide //weight: 1
        $x_1_2 = "@force_lock" wide //weight: 1
        $x_1_3 = "@monitor_window" wide //weight: 1
        $x_1_4 = "@monitor_key" wide //weight: 1
        $x_1_5 = "@leadsmarket.com" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "data source=192.168.0.2;user id=em;password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_BV_2147706839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.BV"
        threat_id = "2147706839"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6e 6d 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "passoruserketto" ascii //weight: 1
        $x_1_3 = "felesleg" ascii //weight: 1
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_5 = "@gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_CH_2147717151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.CH"
        threat_id = "2147717151"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " - Logs of ###" wide //weight: 1
        $x_1_2 = "Print.png" wide //weight: 1
        $x_1_3 = "bitcointranslate@" wide //weight: 1
        $x_1_4 = "Victim's Info" wide //weight: 1
        $x_1_5 = "Keyboard logger" wide //weight: 1
        $x_1_6 = "@dlfileoverwrite" wide //weight: 1
        $x_1_7 = "/severalcmds.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_MA_2147811901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.MA!MTB"
        threat_id = "2147811901"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Caps Lock]" wide //weight: 1
        $x_1_2 = "[Pause]" wide //weight: 1
        $x_1_3 = "Base64Decode" ascii //weight: 1
        $x_1_4 = "\\WindowsApps\\dasHost.exe" wide //weight: 1
        $x_1_5 = "Kill" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "/C ping 1.1.1.1 - n 1 - w 5000 > Nul & Del" wide //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "Encrypt" ascii //weight: 1
        $x_1_10 = "AdminOrNot" ascii //weight: 1
        $x_1_11 = "HKEY_CLASSES_ROOT\\http\\shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_MD_2147819712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.MD!MTB"
        threat_id = "2147819712"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 04 16 13 05 28 ?? ?? ?? 06 13 0d 12 0d 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 0c 11 0c 2c 07 00 17 13 05 00 2b 05 00 16 13 05 00 28 ?? ?? ?? 06 13 06 1f 10 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 07 11 07 20 00 80 00 00 5f 20 00 80 00 00 fe 01 13 0e 11 0e 2c 02 00 00 28 ?? ?? ?? 0a 13 08 04 28 ?? ?? ?? 0a 0b 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 00 07 1f 40 31 07}  //weight: 1, accuracy: Low
        $x_1_2 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_3 = "SetHook" ascii //weight: 1
        $x_1_4 = "SetAutorunValue" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_6 = "\\WarningsEncoded.log" wide //weight: 1
        $x_1_7 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_8 = "get_CapsLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_ME_2147819714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.ME!MTB"
        threat_id = "2147819714"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 53 00 06 28 ?? ?? ?? 06 0b 07 17 2e 0a 07 20 01 ?? ?? ?? fe 01 2b 01 17 0c 08 2c 33 00 7e ?? ?? ?? 04 06 0d 12 03 fe ?? ?? ?? ?? 01 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 1f 51 fe 01 13 04 11 04 2c 0b 72 ?? ?? ?? 70 28 ?? ?? ?? 06 00 2b 13}  //weight: 1, accuracy: Low
        $x_1_2 = "example1@mz.netartis.pl" wide //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "SendMail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_SRP_2147835601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.SRP!MTB"
        threat_id = "2147835601"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 04 05 0e 04 0e 05 0e 06 28 ?? ?? ?? 06 2d 06 06 17 58 0a 2b 04 15 0b de 0c 06 1f 0a 31 e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_ARA_2147848467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.ARA!MTB"
        threat_id = "2147848467"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\Users\\lab\\Desktop\\lab\\keylog.txt" ascii //weight: 2
        $x_2_2 = "KEYLOGGER" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_ARA_2147848467_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.ARA!MTB"
        threat_id = "2147848467"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 13 07 11 07 17 2e 0b 11 07 20 01 80 ff ff fe 01 2b 01 17 13 08 11 08 2c 2c}  //weight: 2, accuracy: High
        $x_2_2 = "chkSysEve" ascii //weight: 2
        $x_2_3 = ":\\Windows Handler\\Handler.dat" ascii //weight: 2
        $x_2_4 = "Keystrokes saved from user" ascii //weight: 2
        $x_1_5 = "SendMail" ascii //weight: 1
        $x_1_6 = "ICredentialsByHost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_KeyLogger_SK_2147906166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/KeyLogger.SK!MTB"
        threat_id = "2147906166"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 04 00 00 5b 20 00 04 00 00 5b 1f 64 5a 1f 18 5b 0d 09 18 31 07 02 09 28 0d 00 00 06 07 17 58 0b 07 06 8e 69 32 a7}  //weight: 2, accuracy: High
        $x_2_2 = "SfkLoader.Form1.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

