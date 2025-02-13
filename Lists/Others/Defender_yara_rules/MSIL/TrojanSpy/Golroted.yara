rule TrojanSpy_MSIL_Golroted_A_2147648535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Golroted.A"
        threat_id = "2147648535"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golroted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 00 4c 00 6f 00 67 00 67 00 65 00 72 00 [0-15] 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 4c 00 6f 00 67 00 20 00 2d 00 20 00 5b 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Stealer - [" wide //weight: 1
        $x_1_3 = "Predator Logger - [" wide //weight: 1
        $x_1_4 = "Notification Email - [" wide //weight: 1
        $x_1_5 = "RsBot_Accounts.ini" wide //weight: 1
        $x_1_6 = "Steals the Wallet.DAT file" wide //weight: 1
        $x_1_7 = "Bitcoinsub" ascii //weight: 1
        $x_1_8 = "Disablefakerror" wide //weight: 1
        $x_1_9 = "Disablespreaders" wide //weight: 1
        $x_1_10 = "Predator Pain v" wide //weight: 1
        $x_1_11 = {68 00 6f 00 6c 00 64 00 65 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 74 00 78 00 74 00 ?? ?? ?? 53 00 6f 00 75 00 72 00 63 00 65 00 3a 00 7b 00 34 00 7d 00 7b 00 34 00 7d 00 7b 00 30 00 7d 00 7b 00 35 00 7d 00 48 00 6f 00 73 00 74 00 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Golroted_B_2147686566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Golroted.B"
        threat_id = "2147686566"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golroted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FolderN\\name.exe" ascii //weight: 1
        $x_1_2 = "FolderN\\mata2.bat" ascii //weight: 1
        $x_1_3 = "FolderN\\svhost.bat" ascii //weight: 1
        $x_1_4 = "FolderN\\name.exe.bat" ascii //weight: 1
        $x_1_5 = "FolderN\\melt.bat" ascii //weight: 1
        $x_1_6 = "svhost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_Golroted_B_2147686566_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Golroted.B"
        threat_id = "2147686566"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golroted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendLogsPHP" ascii //weight: 1
        $x_1_2 = "SendLogsFTP" ascii //weight: 1
        $x_1_3 = "stealWebroswers" ascii //weight: 1
        $x_1_4 = "stealMail" ascii //weight: 1
        $x_1_5 = {53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "seekanddestroy" ascii //weight: 1
        $x_1_7 = "Disablestealers" wide //weight: 1
        $x_1_8 = "Disablelogger" wide //weight: 1
        $x_1_9 = "Disablestartup" wide //weight: 1
        $x_1_10 = "Disablescreeny" wide //weight: 1
        $x_1_11 = "Disablespreaders" wide //weight: 1
        $x_1_12 = "Disablemelt" wide //weight: 1
        $x_1_13 = "Keylogger Enabled:" wide //weight: 1
        $x_1_14 = "Clipboard-Logger Enabled:" wide //weight: 1
        $x_1_15 = "Stealers Enabled:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule TrojanSpy_MSIL_Golroted_B_2147691501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Golroted.B!!Golroted.gen!A"
        threat_id = "2147691501"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golroted"
        severity = "Critical"
        info = "Golroted: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendLogsPHP" ascii //weight: 1
        $x_1_2 = "SendLogsFTP" ascii //weight: 1
        $x_1_3 = "stealWebroswers" ascii //weight: 1
        $x_1_4 = "stealMail" ascii //weight: 1
        $x_1_5 = {53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "seekanddestroy" ascii //weight: 1
        $x_1_7 = "Disablestealers" wide //weight: 1
        $x_1_8 = "Disablelogger" wide //weight: 1
        $x_1_9 = "Disablestartup" wide //weight: 1
        $x_1_10 = "Disablescreeny" wide //weight: 1
        $x_1_11 = "Disablespreaders" wide //weight: 1
        $x_1_12 = "Disablemelt" wide //weight: 1
        $x_1_13 = "Keylogger Enabled:" wide //weight: 1
        $x_1_14 = "Clipboard-Logger Enabled:" wide //weight: 1
        $x_1_15 = "Stealers Enabled:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_MSIL_Golroted_C_2147693097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Golroted.C"
        threat_id = "2147693097"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golroted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RuntimeTypeHandle" ascii //weight: 1
        $x_1_2 = "GetTypeFromHandle" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
        $x_1_4 = "System.Runtime.CompilerServices" ascii //weight: 1
        $x_1_5 = "RuntimeHelpers" ascii //weight: 1
        $x_1_6 = "GetObjectValue" ascii //weight: 1
        $x_1_7 = "NewLateBinding" ascii //weight: 1
        $x_1_8 = "LateGet" ascii //weight: 1
        $x_1_9 = "LateCall" ascii //weight: 1
        $x_1_10 = "GetObject" wide //weight: 1
        $x_1_11 = "Invoke" wide //weight: 1
        $x_1_12 = "Load" wide //weight: 1
        $x_1_13 = {14 d0 02 00 00 01 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 17 8d 01 00 00 01 13 0d 11 0d 16 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? a2 11 0d 14 14 14 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0d 09 74 02 00 00 01 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
        $x_1_14 = {09 11 2a 09 11 2a 91 08 11 29 91 11 2a 1a 5d 1d 5f 62 d2 61 09 11 2a 17 da 91 61 20 ?? ?? ?? ?? 5d b4 9c 11 2a 17 d6 13 2a 11 2a 11 3d 3e ?? ?? ?? ?? 11 29 17 d6 13 29 11 29 17 3e ?? ?? ?? ?? 09 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

