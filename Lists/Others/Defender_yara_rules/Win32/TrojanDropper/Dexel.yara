rule TrojanDropper_Win32_Dexel_A_2147696739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dexel.A"
        threat_id = "2147696739"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fso.CopyFile WScript.ScriptFullName, startup & \"\\Download_Manager.exe\"" wide //weight: 1
        $x_1_2 = "fso.CreateFolder temp & \"\\{09a405f0-0a5f-4cfe-a424-a56e9a3186f}\"" wide //weight: 1
        $x_1_3 = "Function kills(folderspec)" wide //weight: 1
        $x_1_4 = "wshshell.regwrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MSKERNEL\"" wide //weight: 1
        $x_1_5 = "\\xelag.exe" wide //weight: 1
        $x_1_6 = "\\WinDefender.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dexel_B_2147749641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dexel.B!MSR"
        threat_id = "2147749641"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexel"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 76 00 62 00 73 00 65 00 64 00 69 00 74 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 5c 00 73 00 63 00 72 00 69 00 70 00 74 00 32 00 65 00 78 00 65 00 5c 00 [0-16] 5c 00 6d 00 79 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 76 62 73 65 64 69 74 5f 73 6f 75 72 63 65 5c 73 63 72 69 70 74 32 65 78 65 5c [0-16] 5c 6d 79 77 73 63 72 69 70 74 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "A:E:I:M:Q:U:Y:]:a:e:i:m:q:u:y:}:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

