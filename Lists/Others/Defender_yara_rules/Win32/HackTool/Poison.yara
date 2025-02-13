rule HackTool_Win32_Poison_A_2147648245_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Poison.gen!A"
        threat_id = "2147648245"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {33 db 8a 98 01 01 00 00 88 14 18 33 db 8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75 a5}  //weight: 20, accuracy: High
        $x_1_2 = "SOFTWARE\\Classes\\http\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "OpenProcessToken" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "TerminateProcess" ascii //weight: 1
        $x_1_9 = "WNetOpenEnumA" ascii //weight: 1
        $x_1_10 = "OpenServiceA" ascii //weight: 1
        $x_1_11 = "NtQueryInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

