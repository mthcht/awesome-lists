rule Backdoor_Win32_Havar_G_2147599952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Havar.G"
        threat_id = "2147599952"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Havar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SelfDelete.bat" ascii //weight: 1
        $x_1_2 = "if EXIST " ascii //weight: 1
        $x_1_3 = "wKBPSEVAxgHEWWAWxLPPTxWLAHHxKTAJxGKIIEJ@" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_5 = "Win32 Service" ascii //weight: 1
        $x_1_6 = "WinExec" ascii //weight: 1
        $x_1_7 = {89 03 b8 8f 23 68 da e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 ad b6 4d 81 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 a8 ed f2 ce e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 f8 19 42 5b e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 cc 97 10 25 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 1c 1c 60 30 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 78 5c 3b 55 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 74 ea c7 ef e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 d0 03 5c 09 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 65 41 fb a7 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 f4 15 93 b0 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 cb 6b 9b 91}  //weight: 1, accuracy: Low
        $x_1_8 = {ba a1 25 00 00 b9 50 78 01 00 b8 96 ff 92 00 03 c0 03 d1 03 d0 8b ca 2b c8 03 c8 03 c8 2b c8 8b c1 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Havar_B_2147619549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Havar.B"
        threat_id = "2147619549"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Havar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hav-Rat: " ascii //weight: 1
        $x_1_2 = "- LibTheme Version" ascii //weight: 1
        $x_1_3 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_4 = "Server succesfully created in current directory" ascii //weight: 1
        $x_1_5 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii //weight: 1
        $x_1_6 = "Server creator started...." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

