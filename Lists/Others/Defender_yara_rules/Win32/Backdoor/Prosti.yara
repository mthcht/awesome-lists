rule Backdoor_Win32_Prosti_U_2147607977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prosti.U"
        threat_id = "2147607977"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prosti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ab ab ab e9 54 01 00 00 66 b8 0a 84 bb 00 00 f7 bf 80 fa 60 ba 4b 45 58 50 73 02 b0 03 39 93 00 10 00 00}  //weight: 5, accuracy: High
        $x_1_2 = {4e 6f 52 65 61 6c 4d 6f 64 65 [0-5] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 57 69 6e 4f 6c 64 41 70 70 [0-16] 44 65 6c 65 74 65 [0-2] 2e 62 61 74 [0-16] 3a 74 72 79}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 79 64 6c 6c [0-16] 64 6c 6c 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {52 74 6c 4e 74 53 74 61 74 75 73 54 6f 44 6f 73 45 72 72 6f 72 00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 4e 74 4f 70 65 6e 54 68 72 65 61 64 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Prosti_F_2147621242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prosti.F"
        threat_id = "2147621242"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prosti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Windows\\ScreenBlazeUpgrader.bat" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 63 72 65 65 6e 62 6c 61 7a 65 2e 63 6f 6d 2f [0-8] 2e 70 68 70 3f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "This way madExcept can't install the thread hooks" ascii //weight: 1
        $x_1_4 = {8b e5 5d c3 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 73 63 72 65 65 6e 62 6c 61 7a 65 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prosti_L_2147621602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prosti.L"
        threat_id = "2147621602"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prosti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 43 14 66 c7 45 ?? 02 00 56 e8 ?? ?? ?? ?? 66 89 45 ?? 8b 43 04 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 7e 66 04 80 8b 43 14 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {68 7f 66 04 40 8b 43 14 50 e8 ?? ?? ?? ?? 40 75 ?? c7 04 24 ff ff ff ff 8b c3 e8 ?? ?? ?? ?? eb ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prosti_AG_2147627798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prosti.AG"
        threat_id = "2147627798"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prosti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_1_2 = "http://www.screenblaze.com/curver.php" ascii //weight: 1
        $x_1_3 = "\\ScrBlaze.scr" ascii //weight: 1
        $x_1_4 = "\\ScreenBlaze.exe " ascii //weight: 1
        $x_1_5 = "\\ScreenBlazeUpgrader.bat" ascii //weight: 1
        $x_1_6 = "del C:\\Windows\\ScreenBlaze.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Prosti_CCJZ_2147943648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prosti.CCJZ!MTB"
        threat_id = "2147943648"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prosti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Start To InJect" ascii //weight: 2
        $x_2_2 = "Dllrun" ascii //weight: 2
        $x_1_3 = "Buf_CoolDll" ascii //weight: 1
        $x_1_4 = "RealHost:" ascii //weight: 1
        $x_1_5 = "HostPID:" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\NetDDE\\SysDll" ascii //weight: 1
        $x_1_7 = "\\Temp\\comb.dll" ascii //weight: 1
        $x_1_8 = "C:\\$RECYCLE.BIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

