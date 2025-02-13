rule Worm_Win32_Datheens_A_2147582960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Datheens.A"
        threat_id = "2147582960"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Datheens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":\\Autorun.inf" ascii //weight: 2
        $x_2_2 = "[Autorun]" ascii //weight: 2
        $x_2_3 = "OPEN=Death.exe" ascii //weight: 2
        $x_3_4 = "shellexecute=Death.exe" ascii //weight: 3
        $x_3_5 = "shell\\Auto\\command=Death.exe" ascii //weight: 3
        $x_2_6 = "C:\\hosts" ascii //weight: 2
        $x_1_7 = "\\SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_8 = "net stop server /y" ascii //weight: 2
        $x_2_9 = "c:\\pass.dic" ascii //weight: 2
        $x_1_10 = "CreateRemoteThread" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
        $x_1_12 = "WNetAddConnection2A" ascii //weight: 1
        $x_1_13 = "NetScheduleJobAdd" ascii //weight: 1
        $x_1_14 = "NetShareEnum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Datheens_B_2147582961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Datheens.B"
        threat_id = "2147582961"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Datheens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Death.exe" ascii //weight: 1
        $x_1_2 = {2e 53 43 52 00 00 00 00 ff ff ff ff 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 48 54 4d 4c 00 00 00 ff ff ff ff 04 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 41 53 50 58 00 00 00 ff ff ff ff 1b 00}  //weight: 1, accuracy: High
        $x_1_5 = "width=0 height=0></iframe>" ascii //weight: 1
        $x_1_6 = "<iframe src=" ascii //weight: 1
        $x_1_7 = "GetSystemDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Datheens_C_2147582966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Datheens.C"
        threat_id = "2147582966"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Datheens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "net stop Symantec" ascii //weight: 3
        $x_2_2 = {2e 48 54 4d 4c 00 00 00 ff ff ff ff 04 00}  //weight: 2, accuracy: High
        $x_2_3 = {2e 41 53 50 58 00 00 00 ff ff ff ff 1b 00}  //weight: 2, accuracy: High
        $x_2_4 = ":\\autorun.inf" ascii //weight: 2
        $x_2_5 = "<script language=\"javascript\" src=" ascii //weight: 2
        $x_2_6 = "[AutoRun]" ascii //weight: 2
        $x_1_7 = "open=" ascii //weight: 1
        $x_1_8 = "shellexecute=" ascii //weight: 1
        $x_1_9 = "shell\\Auto\\command=" ascii //weight: 1
        $x_1_10 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_11 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Datheens_D_2147583249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Datheens.D"
        threat_id = "2147583249"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Datheens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 9
        $x_5_2 = "\\Death.exe" ascii //weight: 5
        $x_5_3 = "c:\\pass.dic" ascii //weight: 5
        $x_5_4 = "net stop server /y" ascii //weight: 5
        $x_5_5 = "Dedll1" ascii //weight: 5
        $x_5_6 = "dllfile1" ascii //weight: 5
        $x_1_7 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "\\wuauclt.exe" ascii //weight: 1
        $x_1_9 = "\\spoolsv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Datheens_E_2147583250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Datheens.E"
        threat_id = "2147583250"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Datheens"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 9
        $x_5_2 = "Death.exe" ascii //weight: 5
        $x_5_3 = "Death.dll" ascii //weight: 5
        $x_5_4 = "Dedll" ascii //weight: 5
        $x_5_5 = "dllfile" ascii //weight: 5
        $x_1_6 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "\\program files\\internet explorer\\iexplore.exe" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

