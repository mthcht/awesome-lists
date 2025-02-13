rule TrojanDropper_Win32_QQpass_CJK_2147581215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.CJK"
        threat_id = "2147581215"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CLSID\\{08315C1A-9BA9-4B7C-A432-2688" ascii //weight: 10
        $x_1_2 = "xiaran" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_4 = "_xr.bat" ascii //weight: 1
        $x_1_5 = "JmpHookOff" ascii //weight: 1
        $x_1_6 = "JmpHookOn" ascii //weight: 1
        $x_1_7 = ":try" ascii //weight: 1
        $x_1_8 = "goto try" ascii //weight: 1
        $x_1_9 = "if exist \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_CJL_2147581216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.CJL"
        threat_id = "2147581216"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CLSID\\{06A48AD9-FF57-4E73-937B-B493" ascii //weight: 10
        $x_1_2 = "WinInfo.rxk" ascii //weight: 1
        $x_1_3 = "WinInfo.bkk" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_5 = "MsgHookOff" ascii //weight: 1
        $x_1_6 = "MsgHookOn" ascii //weight: 1
        $x_1_7 = "co6meiy" ascii //weight: 1
        $x_1_8 = "ea7cuoa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_CJM_2147581217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.CJM"
        threat_id = "2147581217"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CLSID\\{A6011F8F-A7F8-49AA-9ADA-49127D43138F" ascii //weight: 10
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_3 = "NewInfo.bak" ascii //weight: 1
        $x_1_4 = "NewInfo.rxk" ascii //weight: 1
        $x_1_5 = "tianlia" ascii //weight: 1
        $x_1_6 = "xiaogan" ascii //weight: 1
        $x_1_7 = "HookOn" ascii //weight: 1
        $x_1_8 = "HookOff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_CJN_2147581218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.CJN"
        threat_id = "2147581218"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "CLSID\\{F3D0D422-CE6D-47B3-9CE6-C54DD63F1ADB}" ascii //weight: 20
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_2_3 = "qqgsExe" ascii //weight: 2
        $x_2_4 = "qqgsDll" ascii //weight: 2
        $x_1_5 = "MsgHookOff" ascii //weight: 1
        $x_1_6 = "MsgHookOn" ascii //weight: 1
        $x_1_7 = ":try" ascii //weight: 1
        $x_1_8 = "del \"" ascii //weight: 1
        $x_1_9 = "if exist \"" ascii //weight: 1
        $x_1_10 = " goto try" ascii //weight: 1
        $x_1_11 = "del %0" ascii //weight: 1
        $x_2_12 = "QQ_GuiShou" ascii //weight: 2
        $x_2_13 = "MrSoft.bak" ascii //weight: 2
        $x_2_14 = "MrSoft.sys" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_D_2147582400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.gen!D"
        threat_id = "2147582400"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 3
        $x_2_2 = ":\\Program Files\\Common Files\\Microsoft Shared\\MSINFO\\" ascii //weight: 2
        $x_3_3 = "JmpHookOn" ascii //weight: 3
        $x_2_4 = "JmpHookOff" ascii //weight: 2
        $x_1_5 = "DLLFILE" ascii //weight: 1
        $x_1_6 = "\\InProcServer32" ascii //weight: 1
        $x_1_7 = "del %0" ascii //weight: 1
        $x_1_8 = "ThreadingModel" ascii //weight: 1
        $x_1_9 = "Apartment" ascii //weight: 1
        $x_1_10 = " goto try" ascii //weight: 1
        $x_3_11 = "erver32" ascii //weight: 3
        $x_1_12 = "SHLWAPI.DLL" ascii //weight: 1
        $x_2_13 = "wininit.ini" ascii //weight: 2
        $x_1_14 = "ListBox" ascii //weight: 1
        $x_1_15 = "del \"" ascii //weight: 1
        $x_1_16 = "if exist \"" ascii //weight: 1
        $x_10_17 = "ZXY_wfgQQ" ascii //weight: 10
        $x_5_18 = "SysWFGQQ2.dll" ascii //weight: 5
        $x_10_19 = "_xr.bat" ascii //weight: 10
        $x_10_20 = "C:\\Program Files\\Common Files\\Microsoft Shared\\MSINFO\\SysWFGQQ.dll" ascii //weight: 10
        $x_5_21 = "-z*tk" ascii //weight: 5
        $x_10_22 = "C:\\Program Files\\Common Files\\Microsoft Shared\\MSINFO\\SysWFGQQ2.dll" ascii //weight: 10
        $x_5_23 = "C:\\_xr.bat" ascii //weight: 5
        $x_5_24 = "SysWFGQQ.dll" ascii //weight: 5
        $x_10_25 = "{91B1E846-2BEF-4345-8848-7699C7C9935F}" ascii //weight: 10
        $x_10_26 = "youmeiyougaocuo" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*))) or
            ((4 of ($x_10_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_A_2147602492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.gen!A"
        threat_id = "2147602492"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "npkcrypt.sys" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_2_3 = "First Run" ascii //weight: 2
        $x_2_4 = "C:\\Windows\\iexplore.$" ascii //weight: 2
        $x_1_5 = "Explorer.Exe" ascii //weight: 1
        $x_2_6 = {2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72}  //weight: 2, accuracy: High
        $x_3_7 = {06 00 44 00 56 00 43 00 4c 00 41 00 4c 00}  //weight: 3, accuracy: High
        $x_2_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 2
        $x_3_9 = "xiaran" ascii //weight: 3
        $x_2_10 = "LoginCtrl.dll" ascii //weight: 2
        $x_2_11 = "rejoice.dll" ascii //weight: 2
        $x_1_12 = "xr_Dll" ascii //weight: 1
        $x_2_13 = "xr_Exe" ascii //weight: 2
        $x_2_14 = "aixiaran" ascii //weight: 2
        $x_5_15 = {8b d8 eb 01 6b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 77 8b c6}  //weight: 5, accuracy: High
        $x_5_16 = {73 76 77 8b fa 8b f0 8b c6 e8 ?? ?? ?? ?? 8b d8 eb 01 6b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 77 8b c6 e8 ?? ?? ?? ?? 8b c8 2b cb 8d 73 01 8b c6 e8 ?? ?? ?? ?? 5f 5e 5b c3}  //weight: 5, accuracy: Low
        $x_5_17 = {73 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 6a 01 e8 e2 ff ff ff}  //weight: 5, accuracy: High
        $x_5_18 = {75 2e 6a f4 53 e8 ?? ?? ff ff 3d b4 00 00 00 74 23 6a f0 53 e8 ?? ?? ff ff a8 20 75 17 6a 00 6a 00 68 d2 00 00 00 53 e8 ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_5_19 = "Liu_Mazi" ascii //weight: 5
        $x_5_20 = "xiang" ascii //weight: 5
        $x_2_21 = "THookAPI" ascii //weight: 2
        $x_2_22 = "UnhookWindowsHookEx" ascii //weight: 2
        $x_2_23 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_24 = {00 68 6f 6f 6b 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_2_25 = "JmpHookOn" ascii //weight: 2
        $x_2_26 = "~hook" ascii //weight: 2
        $x_15_27 = {53 6f 66 74 77 61 72 65 5c [0-3] 5c 51 51 42 65 74 61 33 20 48 6f 6f 6b 65 72}  //weight: 15, accuracy: Low
        $x_10_28 = "08315C1A-9BA9-4B7C-A432-26885F78DF28" ascii //weight: 10
        $x_10_29 = "QQ2005_Hooker_Head" ascii //weight: 10
        $x_10_30 = "QqHelperDll.Dll" ascii //weight: 10
        $x_10_31 = "QQNumber=" ascii //weight: 10
        $x_5_32 = {00 71 71 2e 45 78 65}  //weight: 5, accuracy: High
        $x_10_33 = "&QQPassWord=" ascii //weight: 10
        $x_5_34 = "QQList" ascii //weight: 5
        $x_5_35 = "http://jump.qq.com/clienturl_" ascii //weight: 5
        $x_2_36 = "HELO " ascii //weight: 2
        $x_2_37 = "AUTH LOGIN" ascii //weight: 2
        $x_2_38 = "MAIL FROM: <" ascii //weight: 2
        $x_1_39 = "RCPT TO: <" ascii //weight: 1
        $x_1_40 = "From: <" ascii //weight: 1
        $x_1_41 = "To: <" ascii //weight: 1
        $x_1_42 = "Subject: " ascii //weight: 1
        $x_5_43 = {64 61 74 61 0d 0a 00 00 ff ff ff ff ?? 00 00 00 66 72 6f 6d 3a 20 3c}  //weight: 5, accuracy: Low
        $x_1_44 = "HTTP/1.0" ascii //weight: 1
        $x_1_45 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_2_46 = {ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00}  //weight: 2, accuracy: High
        $x_2_47 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30 00 00 00 00 50 4f 53 54 00 00 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64}  //weight: 2, accuracy: High
        $x_5_48 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 18 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 19 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*))) or
            ((4 of ($x_5_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_5_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_5_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 18 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((5 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*) and 15 of ($x_2_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((6 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((6 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((6 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*) and 13 of ($x_2_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((7 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((7 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((7 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_5_*) and 10 of ($x_2_*))) or
            ((7 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((7 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((7 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((7 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((7 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((7 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((7 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((8 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((8 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((8 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((8 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_5_*) and 8 of ($x_2_*))) or
            ((8 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((8 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((8 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((9 of ($x_5_*) and 10 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((9 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((9 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_5_*) and 5 of ($x_2_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((9 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((10 of ($x_5_*) and 5 of ($x_1_*))) or
            ((10 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((10 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((10 of ($x_5_*) and 3 of ($x_2_*))) or
            ((10 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((10 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((10 of ($x_5_*) and 2 of ($x_3_*))) or
            ((11 of ($x_5_*))) or
            ((1 of ($x_10_*) and 18 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 19 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 18 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 15 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 13 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 9 of ($x_5_*))) or
            ((2 of ($x_10_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 18 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 13 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*) and 7 of ($x_5_*))) or
            ((3 of ($x_10_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 13 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*))) or
            ((4 of ($x_10_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 8 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*))) or
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 19 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 17 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 18 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 15 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 13 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 10 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 15 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 13 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 6 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 10 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_B_2147602505_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.gen!B"
        threat_id = "2147602505"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "68"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 6a 01 e8 e2 ff ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {70 83 7d 0c 01 1b c0 40 83 e0 7f 70 8b 65 08 70}  //weight: 5, accuracy: High
        $x_5_3 = {61 64 76 61 70 69 33 32 2e 64 6c 6c 00 00 00 00 71 75 65 72 79 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32 61 00 00 00 00 71 75 65 72 79 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32 77 00 00 00 00 63 68 61 6e 67 65 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32 61 00 00 00 63 68 61 6e 67 65 73 65 72 76 69 63 65 63 6f 6e 66 69 67 32}  //weight: 5, accuracy: High
        $x_2_4 = {b0 01 5b c3 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 63 72 65 61 74 65 74 6f 6f 6c}  //weight: 2, accuracy: High
        $x_2_5 = {ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00}  //weight: 2, accuracy: High
        $x_2_6 = {47 45 54 20 00 00 00 00 ff ff ff ff 0b 00 00 00 20 48 54 54 50 2f 31 2e 30 0d 0a 00 ff}  //weight: 2, accuracy: High
        $x_2_7 = "accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword, */*" ascii //weight: 2
        $x_2_8 = {0d 0a 00 00 ff ff ff ff 18 00 00 00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a 00 00 00 00 ff ff ff ff 40}  //weight: 2, accuracy: High
        $x_2_9 = "UrlMon" ascii //weight: 2
        $x_2_10 = "UUnit_SendMail" ascii //weight: 2
        $x_2_11 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 2
        $x_2_12 = "ChangeServiceConfig2A" ascii //weight: 2
        $x_2_13 = "Process32Next" ascii //weight: 2
        $x_5_14 = {53 74 61 72 74 48 6f 6f 6b 00 53 74 6f 70 48 6f 6f 6b}  //weight: 5, accuracy: High
        $x_2_15 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runservices" ascii //weight: 2
        $x_2_17 = "dllfile" ascii //weight: 2
        $x_2_18 = "Shell" ascii //weight: 2
        $x_2_19 = "system.ini" ascii //weight: 2
        $x_2_20 = "Explorer.exe " ascii //weight: 2
        $x_2_21 = "Proxy-Connection: Keep-Alive" ascii //weight: 2
        $x_5_22 = "?winntService" ascii //weight: 5
        $x_10_23 = "ZLTHOOK" ascii //weight: 10
        $x_5_24 = "zlthook" ascii //weight: 5
        $x_5_25 = "zlthook.dll" ascii //weight: 5
        $x_20_26 = "C:\\WINDOWS\\help\\QQZLT.CHI" ascii //weight: 20
        $x_5_27 = "qUnitHookDll" ascii //weight: 5
        $x_10_28 = "qqtlz!" ascii //weight: 10
        $x_10_29 = "?qqmail=" ascii //weight: 10
        $x_10_30 = "ls.net/q2q" ascii //weight: 10
        $x_10_31 = "http://www.dnangels.net/q2q/qqlong.asp" ascii //weight: 10
        $x_2_32 = "HELO " ascii //weight: 2
        $x_2_33 = "EHLO " ascii //weight: 2
        $x_2_34 = "AUTH LOGIN" ascii //weight: 2
        $x_2_35 = "MAIL FROM: <" ascii //weight: 2
        $x_1_36 = "RCPT TO: <" ascii //weight: 1
        $x_1_37 = "From: <" ascii //weight: 1
        $x_1_38 = "To: <" ascii //weight: 1
        $x_1_39 = "Subject: " ascii //weight: 1
        $x_5_40 = {64 61 74 61 0d 0a 00 00 ff ff ff ff ?? 00 00 00 66 72 6f 6d 3a 20 3c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 20 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_5_*) and 21 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*) and 17 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_5_*) and 18 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_5_*) and 19 of ($x_2_*))) or
            ((7 of ($x_5_*) and 15 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_5_*) and 16 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_5_*) and 17 of ($x_2_*))) or
            ((8 of ($x_5_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_5_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_5_*) and 14 of ($x_2_*))) or
            ((9 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((9 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((9 of ($x_5_*) and 12 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 20 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 21 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 17 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 18 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 19 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 15 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 16 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 17 of ($x_2_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 14 of ($x_2_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 12 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*) and 9 of ($x_2_*))) or
            ((1 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 9 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 9 of ($x_5_*) and 7 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 20 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 21 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 17 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 18 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 19 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 15 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 16 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 17 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 14 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 12 of ($x_2_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*) and 9 of ($x_2_*))) or
            ((2 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 7 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 7 of ($x_5_*) and 7 of ($x_2_*))) or
            ((2 of ($x_10_*) and 8 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 8 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 8 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*) and 9 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 9 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 9 of ($x_5_*) and 2 of ($x_2_*))) or
            ((3 of ($x_10_*) and 17 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 18 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 19 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 16 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 17 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 14 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 12 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 9 of ($x_2_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 7 of ($x_2_*))) or
            ((3 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 6 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 6 of ($x_5_*) and 4 of ($x_2_*))) or
            ((3 of ($x_10_*) and 7 of ($x_5_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_2_*))) or
            ((3 of ($x_10_*) and 8 of ($x_5_*))) or
            ((4 of ($x_10_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 14 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 9 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 4 of ($x_2_*))) or
            ((4 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*))) or
            ((4 of ($x_10_*) and 6 of ($x_5_*))) or
            ((5 of ($x_10_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 9 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*))) or
            ((5 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((5 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 20 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 21 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 17 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 18 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 19 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*) and 15 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*) and 16 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*) and 17 of ($x_2_*))) or
            ((1 of ($x_20_*) and 4 of ($x_5_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_5_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_5_*) and 14 of ($x_2_*))) or
            ((1 of ($x_20_*) and 5 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 5 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 5 of ($x_5_*) and 12 of ($x_2_*))) or
            ((1 of ($x_20_*) and 6 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 6 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 6 of ($x_5_*) and 9 of ($x_2_*))) or
            ((1 of ($x_20_*) and 7 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 7 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 7 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_20_*) and 8 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 8 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 8 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_20_*) and 9 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 9 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 9 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 17 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 18 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 19 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 16 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 17 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*) and 14 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 12 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 9 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 8 of ($x_5_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 12 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 13 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 14 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 9 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 4 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 6 of ($x_5_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 9 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 4 of ($x_2_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_20_*) and 5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_QQpass_C_2147602526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQpass.gen!C"
        threat_id = "2147602526"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "npkcrypt.sys" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_2_3 = {73 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 6a 01 e8 e2 ff ff ff}  //weight: 2, accuracy: High
        $x_1_4 = "money" ascii //weight: 1
        $x_1_5 = "strikeout" ascii //weight: 1
        $x_1_6 = "hotlight" ascii //weight: 1
        $x_2_7 = "uxtheme.dll" ascii //weight: 2
        $x_2_8 = {83 c9 ff 83 ca ff e8 01 00 00 00 c3 6a 00 52 51 b2 04 66 8b}  //weight: 2, accuracy: High
        $x_2_9 = "explorerbar" wide //weight: 2
        $x_2_10 = "keypress" ascii //weight: 2
        $x_1_11 = "smtp" ascii //weight: 1
        $x_1_12 = "tform1" ascii //weight: 1
        $x_2_13 = {8b 65 fc 8a 64 18 ff 24 0f 8b 75 f8 8a 74 32 ff 80 e2 0f 32 c2 88 65 f3 8d 65 fc e8 ?? ?? ?? ?? 8b 75 fc 8a 74 1a ff 80 e2 f0 8a 6d f3 02 d1 88 74 18 ff 66}  //weight: 2, accuracy: Low
        $x_2_14 = {07 00 42 00 42 00 41 00 42 00 4f 00 52 00 54 00}  //weight: 2, accuracy: High
        $x_2_15 = {06 00 44 00 56 00 43 00 4c 00 41 00 4c 00}  //weight: 2, accuracy: High
        $x_2_16 = {08 00 4d 00 41 00 49 00 4e 00 49 00 43 00 4f 00 4e 00}  //weight: 2, accuracy: High
        $x_2_17 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c [0-8] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_18 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 2
        $x_10_19 = "SysWFSF.dll" ascii //weight: 10
        $x_10_20 = "SysWFGQQ2.dll" ascii //weight: 10
        $x_5_21 = "xiaoyuwed@gmail.com" ascii //weight: 5
        $x_3_22 = "hooking" ascii //weight: 3
        $x_2_23 = "THookAPI" ascii //weight: 2
        $x_2_24 = "UnhookWindowsHookEx" ascii //weight: 2
        $x_2_25 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_26 = {00 68 6f 6f 6b 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_2_27 = "JmpHookOn" ascii //weight: 2
        $x_2_28 = "~hook" ascii //weight: 2
        $x_5_29 = {53 6f 66 74 77 61 72 65 5c [0-3] 5c 51 51 42 65 74 61 33 20 48 6f 6f 6b 65 72}  //weight: 5, accuracy: Low
        $x_10_30 = "91B1E846-2BEF-4345-8848-7699C7C9935F" ascii //weight: 10
        $x_2_31 = "QQ2005_Hooker_Head" ascii //weight: 2
        $x_2_32 = "QqHelperDll.Dll" ascii //weight: 2
        $x_10_33 = "QQNumber=" ascii //weight: 10
        $x_5_34 = {00 71 71 2e 45 78 65}  //weight: 5, accuracy: High
        $x_10_35 = "&QQPassWord=" ascii //weight: 10
        $x_10_36 = "QQNumber.ini" ascii //weight: 10
        $x_10_37 = "&QQclub=" ascii //weight: 10
        $x_10_38 = "&QQip=" ascii //weight: 10
        $x_5_39 = "QQList" ascii //weight: 5
        $x_2_40 = "http://jump.qq.com/clienturl_" ascii //weight: 2
        $x_2_41 = "mailto:" ascii //weight: 2
        $x_3_42 = "?subject=" ascii //weight: 3
        $x_2_43 = "&body=" ascii //weight: 2
        $x_3_44 = {68 65 6c 6f [0-56] 61 75 74 68 20 6c 6f 67 69 6e 0d 0a 00 00 00 00 ff ff ff ff 0c 00 00 00 6d 61 69 6c 20 66 72 6f 6d 3a 20 3c 00 00 00 00 ff ff ff ff 01 00 00 00 3e 00 00 00 ff ff ff ff 0a 00 00 00 72 63 70 74 20 74 6f 3a 20 3c}  //weight: 3, accuracy: Low
        $x_1_45 = "HELO " ascii //weight: 1
        $x_1_46 = "AUTH LOGIN" ascii //weight: 1
        $x_1_47 = "MAIL FROM: <" ascii //weight: 1
        $x_1_48 = "RCPT TO: <" ascii //weight: 1
        $x_1_49 = "From: <" ascii //weight: 1
        $x_1_50 = "To: <" ascii //weight: 1
        $x_1_51 = "Subject: " ascii //weight: 1
        $x_1_52 = "HTTP/1.0" ascii //weight: 1
        $x_1_53 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_5_54 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 22 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_3_*) and 20 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_3_*) and 21 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_3_*) and 22 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 22 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 21 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 20 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 21 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 22 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 18 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 19 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 20 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 21 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 22 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 20 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_5_*) and 21 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_5_*) and 22 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 21 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 20 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 21 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 22 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 18 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 19 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 20 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 21 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 22 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 17 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_5_*) and 18 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_5_*) and 19 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_5_*) and 20 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 21 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 22 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 21 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 20 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 21 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 22 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 18 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 19 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 20 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 21 of ($x_2_*))) or
            ((4 of ($x_5_*) and 15 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_5_*) and 16 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_5_*) and 17 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_5_*) and 18 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_5_*) and 19 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_5_*) and 20 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*) and 21 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*) and 22 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 21 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 20 of ($x_2_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 18 of ($x_2_*))) or
            ((5 of ($x_5_*) and 12 of ($x_2_*) and 16 of ($x_1_*))) or
            ((5 of ($x_5_*) and 13 of ($x_2_*) and 14 of ($x_1_*))) or
            ((5 of ($x_5_*) and 14 of ($x_2_*) and 12 of ($x_1_*))) or
            ((5 of ($x_5_*) and 15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_5_*) and 16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_5_*) and 17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_5_*) and 18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_5_*) and 19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*) and 20 of ($x_2_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 15 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 13 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 11 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 16 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 14 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 12 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 13 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 11 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 9 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*))) or
            ((1 of ($x_10_*) and 20 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 21 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 22 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 21 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 22 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 20 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 21 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 22 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 18 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 19 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 20 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 21 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 22 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 17 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 18 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 19 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 20 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 21 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 22 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 21 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 20 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 21 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 22 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 18 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 19 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 20 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 21 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 16 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 17 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 18 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 19 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 20 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 21 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 22 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 21 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 20 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 18 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 12 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 13 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 14 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 20 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 10 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 11 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 12 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 18 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 9 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 15 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*))) or
            ((2 of ($x_10_*) and 15 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 16 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 17 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 18 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 19 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 20 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 21 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 22 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 19 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 20 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 21 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 17 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 18 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 19 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 20 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 16 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 17 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 18 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 13 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 14 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 20 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 19 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 16 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 17 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 14 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 15 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 11 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 12 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 18 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 13 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 9 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 15 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 13 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 10 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 11 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 12 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 13 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 14 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 15 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 16 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 17 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 18 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 14 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 15 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 16 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 12 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 13 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 14 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 15 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 11 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 12 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 13 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 13 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 14 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 13 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 14 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 11 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 12 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 9 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 10 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 13 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_10_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 9 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 10 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 11 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 13 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 10 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 16 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_10_*) and 5 of ($x_5_*))) or
            ((5 of ($x_10_*) and 15 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((5 of ($x_10_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_10_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 8 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((5 of ($x_10_*) and 3 of ($x_5_*))) or
            ((6 of ($x_10_*) and 5 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 3 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_10_*) and 2 of ($x_3_*))) or
            ((6 of ($x_10_*) and 1 of ($x_5_*))) or
            ((7 of ($x_10_*))) or
            (all of ($x*))
        )
}

