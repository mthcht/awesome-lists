rule TrojanClicker_Win32_Donise_A_2147576243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Donise.A"
        threat_id = "2147576243"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Donise"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {3c 01 77 f7 80 3f 01 75 f2 8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 ab 47 89 d8 e2 dc}  //weight: 4, accuracy: High
        $x_1_2 = "SOCK32.dll" ascii //weight: 1
        $x_1_3 = "85CB6900-4D95-11CF-960C-0080C7F4EE85" ascii //weight: 1
        $x_1_4 = "CMD.EXE" ascii //weight: 1
        $x_1_5 = "COMSPEC" ascii //weight: 1
        $x_1_6 = "%s /c %s \"%s\"" ascii //weight: 1
        $x_1_7 = "del %0" ascii //weight: 1
        $x_1_8 = "if exist %1 goto a" ascii //weight: 1
        $x_1_9 = "del %1" ascii //weight: 1
        $x_1_10 = "@echo off" ascii //weight: 1
        $x_1_11 = "temp_%d.bat" ascii //weight: 1
        $x_1_12 = "\\*.txt" ascii //weight: 1
        $x_1_13 = "Cookies" ascii //weight: 1
        $x_1_14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_15 = "NNIExplore" ascii //weight: 1
        $x_1_16 = "AppEvents\\Schemes\\Apps\\Explorer\\Navigating\\.current" ascii //weight: 1
        $x_1_17 = "linkrunner" ascii //weight: 1
        $x_1_18 = "WriteProcessMemory" ascii //weight: 1
        $x_1_19 = "ReadProcessMemory" ascii //weight: 1
        $x_1_20 = "GetStartupInfoA" ascii //weight: 1
        $x_1_21 = "CreateThread" ascii //weight: 1
        $x_1_22 = "FindFirstFileA" ascii //weight: 1
        $x_1_23 = "DeleteFileA" ascii //weight: 1
        $x_1_24 = "FindNextFileA" ascii //weight: 1
        $x_1_25 = "CreateProcessA" ascii //weight: 1
        $x_1_26 = "GetStockObject" ascii //weight: 1
        $x_1_27 = "wcstombs" ascii //weight: 1
        $x_1_28 = "GetKeyboardLayoutList" ascii //weight: 1
        $x_1_29 = "PostQuitMessage" ascii //weight: 1
        $x_1_30 = "GetClientRect" ascii //weight: 1
        $x_1_31 = "PostMessageA" ascii //weight: 1
        $x_1_32 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_33 = "InternetReadFile" ascii //weight: 1
        $x_1_34 = ":$:*:1:::B:I:T:Z:`:j:p:v:" ascii //weight: 1
        $x_1_35 = "=E=M=b=m=" ascii //weight: 1
        $x_1_36 = "=H=R=a=k=x=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((26 of ($x_1_*))) or
            ((1 of ($x_4_*) and 22 of ($x_1_*))) or
            (all of ($x*))
        )
}

