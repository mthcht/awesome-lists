rule PWS_Win32_Zengtu_A_2147582297_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.A"
        threat_id = "2147582297"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WXYZ9213065478FGHIJKLMABCDENOPQRSTUV" ascii //weight: 1
        $x_1_2 = "bcdefghi8921306qrstuvwxyz547jklmnopa" ascii //weight: 1
        $x_1_3 = "PendingFileRenameOperations" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_6 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_7 = "bgtz.dll" ascii //weight: 1
        $x_1_8 = "agtz.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zengtu_H_2147601540_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.H"
        threat_id = "2147601540"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zhengtu_client" ascii //weight: 2
        $x_1_2 = "user=" ascii //weight: 1
        $x_2_3 = "&pass=" ascii //weight: 2
        $x_1_4 = "&ser=" ascii //weight: 1
        $x_1_5 = "&pass2=" ascii //weight: 1
        $x_2_6 = "&beizhu=" ascii //weight: 2
        $x_2_7 = "&pcname=" ascii //weight: 2
        $x_2_8 = "Send OK" ascii //weight: 2
        $x_1_9 = "&cangku=" ascii //weight: 1
        $x_2_10 = "if exist \"" ascii //weight: 2
        $x_1_11 = "ReadProcessMemory" ascii //weight: 1
        $x_1_12 = "WriteProcessMemory" ascii //weight: 1
        $x_1_13 = "DownDLL.dll" ascii //weight: 1
        $x_2_14 = "StartHook" ascii //weight: 2
        $x_2_15 = "risiOff" ascii //weight: 2
        $x_2_16 = "risiOn" ascii //weight: 2
        $x_2_17 = "shizongrisini" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((10 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zengtu_B_2147601541_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.B"
        threat_id = "2147601541"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WhBoy" ascii //weight: 2
        $x_2_2 = "ZhengTu" ascii //weight: 2
        $x_2_3 = "mailbody=" ascii //weight: 2
        $x_2_4 = "`uup2.." ascii //weight: 2
        $x_2_5 = "Content-Type:" ascii //weight: 2
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "Mutex" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "HookOn" ascii //weight: 1
        $n_15_10 = "ggsafe.com/ggtools.ini" ascii //weight: -15
        $n_15_11 = "update.ggsafe.com/" ascii //weight: -15
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zengtu_C_2147601542_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.C"
        threat_id = "2147601542"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "zhengtu" ascii //weight: 3
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "Content-Type:" ascii //weight: 1
        $x_1_4 = "Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "Pass=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zengtu_D_2147601543_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.D"
        threat_id = "2147601543"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhengtu" ascii //weight: 1
        $x_1_2 = "servername" ascii //weight: 1
        $x_1_3 = "config.ini" ascii //weight: 1
        $x_1_4 = "Content-Length: %ld" ascii //weight: 1
        $x_1_5 = "%d.%d.%d.%d;" ascii //weight: 1
        $x_1_6 = "Win95OSR2" ascii //weight: 1
        $x_1_7 = "image/pjpeg, application/vnd.ms-excel," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zengtu_E_2147601544_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.E"
        threat_id = "2147601544"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhengtu_client" ascii //weight: 1
        $x_1_2 = "Content-Type: application" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_4 = "sendmail.asp" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "&Pass=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zengtu_F_2147601545_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.F"
        threat_id = "2147601545"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhengtu_client" ascii //weight: 1
        $x_1_2 = "if exist \"" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_4 = "CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_5 = "Send OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zengtu_G_2147601546_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zengtu.G"
        threat_id = "2147601546"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "WindowsXP" ascii //weight: 1
        $x_1_3 = "Windows23" ascii //weight: 1
        $x_1_4 = "Content-Type: application" ascii //weight: 1
        $x_1_5 = {55 73 65 72 3d 00 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "StartHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

