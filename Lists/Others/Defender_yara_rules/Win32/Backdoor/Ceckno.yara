rule Backdoor_Win32_Ceckno_D_2147606654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ceckno.D"
        threat_id = "2147606654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceckno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 00 38 35 37 39 46 43 35 33 44 31 37 33 35 30 39 34 43 36 32 42 43 44 38 38 43 33 33 46 32 37 42 38}  //weight: 1, accuracy: High
        $x_1_2 = "#1<<<<<IDC<<<<<<<<%s<" ascii //weight: 1
        $x_1_3 = {55 73 65 72 69 6e 69 74 00 00 00 00 25 73 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 2c}  //weight: 1, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_5 = {55 50 44 41 54 41 3a 00 53 54 4f 50 41 54 54 41 43 4b}  //weight: 1, accuracy: High
        $x_1_6 = "socket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Ceckno_A_2147607870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ceckno.gen!A"
        threat_id = "2147607870"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceckno"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Made in China DDoS" ascii //weight: 1
        $x_1_2 = "Windows China Driver" ascii //weight: 1
        $x_1_3 = "Network China NetBot" ascii //weight: 1
        $x_5_4 = {68 c0 30 40 00 68 40 30 40 00 68 20 30 40 00}  //weight: 5, accuracy: High
        $x_5_5 = {62 00 00 00 5c 78 63 6f 70 79 2e 65 78 65 00 00 5c 6e 74 73 65 72 76 65 72 2e 65 78 65 00 00 00 45 58 45 00 5c 6e 74 73 65 72 76 65 72 2e 64 6c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ceckno_E_2147610055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ceckno.E"
        threat_id = "2147610055"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceckno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_2 = " /c del %s > nul" ascii //weight: 1
        $x_1_3 = "CreateServiceA" ascii //weight: 1
        $x_1_4 = "<mir182>%s" ascii //weight: 1
        $x_1_5 = "STOPATTACK" ascii //weight: 1
        $x_1_6 = "@AttackMode" ascii //weight: 1
        $x_1_7 = "StartServiceCtrlDispatcherA" ascii //weight: 1
        $x_1_8 = "@jihuodenglu>" ascii //weight: 1
        $x_1_9 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ceckno_C_2147610693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ceckno.C"
        threat_id = "2147610693"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceckno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "flood" ascii //weight: 10
        $x_10_2 = "stopattack" ascii //weight: 10
        $x_1_3 = "\\WINDOWS\\SYSTEM32\\wmiprvxe.exe" ascii //weight: 1
        $x_1_4 = "\\system32\\cmd.exe /c  del C:\\myapp.exe > nul" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ceckno_H_2147664028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ceckno.H"
        threat_id = "2147664028"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceckno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET ^&&%$%$^%$#^&**" ascii //weight: 1
        $x_1_2 = "Made in China DDoS" ascii //weight: 1
        $x_1_3 = "Network China NetBot" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Ceckno_I_2147681578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ceckno.I"
        threat_id = "2147681578"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceckno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "insane" ascii //weight: 10
        $x_10_2 = {2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 72 75 20 22 00}  //weight: 10, accuracy: High
        $x_10_3 = "up\\*.scr" ascii //weight: 10
        $x_1_4 = "stopattack" ascii //weight: 1
        $x_1_5 = "sandbox" ascii //weight: 1
        $x_1_6 = "disableregistrytools" ascii //weight: 1
        $x_1_7 = {00 73 73 79 6e}  //weight: 1, accuracy: High
        $x_1_8 = "autorun.inf" ascii //weight: 1
        $x_1_9 = "\\filezilla\\recentservers.xml" ascii //weight: 1
        $x_1_10 = "set cdaudio door open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

