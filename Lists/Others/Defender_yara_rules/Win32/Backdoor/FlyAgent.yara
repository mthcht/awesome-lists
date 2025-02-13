rule Backdoor_Win32_FlyAgent_D_2147608223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlyAgent.D"
        threat_id = "2147608223"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 83 04 24 06 c3 ?? 68 ?? ?? 00 80 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 47 65 74 4e 65 77 53 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\EnableAdminTSRemote" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_FlyAgent_E_2147620374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlyAgent.E"
        threat_id = "2147620374"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 7d 0c 01 75 09 b8 01 00 00 00 c9 c2 0c 00 83 7d 0c 00 75 38 83 3d 04 30 00 10 00 74 06 ff 15 04 30 00 10 83 3d 08 30 00 10 00 74 0c ff 35 00 30 00 10 ff 15 08 30 00 10 83 3d 0c 30 00 10 00 74 0b ff 35 0c 30 00 10 e8 ?? ?? 00 00 c9 c2 0c 00 10 32 54 86 83 3d 10 30 00 10 00 75 07 60 e8 ?? ?? 00 00 61}  //weight: 10, accuracy: Low
        $x_1_2 = {2e 74 6d 70 00 20 3e 20 00 6e 65 74 20 76 69 65 77 20 5c 5c 00 44 69 73 6b}  //weight: 1, accuracy: High
        $x_1_3 = {4f 50 45 4e 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65}  //weight: 1, accuracy: High
        $x_1_4 = {4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 48 69 73 74 6f 72 79 5c 48 69 73 74 6f 72 79 2e 49 45 35 5c [0-26] 6d 61 69 6c 74 6f 3a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 5c [0-32] 6d 63 69 20 63 6f 6d 6d 61 6e 64 20 68 61 6e 64 6c 69 6e 67 20 77 69 6e 64 6f 77}  //weight: 1, accuracy: Low
        $x_1_6 = "$f%wh$" ascii //weight: 1
        $x_1_7 = "image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_FlyAgent_H_2147646522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlyAgent.H"
        threat_id = "2147646522"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_And xMe.bat" ascii //weight: 1
        $x_1_2 = "Sky\\E\\Install\\Path" ascii //weight: 1
        $x_1_3 = "on.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_FlyAgent_H_2147646522_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlyAgent.H"
        threat_id = "2147646522"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_And DeleteMe.bat" ascii //weight: 1
        $x_1_2 = "Software\\FlySky\\E\\Install\\Path" ascii //weight: 1
        $x_1_3 = "\\msyianjiup." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_FlyAgent_HDFG_2147793773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlyAgent.HDFG!MTB"
        threat_id = "2147793773"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 fe ff f3 35 33 f6 74 08 8b 4e 04 83 c6 08 f3 a4 4a 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

