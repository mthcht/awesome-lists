rule Trojan_Win32_Regrun_A_2147608174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Regrun.A"
        threat_id = "2147608174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Regrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if exist %1 goto Loop" ascii //weight: 1
        $x_1_2 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 00 00 00 ff ff ff ff 08 00 00 00 50 6f 6c 69 63 69 65 73 00 00 00 00 ff ff ff ff 05 00 00 00 63 6c 61 76 65}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_4 = "\\wdfmgr.exe\" /wait" ascii //weight: 1
        $x_1_5 = "UserRestart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Regrun_B_2147611548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Regrun.B"
        threat_id = "2147611548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Regrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "I*\\AD:\\My Documets\\All My Project\\Murni\\Virus Roy Final Release\\Siap Exe\\Roy.VBP" wide //weight: 10
        $x_5_2 = "Launch_U3" wide //weight: 5
        $x_5_3 = {52 6f 79 00 41 50 49 00 46 75 6e 67 73 69}  //weight: 5, accuracy: High
        $x_1_4 = "SetFileAttributesA" ascii //weight: 1
        $x_1_5 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

