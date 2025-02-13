rule PWS_Win32_Skatayo_A_2147583515_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Skatayo.A"
        threat_id = "2147583515"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Skatayo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 ca be [0-16] 23 33 32 37 37 30}  //weight: 5, accuracy: Low
        $x_5_2 = {cd ac d2 e2 d0 de b8 c4 [0-16] 42 75 74 74 6f 6e}  //weight: 5, accuracy: Low
        $x_2_3 = "if exists \"" ascii //weight: 2
        $x_2_4 = "goto try" ascii //weight: 2
        $x_2_5 = "AskTao." ascii //weight: 2
        $x_1_6 = "Explorer.exe" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Skatayo_A_2147595042_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Skatayo.A"
        threat_id = "2147595042"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Skatayo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeDebugPrivilege" ascii //weight: 1
        $x_3_2 = "%s?s=%s&q=%s&u=%s&p=%s&sp=%s&r=%s&l=%s" ascii //weight: 3
        $x_2_3 = "/lin.asp" ascii //weight: 2
        $x_2_4 = "asktao." ascii //weight: 2
        $x_2_5 = "Explorer.exe" ascii //weight: 2
        $x_2_6 = "CreateRemoteThread" ascii //weight: 2
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

