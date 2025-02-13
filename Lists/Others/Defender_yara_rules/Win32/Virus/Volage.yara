rule Virus_Win32_Volage_A_2147600069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Volage.gen!A"
        threat_id = "2147600069"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Volage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "written by DR-EF" ascii //weight: 10
        $x_10_2 = "2004 DR-EF" ascii //weight: 10
        $x_1_3 = "MessageBoxA" ascii //weight: 1
        $x_1_4 = "CreateMutexA" ascii //weight: 1
        $x_1_5 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

