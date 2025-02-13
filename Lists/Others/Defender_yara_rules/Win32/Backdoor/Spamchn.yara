rule Backdoor_Win32_Spamchn_2147624699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spamchn"
        threat_id = "2147624699"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spamchn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = ",SubHost:" ascii //weight: 1
        $x_1_3 = "Logins;" ascii //weight: 1
        $x_1_4 = "\\SynSend.exe" ascii //weight: 1
        $x_1_5 = "218.7.120.70" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Spamchn_A_2147639970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spamchn.A"
        threat_id = "2147639970"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spamchn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ",SubHost:" ascii //weight: 3
        $x_3_2 = "#1<<<<<IDC<<<<<<<<=CQ]TS\\<<<<<<<<CHsIvUri]I" ascii //weight: 3
        $x_2_3 = "Accept-Language: zh-cn" ascii //weight: 2
        $x_1_4 = "window.location" ascii //weight: 1
        $x_1_5 = "svchost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

